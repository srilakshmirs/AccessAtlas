"""FastAPI application for AccessAtlas IAM Security Intelligence and Findings API."""

from __future__ import annotations

import logging
import math
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException, Query, status

from accessatlas.api.schemas import (
    EvaluationResponse,
    HealthResponse,
    IdentityDetail,
    IdentityItem,
    PaginatedResponse,
    ScenarioMetricItem,
    TrapMetricItem,
)
from accessatlas.graph import build_privilege_graph, compute_identity_privileges
from accessatlas.ingestion.loader import load_table
from accessatlas.resolution import resolve_identities
from accessatlas.rules.detectors import evaluate_all_rules
from accessatlas.rules.models import Finding
from accessatlas.utils import load_config

logger = logging.getLogger(__name__)


class AppState:
    """Holds in-memory indexed models and findings loaded once at startup."""

    def __init__(self) -> None:
        self.config: dict[str, Any] = {}
        self.snapshot_date: str = "2026-10-12"
        self.resolved_df: pd.DataFrame = pd.DataFrame()
        self.unresolved_df: pd.DataFrame = pd.DataFrame()
        self.privilege_df: pd.DataFrame = pd.DataFrame()
        self.findings: list[Finding] = []
        self.findings_by_id: dict[str, Finding] = {}
        self.findings_by_identity: dict[str, list[Finding]] = {}
        self.identities_by_id: dict[str, dict[str, Any]] = {}
        self.is_loaded: bool = False

    def load(
        self,
        config: dict[str, Any] | None = None,
        fixture_dir: Path | None = None,
    ) -> None:
        """Load data and compute identity resolutions, privilege graph, and findings."""
        if self.is_loaded:
            return

        cfg = config or load_config()
        self.config = cfg
        self.snapshot_date = str(cfg.get("snapshot_date", "2026-10-12"))

        logger.info("Initializing AccessAtlas API state (fixture_dir=%s)...", fixture_dir)

        # 1. Load core tables
        hr = load_table("HR_Records", config=cfg, fixture_dir=fixture_dir)
        hr_off = load_table("HR_Offboarding", config=cfg, fixture_dir=fixture_dir)
        role_changes = load_table("HR_RoleChanges", config=cfg, fixture_dir=fixture_dir)
        ad = load_table("AD_Users", config=cfg, fixture_dir=fixture_dir)
        aws = load_table("AWS_Users", config=cfg, fixture_dir=fixture_dir)
        okta = load_table("Okta_Users", config=cfg, fixture_dir=fixture_dir)
        exc = load_table("Exceptions", config=cfg, fixture_dir=fixture_dir)
        oncall = load_table("OnCall_Roster", config=cfg, fixture_dir=fixture_dir)
        jobs = load_table("Scheduled_Jobs", config=cfg, fixture_dir=fixture_dir)
        tokens = load_table("API_Tokens", config=cfg, fixture_dir=fixture_dir)
        tier_map = load_table("Tier_Mapping", config=cfg, fixture_dir=fixture_dir)

        # Load events table
        audit = load_table("Audit_Events", config=cfg, validate=False, fixture_dir=fixture_dir)

        # 2. Resolve identities (M2)
        res = resolve_identities(hr, ad, aws, okta)
        self.resolved_df = res.resolved_identities
        self.unresolved_df = res.unresolved_accounts

        # 3. Privilege graph (M3)
        graph = build_privilege_graph(
            ad_groups_df=load_table("AD_Groups", config=cfg, fixture_dir=fixture_dir),
            ad_membership_df=load_table("AD_GroupMembership", config=cfg, fixture_dir=fixture_dir),
            aws_groups_df=load_table("AWS_Groups", config=cfg, fixture_dir=fixture_dir),
            aws_policies_df=load_table("AWS_Policies", config=cfg, fixture_dir=fixture_dir),
            aws_user_groups_df=load_table("AWS_UserGroups", config=cfg, fixture_dir=fixture_dir),
            aws_policy_attach_df=load_table(
                "AWS_PolicyAttach", config=cfg, fixture_dir=fixture_dir
            ),
            okta_admin_roles_df=load_table("Okta_AdminRoles", config=cfg, fixture_dir=fixture_dir),
            okta_group_membership_df=load_table(
                "Okta_GroupMembership", config=cfg, fixture_dir=fixture_dir
            ),
            okta_aws_federation_df=load_table(
                "Okta_AWS_Federation", config=cfg, fixture_dir=fixture_dir
            ),
            tier_mapping_df=tier_map,
            ad_users_df=ad,
            aws_users_df=aws,
            okta_users_df=okta,
        )
        self.privilege_df = compute_identity_privileges(graph, self.resolved_df)

        # 4. Rules & Findings (M4)
        self.findings = evaluate_all_rules(
            hr_df=hr,
            hr_offboarding_df=hr_off,
            ad_users_df=ad,
            aws_users_df=aws,
            okta_users_df=okta,
            resolved_identities=self.resolved_df,
            unresolved_accounts=self.unresolved_df,
            privilege_df=self.privilege_df,
            audit_events_df=audit,
            exceptions_df=exc,
            oncall_df=oncall,
            scheduled_jobs_df=jobs,
            role_changes_df=role_changes,
            tokens_df=tokens,
            config=cfg,
        )

        # Index findings by id and by identity_id
        self.findings_by_id = {f.finding_id: f for f in self.findings}
        self.findings_by_identity = {}
        for f in self.findings:
            self.findings_by_identity.setdefault(f.identity_id, []).append(f)

        # Index combined identities for fast retrieval
        priv_lookup = {str(row["identity_id"]): row for _, row in self.privilege_df.iterrows()}
        self.identities_by_id = {}

        for _, row in self.resolved_df.iterrows():
            iid = str(row["identity_id"])
            p_row = priv_lookup.get(iid)

            ad_acc = row.get("ad_account_id")
            aws_acc = row.get("aws_user_id")
            okta_acc = row.get("okta_id")

            self.identities_by_id[iid] = {
                "identity_id": iid,
                "identity_kind": str(row.get("identity_kind", "human")),
                "ad_account_id": str(ad_acc) if pd.notna(ad_acc) and ad_acc else None,
                "aws_user_id": str(aws_acc) if pd.notna(aws_acc) and aws_acc else None,
                "okta_id": str(okta_acc) if pd.notna(okta_acc) and okta_acc else None,
                "overall_effective_tier": int(p_row["overall_effective_tier"])
                if p_row is not None
                else None,
                "ad_effective_tier": int(p_row["ad_effective_tier"]) if p_row is not None else None,
                "aws_effective_tier": int(p_row["aws_effective_tier"])
                if p_row is not None
                else None,
                "okta_tier": int(p_row["okta_tier"]) if p_row is not None else None,
                "overall_grant_path": str(p_row.get("overall_grant_path", ""))
                if p_row is not None
                else None,
                "hidden_escalation": bool(p_row.get("hidden_escalation", False))
                if p_row is not None
                else False,
            }

        self.is_loaded = True
        logger.info(
            "AccessAtlas API initialized: %d identities, %d findings",
            len(self.identities_by_id),
            len(self.findings),
        )


app_state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler: loads tables and rules once at startup."""
    try:
        app_state.load()
    except Exception as exc:
        logger.warning(
            "Could not auto-load production tables on startup (%s). State can be set via fixtures.",
            exc,
        )
    yield


app = FastAPI(
    title="AccessAtlas IAM Security API",
    description="Identity resolution, effective privilege graphs, and explainable security rules API.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse, tags=["System"])
def get_health() -> HealthResponse:
    """Return health status, software version, and loaded finding counts."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        identities_count=len(app_state.identities_by_id),
        findings_count=len(app_state.findings),
        snapshot_date=app_state.snapshot_date,
    )


@app.get("/identities", response_model=PaginatedResponse[IdentityItem], tags=["Identities"])
def list_identities(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    size: int = Query(50, ge=1, le=500, description="Items per page"),
    kind: str | None = Query(None, description="Filter by identity kind ('human', 'service')"),
    tier: int | None = Query(
        None, ge=0, le=9, description="Filter by exact overall effective tier"
    ),
    max_tier: int | None = Query(
        None, ge=0, le=9, description="Filter by maximum overall effective tier (<= max_tier)"
    ),
) -> PaginatedResponse[IdentityItem]:
    """List resolved identities with optional tier and kind filters and pagination."""
    items = list(app_state.identities_by_id.values())

    if kind is not None:
        items = [i for i in items if i["identity_kind"].lower() == kind.lower()]

    if tier is not None:
        items = [i for i in items if i["overall_effective_tier"] == tier]

    if max_tier is not None:
        items = [
            i
            for i in items
            if i["overall_effective_tier"] is not None and i["overall_effective_tier"] <= max_tier
        ]

    total = len(items)
    pages = math.ceil(total / size) if total > 0 else 1
    offset = (page - 1) * size
    page_items = items[offset : offset + size]

    response_items = [
        IdentityItem(
            identity_id=i["identity_id"],
            identity_kind=i["identity_kind"],
            ad_account_id=i["ad_account_id"],
            aws_user_id=i["aws_user_id"],
            okta_id=i["okta_id"],
            overall_effective_tier=i["overall_effective_tier"],
            ad_effective_tier=i["ad_effective_tier"],
            aws_effective_tier=i["aws_effective_tier"],
            okta_tier=i["okta_tier"],
            findings_count=len(app_state.findings_by_identity.get(i["identity_id"], [])),
        )
        for i in page_items
    ]

    return PaginatedResponse(
        items=response_items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@app.get("/identities/{id}", response_model=IdentityDetail, tags=["Identities"])
def get_identity(id: str) -> IdentityDetail:
    """Retrieve detailed identity attributes, platform account links, and security findings."""
    identity = app_state.identities_by_id.get(id)
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity '{id}' not found",
        )

    findings = app_state.findings_by_identity.get(id, [])

    return IdentityDetail(
        identity_id=identity["identity_id"],
        identity_kind=identity["identity_kind"],
        ad_account_id=identity["ad_account_id"],
        aws_user_id=identity["aws_user_id"],
        okta_id=identity["okta_id"],
        overall_effective_tier=identity["overall_effective_tier"],
        ad_effective_tier=identity["ad_effective_tier"],
        aws_effective_tier=identity["aws_effective_tier"],
        okta_tier=identity["okta_tier"],
        overall_grant_path=identity["overall_grant_path"],
        hidden_escalation=identity["hidden_escalation"],
        findings_count=len(findings),
        findings=findings,
    )


@app.get("/findings", response_model=PaginatedResponse[Finding], tags=["Findings"])
def list_findings(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    size: int = Query(50, ge=1, le=500, description="Items per page"),
    rule: str | None = Query(None, description="Filter by detection rule"),
    platform: str | None = Query(
        None, description="Filter by platform involved ('ad', 'aws', 'okta')"
    ),
    severity: str | None = Query(
        None, description="Filter by severity ('critical', 'high', 'medium', 'low')"
    ),
    identity_id: str | None = Query(None, description="Filter by identity identifier"),
) -> PaginatedResponse[Finding]:
    """List explained security findings with multi-dimensional filtering and pagination."""
    findings = app_state.findings

    if rule:
        findings = [f for f in findings if f.rule.lower() == rule.lower()]

    if platform:
        p_lower = platform.lower()
        findings = [f for f in findings if any(p.lower() == p_lower for p in f.platforms)]

    if severity:
        findings = [f for f in findings if f.severity.lower() == severity.lower()]

    if identity_id:
        findings = [f for f in findings if f.identity_id == identity_id]

    total = len(findings)
    pages = math.ceil(total / size) if total > 0 else 1
    offset = (page - 1) * size
    page_items = findings[offset : offset + size]

    return PaginatedResponse(
        items=page_items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@app.get("/findings/{id}", response_model=Finding, tags=["Findings"])
def get_finding(id: str) -> Finding:
    """Retrieve a single finding with full evidence, privilege path, and remediation advice."""
    finding = app_state.findings_by_id.get(id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{id}' not found",
        )
    return finding


@app.get("/evaluation", response_model=EvaluationResponse, tags=["Evaluation"])
def get_evaluation(
    split: str = Query(
        "train", description="Dataset split to evaluate ('train', 'test', 'holdout')"
    ),
) -> EvaluationResponse:
    """Compute and return scenario-level evaluation metrics.

    Calls evaluation functions in accessatlas.evaluation strictly without loading GT sheets directly.
    """
    if split not in ("train", "test", "holdout"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid split '{split}'. Choices: 'train', 'test', 'holdout'",
        )

    # Call isolated evaluation function
    from accessatlas.evaluation.scenario_metrics import (
        evaluate_scenario_findings,
        load_gt_scenario_data,
    )

    try:
        gt_labels, gt_links = load_gt_scenario_data()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ground truth evaluation data unavailable: {exc}",
        )

    report = evaluate_scenario_findings(app_state.findings, gt_labels, gt_links, split=split)

    scenario_items = {
        k: ScenarioMetricItem(
            scenario=v.scenario,
            covered=v.covered,
            tp=v.tp,
            fp=v.fp,
            fn=v.fn,
            precision=v.precision,
            recall=v.recall,
            f1=v.f1,
            notes=v.notes,
        )
        for k, v in report.scenarios.items()
    }

    trap_items = {
        k: TrapMetricItem(
            scenario=v.scenario,
            total_traps=v.total_traps,
            flagged_traps=v.flagged_traps,
            false_alarm_rate=v.false_alarm_rate,
            has_firing_rule=v.has_firing_rule,
            notes=v.notes,
        )
        for k, v in report.traps.items()
    }

    return EvaluationResponse(
        split=report.split,
        total_identities=report.total_identities,
        total_findings=report.total_findings,
        findings_by_rule=report.findings_by_rule,
        findings_by_severity=report.findings_by_severity,
        scenarios=scenario_items,
        traps=trap_items,
    )
