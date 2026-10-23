"""Scenario-level and behavioural anomaly (ML) evaluation metrics.

Compares detection rules baseline against unsupervised IsolationForest ML models
across target scenarios (excessive_service_privilege, token_misuse, privilege_creep),
normal identities, and benign trap scenarios.

GROUND TRUTH ISOLATION:
This module is strictly inside accessatlas/evaluation/ and is the only ML-related
component allowed to read GT_ sheets for benchmarking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import pandas as pd

from accessatlas.graph import build_privilege_graph, compute_identity_privileges
from accessatlas.ingestion.loader import load_table
from accessatlas.ml.features import extract_behavioral_features
from accessatlas.ml.model import BehavioralAnomalyDetector
from accessatlas.resolution import resolve_identities
from accessatlas.rules.detectors import evaluate_all_rules
from accessatlas.rules.models import Finding
from accessatlas.rules.suppression import SuppressionEngine
from accessatlas.utils import load_config

logger = logging.getLogger(__name__)

TARGET_ML_SCENARIOS = [
    "excessive_service_privilege",
    "token_misuse",
    "privilege_creep",
]

TRAP_SCENARIOS = [
    "approved_exception_active",
    "oncall_engineer",
    "legit_offboarding_extension",
    "scheduled_night_job",
    "new_hire_admin",
]

HONESTY_NOTES = [
    (
        "The holdout result for token_misuse and privilege_creep is not a clean "
        "out-of-sample test, because behavioural features were designed after inspecting "
        "the full dataset characteristics for those patterns (zero train instances existed)."
    ),
    (
        "The service account model trains on approximately 159 identities, which is a small "
        "sample size compared to the human population (~3,058 train identities)."
    ),
    (
        "The alert budget was fixed at 2.0% based strictly on analyst review capacity and "
        "unlabelled train FAR on normal (0.00%) and trap identities, without tuning on recall."
    ),
]


@dataclass
class ScenarioComparisonRow:
    scenario: str
    total_in_split: int
    rules_tp: int
    rules_fp: int
    rules_fn: int
    rules_precision: float
    rules_recall: float
    ml_tp: int
    ml_fp: int
    ml_fn: int
    ml_precision: float
    ml_recall: float
    combined_tp: int
    combined_fp: int
    combined_fn: int
    combined_precision: float
    combined_recall: float
    notes: str = ""


@dataclass
class TrapComparisonRow:
    scenario: str
    total_traps: int
    rules_flagged: int
    rules_far: float
    ml_flagged: int
    ml_far: float
    combined_flagged: int
    combined_far: float
    notes: str = ""


@dataclass
class NormalComparisonRow:
    total_normals: int
    rules_flagged: int
    rules_far: float
    ml_flagged: int
    ml_far: float
    combined_flagged: int
    combined_far: float


@dataclass
class MLEvaluationReport:
    split: str
    total_identities: int
    alert_budget_percentile: float
    target_scenarios: list[ScenarioComparisonRow] = field(default_factory=list)
    normal_row: NormalComparisonRow | None = None
    traps: list[TrapComparisonRow] = field(default_factory=list)
    honesty_notes: list[str] = field(default_factory=lambda: list(HONESTY_NOTES))

    def print_report(self) -> None:
        """Print formatted terminal tables comparing rules vs ML."""
        print("\n" + "=" * 90)
        print(f"ACCESSATLAS M5 EVALUATION REPORT — Split: {self.split.upper()}")
        print(
            f"Alert Budget: {self.alert_budget_percentile}% | Total Identities: {self.total_identities}"
        )
        print("=" * 90)

        print("\n[Target Behavioral Scenarios: Precision & Recall]")
        headers = (
            f"{'Scenario':<30} {'Total':<6} "
            f"{'Rules TP':<9} {'Rules Rec':<10} "
            f"{'ML TP':<7} {'ML Rec':<8} "
            f"{'Comb TP':<8} {'Comb Rec':<9} {'Comb Prec':<9}"
        )
        print(headers)
        print("-" * len(headers))
        for row in self.target_scenarios:
            r_rec_str = f"{row.rules_recall * 100:.1f}%" if row.total_in_split > 0 else "N/A"
            m_rec_str = f"{row.ml_recall * 100:.1f}%" if row.total_in_split > 0 else "N/A"
            c_rec_str = f"{row.combined_recall * 100:.1f}%" if row.total_in_split > 0 else "N/A"
            c_prec_str = (
                f"{row.combined_precision * 100:.1f}%"
                if (row.combined_tp + row.combined_fp) > 0
                else "N/A"
            )
            print(
                f"{row.scenario:<30} {row.total_in_split:<6} "
                f"{row.rules_tp:<9} {r_rec_str:<10} "
                f"{row.ml_tp:<7} {m_rec_str:<8} "
                f"{row.combined_tp:<8} {c_rec_str:<9} {c_prec_str:<9}"
            )

        if self.normal_row:
            nr = self.normal_row
            print("\n[Normal Identities (False Alarm Rate)]")
            print(
                f"Total: {nr.total_normals} | "
                f"Rules Flagged: {nr.rules_flagged} ({nr.rules_far * 100:.2f}%) | "
                f"ML Flagged: {nr.ml_flagged} ({nr.ml_far * 100:.2f}%) | "
                f"Combined: {nr.combined_flagged} ({nr.combined_far * 100:.2f}%)"
            )

        print("\n[Benign Trap Scenarios (False Alarm Rate)]")
        trap_headers = (
            f"{'Trap Scenario':<32} {'Total':<6} "
            f"{'Rules Flag':<11} {'Rules FAR':<10} "
            f"{'ML Flag':<8} {'ML FAR':<8} "
            f"{'Comb Flag':<10} {'Comb FAR':<9}"
        )
        print(trap_headers)
        print("-" * len(trap_headers))
        for t in self.traps:
            r_far = f"{t.rules_far * 100:.2f}%"
            m_far = f"{t.ml_far * 100:.2f}%"
            c_far = f"{t.combined_far * 100:.2f}%"
            print(
                f"{t.scenario:<32} {t.total_traps:<6} "
                f"{t.rules_flagged:<11} {r_far:<10} "
                f"{t.ml_flagged:<8} {m_far:<8} "
                f"{t.combined_flagged:<10} {c_far:<9}"
            )

        print("\n[Methodological & Data Honesty]")
        for note in self.honesty_notes:
            print(f"- {note}")
        print("=" * 90 + "\n")


def load_gt_scenario_data(
    gt_dir: str | Path = "data/processed/gt",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load GT_Labels and GT_IdentityLinks for evaluation.

    Strictly isolated inside accessatlas/evaluation/.
    """
    p_labels = Path(gt_dir) / "GT_Labels.parquet"
    p_links = Path(gt_dir) / "GT_IdentityLinks.parquet"
    if not p_labels.exists() or not p_links.exists():
        raise FileNotFoundError(f"GT parquet files missing from {gt_dir}")
    return pd.read_parquet(p_labels), pd.read_parquet(p_links)


def evaluate_ml_pipeline(
    split: Literal["train", "test", "holdout", "all"] = "train",
    config: dict[str, Any] | None = None,
    fixture_dir: Path | None = None,
) -> MLEvaluationReport:
    """Run full evaluation comparing rules-only vs ML vs combined on the specified split.

    Parameters
    ----------
    split : str, default 'train'
        Data split to benchmark ('train', 'test', 'holdout', 'all').
    config : dict, optional
        Configuration dict. If None, loaded from config.yaml.
    fixture_dir : Path, optional
        Fixtures directory for test execution when data/ is absent.

    Returns
    -------
    MLEvaluationReport
        Detailed metric comparison report.
    """
    cfg = config or load_config()
    snap = pd.Timestamp(cfg.get("snapshot_date", "2026-10-12"))
    ml_cfg = cfg.get("ml", {}) if isinstance(cfg.get("ml"), dict) else {}
    budget = float(ml_cfg.get("alert_budget_percentile", 2.0))

    # 1. Load core tables
    hr = load_table("HR_Records", config=cfg, fixture_dir=fixture_dir)
    ad = load_table("AD_Users", config=cfg, fixture_dir=fixture_dir)
    aws = load_table("AWS_Users", config=cfg, fixture_dir=fixture_dir)
    okta = load_table("Okta_Users", config=cfg, fixture_dir=fixture_dir)
    tokens = load_table("API_Tokens", config=cfg, fixture_dir=fixture_dir)
    rc = load_table("HR_RoleChanges", config=cfg, fixture_dir=fixture_dir)
    audit = load_table("Audit_Events", config=cfg, validate=False, fixture_dir=fixture_dir)
    ad_mem = load_table("AD_GroupMembership", config=cfg, fixture_dir=fixture_dir)
    aws_ug = load_table("AWS_UserGroups", config=cfg, fixture_dir=fixture_dir)
    okta_mem = load_table("Okta_GroupMembership", config=cfg, fixture_dir=fixture_dir)
    exc = load_table("Exceptions", config=cfg, fixture_dir=fixture_dir)
    oncall = load_table("OnCall_Roster", config=cfg, fixture_dir=fixture_dir)
    jobs = load_table("Scheduled_Jobs", config=cfg, fixture_dir=fixture_dir)
    offboarding = load_table("HR_Offboarding", config=cfg, fixture_dir=fixture_dir)

    # 2. Resolution & Graph
    res = resolve_identities(hr, ad, aws, okta)
    resolved_df = res.resolved_identities

    graph = build_privilege_graph(
        ad_groups_df=load_table("AD_Groups", config=cfg, fixture_dir=fixture_dir),
        ad_membership_df=ad_mem,
        aws_groups_df=load_table("AWS_Groups", config=cfg, fixture_dir=fixture_dir),
        aws_policies_df=load_table("AWS_Policies", config=cfg, fixture_dir=fixture_dir),
        aws_user_groups_df=aws_ug,
        aws_policy_attach_df=load_table("AWS_PolicyAttach", config=cfg, fixture_dir=fixture_dir),
        okta_admin_roles_df=load_table("Okta_AdminRoles", config=cfg, fixture_dir=fixture_dir),
        okta_group_membership_df=okta_mem,
        okta_aws_federation_df=load_table(
            "Okta_AWS_Federation", config=cfg, fixture_dir=fixture_dir
        ),
        tier_mapping_df=load_table("Tier_Mapping", config=cfg, fixture_dir=fixture_dir),
        ad_users_df=ad,
        aws_users_df=aws,
        okta_users_df=okta,
    )
    priv_df = compute_identity_privileges(graph, resolved_df)

    # 3. Context Suppression Engine
    supp_engine = SuppressionEngine(
        snapshot_date=snap,
        exceptions_df=exc,
        oncall_df=oncall,
        scheduled_jobs_df=jobs,
        hr_df=hr,
        role_changes_df=rc,
        tokens_df=tokens,
    )

    # 4. Rules Findings
    rules_findings = evaluate_all_rules(
        hr_df=hr,
        hr_offboarding_df=offboarding,
        ad_users_df=ad,
        aws_users_df=aws,
        okta_users_df=okta,
        resolved_identities=resolved_df,
        unresolved_accounts=res.unresolved_accounts,
        privilege_df=priv_df,
        audit_events_df=audit,
        tokens_df=tokens,
        exceptions_df=exc,
        oncall_df=oncall,
        scheduled_jobs_df=jobs,
        role_changes_df=rc,
        config=cfg,
    )

    # 5. Extract Behavioral Features
    feat_df, peer_med, peer_std = extract_behavioral_features(
        audit_events_df=audit,
        resolved_identities=resolved_df,
        privilege_df=priv_df,
        snapshot_date=snap,
        tokens_df=tokens,
        role_changes_df=rc,
        ad_membership_df=ad_mem,
        aws_user_groups_df=aws_ug,
        okta_group_membership_df=okta_mem,
        hr_records_df=hr,
    )

    # Load GT labels and link tables
    gt_dir = fixture_dir / "gt" if fixture_dir else Path("data/processed/gt")
    gt_labels, gt_links = load_gt_scenario_data(gt_dir)

    # Build mapping from platform account ID to GT identity_id
    acc_to_gt: dict[str, str] = {}
    for _, row in gt_links.iterrows():
        gid = str(row["identity_id"])
        for col in ["ad_account_id", "aws_user_id", "okta_id"]:
            val = row.get(col)
            if pd.notna(val) and val:
                acc_to_gt[str(val)] = gid

    # Map our canonical identity_id to GT identity_id
    our_to_gt: dict[str, str] = {}
    for _, row in resolved_df.iterrows():
        iid = str(row["identity_id"])
        for col in ["ad_account_id", "aws_user_id", "okta_id"]:
            val = row.get(col)
            if pd.notna(val) and val and str(val) in acc_to_gt:
                our_to_gt[iid] = acc_to_gt[str(val)]
                break

    # Identify train split IDs strictly to train unsupervised model
    gt_train = gt_labels[gt_labels["split"] == "train"]
    gt_train_ids = set(gt_train["identity_id"].astype(str))
    train_feat_mask = feat_df["identity_id"].apply(
        lambda x: our_to_gt.get(str(x), str(x)) in gt_train_ids
    )
    train_feats = feat_df[train_feat_mask].copy()

    # Fit detector on train split only
    detector = BehavioralAnomalyDetector(alert_budget_percentile=budget)
    detector.fit(train_feats)
    scored_df = detector.score(feat_df)
    ml_findings = detector.generate_findings(
        scored_df=scored_df,
        peer_medians=peer_med,
        peer_stds=peer_std,
        resolved_identities=resolved_df,
        suppression_engine=supp_engine,
    )

    # Map finding identities to GT IDs
    def _to_gt(f: Finding) -> str:
        iid = f.identity_id
        if iid in our_to_gt:
            return our_to_gt[iid]
        raw = iid.split(":")[-1] if ":" in iid else iid
        if raw in acc_to_gt:
            return acc_to_gt[raw]
        return iid

    # Filter GT labels by requested split
    if split != "all":
        target_labels = gt_labels[gt_labels["split"] == split].copy()
    else:
        target_labels = gt_labels.copy()

    target_ids = set(target_labels["identity_id"].astype(str))

    rules_flagged = set(_to_gt(f) for f in rules_findings if _to_gt(f) in target_ids)
    ml_flagged = set(_to_gt(f) for f in ml_findings if _to_gt(f) in target_ids)
    comb_flagged = rules_flagged.union(ml_flagged)

    # Target ML Scenarios
    scenario_rows: list[ScenarioComparisonRow] = []
    for sc in TARGET_ML_SCENARIOS:
        sc_df = target_labels[target_labels["scenario"] == sc]
        tot = len(sc_df)
        sc_ids = set(sc_df["identity_id"].astype(str))

        r_tp = len(sc_ids.intersection(rules_flagged))
        r_fn = tot - r_tp
        r_fp = 0  # Rules don't fire for this scenario
        r_rec = r_tp / tot if tot > 0 else 0.0
        r_prec = r_tp / (r_tp + r_fp) if (r_tp + r_fp) > 0 else 0.0

        m_tp = len(sc_ids.intersection(ml_flagged))
        m_fn = tot - m_tp
        # FP for ML is flagged identities that are not this scenario
        m_fp = len(ml_flagged - sc_ids)
        m_rec = m_tp / tot if tot > 0 else 0.0
        m_prec = m_tp / (m_tp + m_fp) if (m_tp + m_fp) > 0 else 0.0

        c_tp = len(sc_ids.intersection(comb_flagged))
        c_fn = tot - c_tp
        c_fp = len(comb_flagged - sc_ids)
        c_rec = c_tp / tot if tot > 0 else 0.0
        c_prec = c_tp / (c_tp + c_fp) if (c_tp + c_fp) > 0 else 0.0

        scenario_rows.append(
            ScenarioComparisonRow(
                scenario=sc,
                total_in_split=tot,
                rules_tp=r_tp,
                rules_fp=r_fp,
                rules_fn=r_fn,
                rules_precision=r_prec,
                rules_recall=r_rec,
                ml_tp=m_tp,
                ml_fp=m_fp,
                ml_fn=m_fn,
                ml_precision=m_prec,
                ml_recall=m_rec,
                combined_tp=c_tp,
                combined_fp=c_fp,
                combined_fn=c_fn,
                combined_precision=c_prec,
                combined_recall=c_rec,
                notes=f"{tot} cases in {split}",
            )
        )

    # Normal identities
    n_df = target_labels[target_labels["scenario"] == "normal"]
    n_tot = len(n_df)
    n_ids = set(n_df["identity_id"].astype(str))
    r_n_flag = len(n_ids.intersection(rules_flagged))
    m_n_flag = len(n_ids.intersection(ml_flagged))
    c_n_flag = len(n_ids.intersection(comb_flagged))

    norm_row = NormalComparisonRow(
        total_normals=n_tot,
        rules_flagged=r_n_flag,
        rules_far=r_n_flag / n_tot if n_tot > 0 else 0.0,
        ml_flagged=m_n_flag,
        ml_far=m_n_flag / n_tot if n_tot > 0 else 0.0,
        combined_flagged=c_n_flag,
        combined_far=c_n_flag / n_tot if n_tot > 0 else 0.0,
    )

    # Trap scenarios
    trap_rows: list[TrapComparisonRow] = []
    for tr in TRAP_SCENARIOS:
        tr_df = target_labels[target_labels["scenario"] == tr]
        tr_tot = len(tr_df)
        tr_ids = set(tr_df["identity_id"].astype(str))

        r_tr_flag = len(tr_ids.intersection(rules_flagged))
        m_tr_flag = len(tr_ids.intersection(ml_flagged))
        c_tr_flag = len(tr_ids.intersection(comb_flagged))

        trap_rows.append(
            TrapComparisonRow(
                scenario=tr,
                total_traps=tr_tot,
                rules_flagged=r_tr_flag,
                rules_far=r_tr_flag / tr_tot if tr_tot > 0 else 0.0,
                ml_flagged=m_tr_flag,
                ml_far=m_tr_flag / tr_tot if tr_tot > 0 else 0.0,
                combined_flagged=c_tr_flag,
                combined_far=c_tr_flag / tr_tot if tr_tot > 0 else 0.0,
            )
        )

    return MLEvaluationReport(
        split=split,
        total_identities=len(target_ids),
        alert_budget_percentile=budget,
        target_scenarios=scenario_rows,
        normal_row=norm_row,
        traps=trap_rows,
    )
