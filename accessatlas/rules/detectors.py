"""Detection rules implementation for AccessAtlas M4.

Transforms M2 (identity resolution) and M3 (effective privilege) outputs,
alongside core ingestion tables and audit logs, into explainable security findings.
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from accessatlas.rules.models import Finding
from accessatlas.rules.suppression import SuppressionEngine
from accessatlas.utils import load_config

logger = logging.getLogger(__name__)


def detect_offboarding_gap(
    hr_df: pd.DataFrame,
    hr_offboarding_df: pd.DataFrame | None,
    ad_users_df: pd.DataFrame | None,
    aws_users_df: pd.DataFrame | None,
    okta_users_df: pd.DataFrame | None,
    resolved_identities: pd.DataFrame,
    suppression_engine: SuppressionEngine,
    snapshot_date: pd.Timestamp,
) -> list[Finding]:
    """Detect terminated employees who still retain active platform accounts."""
    findings: list[Finding] = []

    # Map platform account status lookups
    ad_active = {}
    if ad_users_df is not None and not ad_users_df.empty:
        ad_active = dict(
            zip(
                ad_users_df["account_id"].astype(str),
                ad_users_df["enabled"].fillna(False).astype(bool),
            )
        )

    aws_active = {}
    if aws_users_df is not None and not aws_users_df.empty:
        aws_active = dict(
            zip(aws_users_df["user_id"].astype(str), aws_users_df["status"].str.lower() == "active")
        )

    okta_active = {}
    if okta_users_df is not None and not okta_users_df.empty:
        okta_active = dict(
            zip(
                okta_users_df["okta_id"].astype(str),
                okta_users_df["status"].str.upper().isin(["ACTIVE", "SUSPENDED"]),
            )
        )

    # Identify terminated employees
    terminated_hr = hr_df[hr_df["status"].str.lower() == "terminated"].copy()
    term_emp_ids = set(terminated_hr["employee_id"].astype(str))

    # Also check HR_Offboarding if present
    offboarding_map = {}
    if hr_offboarding_df is not None and not hr_offboarding_df.empty:
        for _, row in hr_offboarding_df.iterrows():
            eid = str(row["employee_id"])
            offboarding_map[eid] = row.to_dict()
            t_date = pd.to_datetime(row.get("termination_date"))
            if pd.notna(t_date) and t_date <= snapshot_date:
                term_emp_ids.add(eid)

    # Check each resolved identity belonging to a terminated employee
    human_res = resolved_identities[resolved_identities["identity_kind"] == "human"]
    for _, row in human_res.iterrows():
        eid = str(row["identity_id"])
        if eid not in term_emp_ids:
            continue

        active_plats: list[str] = []
        evidence: list[str] = []

        ad_acc = row.get("ad_account_id")
        if pd.notna(ad_acc) and ad_active.get(str(ad_acc), False):
            active_plats.append("ad")
            evidence.append(f"AD account '{ad_acc}' is still enabled (enabled=True)")

        aws_acc = row.get("aws_user_id")
        if pd.notna(aws_acc) and aws_active.get(str(aws_acc), False):
            active_plats.append("aws")
            evidence.append(f"AWS IAM user '{aws_acc}' is still active (status=active)")

        okta_acc = row.get("okta_id")
        if pd.notna(okta_acc) and okta_active.get(str(okta_acc), False):
            active_plats.append("okta")
            evidence.append(f"Okta account '{okta_acc}' has not been deprovisioned")

        # Check offboarding unrevoked flag if no direct active account found yet
        off_info = offboarding_map.get(eid)
        if not active_plats and off_info and off_info.get("all_platforms_revoked") is False:
            unrevoked: list[str] = []
            if pd.isna(off_info.get("ad_disabled_date")):
                unrevoked.append("ad")
                evidence.append(
                    "HR Offboarding record: AD disabled date is missing (account unrevoked)"
                )
            if pd.isna(off_info.get("aws_access_removed_date")):
                unrevoked.append("aws")
                evidence.append(
                    "HR Offboarding record: AWS access removal date is missing (account unrevoked)"
                )
            if pd.isna(off_info.get("okta_deactivated_date")):
                unrevoked.append("okta")
                evidence.append(
                    "HR Offboarding record: Okta deactivated date is missing (account unrevoked)"
                )

            # If individual dates are not missing, check which platform accounts the identity owns
            if not unrevoked:
                for p_col, p_name in [
                    ("ad_account_id", "ad"),
                    ("aws_user_id", "aws"),
                    ("okta_id", "okta"),
                ]:
                    if pd.notna(row.get(p_col)):
                        unrevoked.append(p_name)
                evidence.append(
                    "HR Offboarding record indicates unrevoked platform access across assigned accounts"
                )

            if not unrevoked:
                unrevoked = ["ad", "aws", "okta"]
                evidence.append("HR Offboarding record indicates unrevoked platform access")

            active_plats.extend(unrevoked)

        active_plats = list(dict.fromkeys(active_plats))

        if active_plats:
            suppressed, s_reason = suppression_engine.check_suppression(
                "offboarding_gap", eid, active_plats
            )
            if suppressed:
                logger.debug("Suppressed offboarding_gap for %s: %s", eid, s_reason)
                continue

            findings.append(
                Finding(
                    finding_id=f"FND-offboarding_gap-{eid}",
                    rule="offboarding_gap",
                    identity_id=eid,
                    platforms=active_plats,
                    severity="high",
                    evidence=evidence,
                    recommended_action="Disable and deprovision all active platform accounts immediately.",
                )
            )

    return findings


def detect_orphan_account(
    unresolved_accounts: pd.DataFrame,
) -> list[Finding]:
    """Detect orphan accounts flagged during identity resolution."""
    findings: list[Finding] = []
    if unresolved_accounts.empty or "reason" not in unresolved_accounts.columns:
        return findings

    orphans = unresolved_accounts[unresolved_accounts["reason"] == "orphan_account"]

    for _, row in orphans.iterrows():
        acc_id = str(row["account_id"])
        platform = str(row.get("platform", "unknown"))
        raw_user = row.get("raw_username") or row.get("raw_email") or acc_id

        findings.append(
            Finding(
                finding_id=f"FND-orphan_account-{acc_id}",
                rule="orphan_account",
                identity_id=acc_id,
                account_id=acc_id,
                platforms=[platform],
                severity="high",
                evidence=[
                    f"{platform.upper()} account '{raw_user}' has no matching HR record and holds elevated privileges."
                ],
                recommended_action="Verify ownership with system administrators or decommission unmanaged orphan account.",
            )
        )

    return findings


def detect_dormant_admin(
    privilege_df: pd.DataFrame,
    resolved_identities: pd.DataFrame,
    audit_events_df: pd.DataFrame,
    suppression_engine: SuppressionEngine,
    snapshot_date: pd.Timestamp,
    dormant_days: int = 60,
) -> list[Finding]:
    """Detect privileged identities (tier <= 1) with no recent activity in Audit_Events."""
    findings: list[Finding] = []

    # Map accounts for each identity
    acc_map: dict[str, list[str]] = {}
    for _, row in resolved_identities.iterrows():
        iid = str(row["identity_id"])
        accs = [
            str(a)
            for a in [row.get("ad_account_id"), row.get("aws_user_id"), row.get("okta_id")]
            if pd.notna(a) and a
        ]
        acc_map[iid] = accs

    # Pre-index latest event per account in Audit_Events
    latest_event_by_acc: dict[str, pd.Timestamp] = {}
    if not audit_events_df.empty:
        grouped = audit_events_df.groupby("account_id")["timestamp"].max()
        latest_event_by_acc = {str(k): pd.to_datetime(v) for k, v in grouped.items()}

    # Check privileged identities
    priv_identities = privilege_df[privilege_df["overall_effective_tier"] <= 1]

    for _, row in priv_identities.iterrows():
        iid = str(row["identity_id"])
        accs = acc_map.get(iid, [])
        if not accs:
            continue

        timestamps = [latest_event_by_acc[a] for a in accs if a in latest_event_by_acc]
        max_ts = max(timestamps) if timestamps else None

        is_dormant = False
        evidence_str = ""

        if max_ts is None:
            is_dormant = True
            evidence_str = f"Privileged identity holds tier {row['overall_effective_tier']} with 0 audit events recorded across all accounts"
        else:
            days_inactive = (snapshot_date - max_ts).days
            if days_inactive > dormant_days:
                is_dormant = True
                evidence_str = f"Privileged identity holds tier {row['overall_effective_tier']} with no audit activity for {days_inactive} days (last active: {max_ts.date()})"

        if is_dormant:
            # Determine platform(s) where tier <= 1
            plats: list[str] = []
            if row.get("ad_effective_tier", 99) <= 1:
                plats.append("ad")
            if row.get("aws_effective_tier", 99) <= 1:
                plats.append("aws")
            if row.get("okta_tier", 99) <= 1:
                plats.append("okta")
            if not plats:
                plats = ["multienvironment"]

            suppressed, s_reason = suppression_engine.check_suppression("dormant_admin", iid, plats)
            if suppressed:
                logger.debug("Suppressed dormant_admin for %s: %s", iid, s_reason)
                continue

            findings.append(
                Finding(
                    finding_id=f"FND-dormant_admin-{iid}",
                    rule="dormant_admin",
                    identity_id=iid,
                    platforms=plats,
                    severity="high",
                    evidence=[evidence_str],
                    privilege_path=str(row.get("overall_grant_path", "")),
                    recommended_action="Revoke or down-scope unused administrative privileges in accordance with least privilege.",
                )
            )

    return findings


def detect_expired_exception_active(
    exceptions_df: pd.DataFrame,
    privilege_df: pd.DataFrame,
    snapshot_date: pd.Timestamp,
) -> list[Finding]:
    """Detect exceptions whose end date has passed but whose privileges remain active."""
    findings: list[Finding] = []
    if exceptions_df.empty:
        return findings

    # Index privilege by identity_id
    priv_map = {str(row["identity_id"]): row for _, row in privilege_df.iterrows()}

    for _, exc in exceptions_df.iterrows():
        exc_id = str(exc["exception_id"])
        emp_id = str(exc["employee_id"])
        e_date = pd.to_datetime(exc.get("end_date"))
        status = str(exc.get("status", "")).lower()

        # Exception is expired if status == 'expired' or end_date < snapshot_date
        is_expired = (status == "expired") or (pd.notna(e_date) and e_date < snapshot_date)
        if not is_expired:
            continue

        # Check if privileges are still active on the exception platform(s)
        priv_row = priv_map.get(emp_id)
        if priv_row is None:
            continue

        exc_plats = [p.strip().lower() for p in str(exc.get("platforms", "")).split("|")]
        active_priv_plats: list[str] = []

        for p in exc_plats:
            if p == "ad" and priv_row.get("ad_effective_tier", 99) <= 1:
                active_priv_plats.append("ad")
            elif p == "aws" and priv_row.get("aws_effective_tier", 99) <= 1:
                active_priv_plats.append("aws")
            elif p == "okta" and priv_row.get("okta_tier", 99) <= 1:
                active_priv_plats.append("okta")

        if active_priv_plats:
            findings.append(
                Finding(
                    finding_id=f"FND-expired_exception_active-{exc_id}",
                    rule="expired_exception_active",
                    identity_id=emp_id,
                    platforms=active_priv_plats,
                    severity="high",
                    evidence=[
                        f"Exception {exc_id} expired on {e_date.date() if pd.notna(e_date) else 'N/A'}, "
                        f"but privileged tier <= 1 remains active on {', '.join(active_priv_plats)}."
                    ],
                    recommended_action="Revoke expired exception privileges and confirm deprovisioning.",
                )
            )

    return findings


def detect_stale_token(
    tokens_df: pd.DataFrame,
    snapshot_date: pd.Timestamp,
    rotation_days: int = 365,
    inactivity_days: int = 90,
) -> list[Finding]:
    """Detect API tokens not rotated or not used within configurable thresholds."""
    findings: list[Finding] = []
    if tokens_df.empty:
        return findings

    for _, row in tokens_df.iterrows():
        # Check active tokens
        if str(row.get("status", "")).lower() != "active":
            continue

        tok_id = str(row["token_id"])
        identity_id = str(row.get("identity_id", "unknown"))
        acc_id = str(row.get("account_id", ""))
        platform = str(row.get("platform", "aws"))

        r_date = pd.to_datetime(row.get("last_rotated_at"))
        u_date = pd.to_datetime(row.get("last_used_at"))

        evidence: list[str] = []
        if pd.notna(r_date):
            days_rotated = (snapshot_date - r_date).days
            if days_rotated > rotation_days:
                evidence.append(
                    f"Token last rotated {days_rotated} days ago (limit: {rotation_days} days)"
                )

        if pd.notna(u_date):
            days_used = (snapshot_date - u_date).days
            if days_used > inactivity_days:
                evidence.append(
                    f"Token unused for {days_used} days (limit: {inactivity_days} days)"
                )

        if evidence:
            findings.append(
                Finding(
                    finding_id=f"FND-stale_token-{tok_id}",
                    rule="stale_token",
                    identity_id=identity_id,
                    account_id=acc_id,
                    platforms=[platform],
                    severity="medium",
                    evidence=evidence,
                    recommended_action="Rotate token credentials immediately and delete inactive keys.",
                )
            )

    return findings


def detect_nested_group_escalation(
    privilege_df: pd.DataFrame,
    unresolved_accounts: pd.DataFrame,
    suppression_engine: SuppressionEngine,
) -> list[Finding]:
    """Detect hidden privilege escalations through nested groups or federation with confidence caveat."""
    findings: list[Finding] = []

    # Pre-index accounts present in unresolved table
    unres_acc_ids = (
        set(unresolved_accounts["account_id"].dropna().astype(str))
        if not unresolved_accounts.empty
        else set()
    )
    unres_emp_ids: set[str] = set()
    if not unresolved_accounts.empty and "candidate_employee_id" in unresolved_accounts.columns:
        for val in unresolved_accounts["candidate_employee_id"].dropna():
            for emp in str(val).split(","):
                clean_emp = emp.strip()
                if clean_emp:
                    unres_emp_ids.add(clean_emp)

    escalations = privilege_df[privilege_df["hidden_escalation"].fillna(False).astype(bool)]

    for _, row in escalations.iterrows():
        iid = str(row["identity_id"])
        path = str(row.get("overall_grant_path", "nested escalation path"))

        # Platforms involved
        plats: list[str] = []
        if row.get("ad_effective_tier", 99) <= 2:
            plats.append("ad")
        if row.get("aws_effective_tier", 99) <= 2:
            plats.append("aws")
        if row.get("okta_tier", 99) <= 2:
            plats.append("okta")
        if not plats:
            plats = ["multienvironment"]

        suppressed, s_reason = suppression_engine.check_suppression(
            "nested_group_escalation", iid, plats
        )
        if suppressed:
            logger.debug("Suppressed nested_group_escalation for %s: %s", iid, s_reason)
            continue

        caveat = None
        severity = "high"
        # Check if identity has an account in M2's unresolved table
        has_unresolved = (iid in unres_emp_ids) or (iid in unres_acc_ids)
        if not has_unresolved:
            for acc_col in ["ad_account_id", "aws_user_id", "okta_id"]:
                acc = row.get(acc_col)
                if pd.notna(acc) and str(acc) in unres_acc_ids:
                    has_unresolved = True
                    break

        if has_unresolved:
            caveat = "Identity has accounts in M2 unresolved table; escalation may be an artifact of an unlinked account."
            severity = "low"

        findings.append(
            Finding(
                finding_id=f"FND-nested_group_escalation-{iid}",
                rule="nested_group_escalation",
                identity_id=iid,
                platforms=plats,
                severity=severity,
                evidence=[
                    f"Hidden escalation detected: effective tier {row['overall_effective_tier']} reached via nesting or federation."
                ],
                privilege_path=path,
                recommended_action="Review nested group hierarchy and remove unintended escalation paths.",
                confidence_caveat=caveat,
            )
        )

    return findings


def detect_cross_platform_admin(
    privilege_df: pd.DataFrame,
    suppression_engine: SuppressionEngine,
) -> list[Finding]:
    """Detect identities holding privileged administrative tier (<= 1) on two or more platforms."""
    findings: list[Finding] = []

    for _, row in privilege_df.iterrows():
        iid = str(row["identity_id"])
        priv_plats: list[str] = []

        if row.get("ad_effective_tier", 99) <= 1:
            priv_plats.append("ad")
        if row.get("aws_effective_tier", 99) <= 1:
            priv_plats.append("aws")
        if row.get("okta_tier", 99) <= 1:
            priv_plats.append("okta")

        if len(priv_plats) >= 2:
            suppressed, s_reason = suppression_engine.check_suppression(
                "cross_platform_admin", iid, priv_plats
            )
            if suppressed:
                logger.debug("Suppressed cross_platform_admin for %s: %s", iid, s_reason)
                continue

            findings.append(
                Finding(
                    finding_id=f"FND-cross_platform_admin-{iid}",
                    rule="cross_platform_admin",
                    identity_id=iid,
                    platforms=priv_plats,
                    severity="medium",
                    evidence=[
                        f"Privilege concentration: identity holds administrative tier <= 1 across {len(priv_plats)} platforms: {', '.join(priv_plats)}."
                    ],
                    recommended_action="Separate administrative duties or enforce dual-authorization across disparate cloud platforms.",
                )
            )

    return findings


def detect_orphaned_service_account(
    resolved_identities: pd.DataFrame,
    hr_df: pd.DataFrame,
    hr_offboarding_df: pd.DataFrame | None,
    snapshot_date: pd.Timestamp,
) -> list[Finding]:
    """Detect service accounts whose designated owner has terminated from the company.

    Do NOT flag service accounts that simply have no owner (ownerless service accounts are normal).
    """
    findings: list[Finding] = []

    # Map terminated HR employees
    terminated_emps = set(
        hr_df[hr_df["status"].str.lower() == "terminated"]["employee_id"].astype(str)
    )
    if hr_offboarding_df is not None and not hr_offboarding_df.empty:
        for _, row in hr_offboarding_df.iterrows():
            t_date = pd.to_datetime(row.get("termination_date"))
            if pd.notna(t_date) and t_date <= snapshot_date:
                terminated_emps.add(str(row["employee_id"]))

    service_identities = resolved_identities[resolved_identities["identity_kind"] == "service"]

    for _, row in service_identities.iterrows():
        iid = str(row["identity_id"])
        owner_id = row.get("owner_employee_id")

        # Do NOT flag ownerless service accounts
        if pd.isna(owner_id) or not str(owner_id).strip():
            continue

        owner_id_str = str(owner_id).strip()
        if owner_id_str in terminated_emps:
            # Determine platform and account ID from identity_id (svc:<platform>:<account_id>)
            parts = iid.split(":")
            platform = parts[1] if len(parts) >= 2 else "unknown"
            acc_id = parts[2] if len(parts) >= 3 else iid

            findings.append(
                Finding(
                    finding_id=f"FND-orphaned_service_account-{acc_id}",
                    rule="orphaned_service_account",
                    identity_id=iid,
                    account_id=acc_id,
                    platforms=[platform],
                    severity="medium",
                    evidence=[
                        f"Service account '{acc_id}' is owned by employee '{owner_id_str}' who is terminated in HR."
                    ],
                    recommended_action="Reassign service account to an active employee owner or decommission if obsolete.",
                )
            )

    return findings


def detect_unlinked_account_review(
    unresolved_accounts: pd.DataFrame,
) -> list[Finding]:
    """Detect unlinked accounts flagged by resolver as ambiguous_name or signal_conflict."""
    findings: list[Finding] = []
    if unresolved_accounts.empty or "reason" not in unresolved_accounts.columns:
        return findings

    review_accounts = unresolved_accounts[
        unresolved_accounts["reason"].isin(["ambiguous_name", "signal_conflict"])
    ]

    for _, row in review_accounts.iterrows():
        acc_id = str(row["account_id"])
        platform = str(row.get("platform", "unknown"))
        reason = str(row.get("reason", "unknown"))
        raw_user = row.get("raw_username") or row.get("raw_display_name") or acc_id

        findings.append(
            Finding(
                finding_id=f"FND-unlinked_account_review-{acc_id}",
                rule="unlinked_account_review",
                identity_id=acc_id,
                account_id=acc_id,
                platforms=[platform],
                severity="low",
                evidence=[
                    f"{platform.upper()} account '{raw_user}' could not be unambiguously linked ({reason})."
                ],
                recommended_action="Conduct manual identity verification to resolve identity conflict or name ambiguity.",
            )
        )

    return findings


def evaluate_all_rules(
    hr_df: pd.DataFrame,
    hr_offboarding_df: pd.DataFrame | None,
    ad_users_df: pd.DataFrame | None,
    aws_users_df: pd.DataFrame | None,
    okta_users_df: pd.DataFrame | None,
    resolved_identities: pd.DataFrame,
    unresolved_accounts: pd.DataFrame,
    privilege_df: pd.DataFrame,
    audit_events_df: pd.DataFrame,
    exceptions_df: pd.DataFrame | None = None,
    oncall_df: pd.DataFrame | None = None,
    scheduled_jobs_df: pd.DataFrame | None = None,
    role_changes_df: pd.DataFrame | None = None,
    tokens_df: pd.DataFrame | None = None,
    config: dict[str, Any] | None = None,
) -> list[Finding]:
    """Orchestrate all 9 detection rules with context suppression."""
    cfg = config or load_config()
    snapshot_date = pd.Timestamp(cfg.get("snapshot_date", "2026-10-12"))
    rules_cfg = cfg.get("rules", {})

    dormant_days = int(rules_cfg.get("dormant_admin_days", 60))
    token_rotation_days = int(rules_cfg.get("token_rotation_days", 365))
    token_inactivity_days = int(rules_cfg.get("token_inactivity_days", 90))
    new_hire_days = int(rules_cfg.get("new_hire_days", 30))
    role_change_days = int(rules_cfg.get("recent_role_change_days", 30))

    suppression_engine = SuppressionEngine(
        snapshot_date=snapshot_date,
        exceptions_df=exceptions_df,
        oncall_df=oncall_df,
        scheduled_jobs_df=scheduled_jobs_df,
        hr_df=hr_df,
        role_changes_df=role_changes_df,
        tokens_df=tokens_df,
        new_hire_days=new_hire_days,
        role_change_days=role_change_days,
    )

    all_findings: list[Finding] = []

    # 1. Offboarding gap
    all_findings.extend(
        detect_offboarding_gap(
            hr_df=hr_df,
            hr_offboarding_df=hr_offboarding_df,
            ad_users_df=ad_users_df,
            aws_users_df=aws_users_df,
            okta_users_df=okta_users_df,
            resolved_identities=resolved_identities,
            suppression_engine=suppression_engine,
            snapshot_date=snapshot_date,
        )
    )

    # 2. Orphan account
    all_findings.extend(detect_orphan_account(unresolved_accounts))

    # 3. Dormant admin
    all_findings.extend(
        detect_dormant_admin(
            privilege_df=privilege_df,
            resolved_identities=resolved_identities,
            audit_events_df=audit_events_df,
            suppression_engine=suppression_engine,
            snapshot_date=snapshot_date,
            dormant_days=dormant_days,
        )
    )

    # 4. Expired exception active
    if exceptions_df is not None and not exceptions_df.empty:
        all_findings.extend(
            detect_expired_exception_active(
                exceptions_df=exceptions_df,
                privilege_df=privilege_df,
                snapshot_date=snapshot_date,
            )
        )

    # 5. Stale token
    if tokens_df is not None and not tokens_df.empty:
        all_findings.extend(
            detect_stale_token(
                tokens_df=tokens_df,
                snapshot_date=snapshot_date,
                rotation_days=token_rotation_days,
                inactivity_days=token_inactivity_days,
            )
        )

    # 6. Nested group escalation
    all_findings.extend(
        detect_nested_group_escalation(
            privilege_df=privilege_df,
            unresolved_accounts=unresolved_accounts,
            suppression_engine=suppression_engine,
        )
    )

    # 7. Cross-platform admin
    all_findings.extend(
        detect_cross_platform_admin(
            privilege_df=privilege_df,
            suppression_engine=suppression_engine,
        )
    )

    # 8. Orphaned service account
    all_findings.extend(
        detect_orphaned_service_account(
            resolved_identities=resolved_identities,
            hr_df=hr_df,
            hr_offboarding_df=hr_offboarding_df,
            snapshot_date=snapshot_date,
        )
    )

    # 9. Unlinked account review
    all_findings.extend(detect_unlinked_account_review(unresolved_accounts))

    logger.info("Rules evaluation generated %d total findings", len(all_findings))
    return all_findings
