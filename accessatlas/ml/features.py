"""Generic behavioral and entitlement feature extraction for unsupervised anomaly detection.

Extracts per-identity activity profiles from audit logs, tokens, role history,
and privilege graphs up to the snapshot date. Features are purely statistical
and unlabelled, with peer-relative standardization against departmental or
identity-kind baselines.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Feature column names for human identities
HUMAN_FEATURE_COLS: list[str] = [
    "events_per_day",
    "total_events",
    "off_hours_share",
    "distinct_ips",
    "distinct_countries",
    "max_bytes_transferred",
    "total_bytes_transferred",
    "failure_rate",
    "privileged_action_share",
    "mfa_rate",
    "total_groups_count",
    "has_role_change",
    "effective_tier_score",
    "privilege_utilization_gap",
    "token_count",
    "min_token_scope_tier",
    "peer_events_per_day_zscore",
    "peer_off_hours_zscore",
    "peer_distinct_ips_zscore",
    "peer_bytes_zscore",
    "peer_priv_action_zscore",
    "peer_group_count_zscore",
    "peer_tier_zscore",
]

# Feature column names for service accounts
SERVICE_FEATURE_COLS: list[str] = [
    "events_per_day",
    "total_events",
    "off_hours_share",
    "distinct_ips",
    "distinct_countries",
    "max_bytes_transferred",
    "total_bytes_transferred",
    "failure_rate",
    "privileged_action_share",
    "effective_tier_score",
    "privilege_utilization_gap",
    "token_count",
    "min_token_scope_tier",
    "peer_events_per_day_zscore",
    "peer_off_hours_zscore",
    "peer_distinct_ips_zscore",
    "peer_bytes_zscore",
    "peer_priv_action_zscore",
    "peer_tier_zscore",
]


def extract_behavioral_features(
    audit_events_df: pd.DataFrame,
    resolved_identities: pd.DataFrame,
    privilege_df: pd.DataFrame,
    snapshot_date: pd.Timestamp | str,
    tokens_df: pd.DataFrame | None = None,
    role_changes_df: pd.DataFrame | None = None,
    ad_membership_df: pd.DataFrame | None = None,
    aws_user_groups_df: pd.DataFrame | None = None,
    okta_group_membership_df: pd.DataFrame | None = None,
    hr_records_df: pd.DataFrame | None = None,
) -> tuple[pd.DataFrame, dict[str, dict[str, float]], dict[str, dict[str, float]]]:
    """Extract generic, unlabelled behavioral features per canonical identity.

    Parameters
    ----------
    audit_events_df : pd.DataFrame
        Raw or preprocessed enterprise audit events across platforms.
    resolved_identities : pd.DataFrame
        Canonical identity entity-resolution output from M2.
    privilege_df : pd.DataFrame
        Privilege graph outputs with overall effective tiers from M3.
    snapshot_date : pd.Timestamp | str
        Effective snapshot date (events strictly after this date are filtered out).
    tokens_df : pd.DataFrame, optional
        API tokens inventory.
    role_changes_df : pd.DataFrame, optional
        HR departmental and job title transfers.
    ad_membership_df : pd.DataFrame, optional
        Active Directory group memberships.
    aws_user_groups_df : pd.DataFrame, optional
        AWS IAM user group memberships.
    okta_group_membership_df : pd.DataFrame, optional
        Okta group memberships.
    hr_records_df : pd.DataFrame, optional
        HR records providing department classifications.

    Returns
    -------
    tuple[pd.DataFrame, dict, dict]
        1. DataFrame with identity features and peer z-scores.
        2. Dictionary of peer medians per peer group.
        3. Dictionary of peer standard deviations per peer group.
    """
    snap_dt = pd.to_datetime(snapshot_date)

    # 1. Map platform account IDs to canonical identity_id
    acc_to_ident: dict[str, str] = {}
    for _, row in resolved_identities.iterrows():
        iid = str(row["identity_id"])
        for col in ["ad_account_id", "aws_user_id", "okta_id"]:
            val = row.get(col)
            if pd.notna(val) and val:
                acc_to_ident[str(val)] = iid

    # 2. Filter audit events up to snapshot date
    audit = audit_events_df.copy()
    if not audit.empty and "timestamp" in audit.columns:
        audit["timestamp"] = pd.to_datetime(audit["timestamp"])
        audit = audit[audit["timestamp"] <= snap_dt].copy()

    # Link events to canonical identity
    if not audit.empty and "account_id" in audit.columns:
        audit["identity_id"] = audit["account_id"].astype(str).map(acc_to_ident)
    else:
        audit["identity_id"] = np.nan

    # 3. Aggregate audit event characteristics per identity
    if not audit.empty and audit["identity_id"].notna().any():
        valid_audit = audit[audit["identity_id"].notna()].copy()

        # Derived event flags
        hours = valid_audit["timestamp"].dt.hour
        days_of_week = valid_audit["timestamp"].dt.dayofweek
        valid_audit["is_off_hours"] = (hours < 7) | (hours >= 19) | (days_of_week >= 5)

        if "result" in valid_audit.columns:
            valid_audit["is_failure"] = (
                valid_audit["result"]
                .astype(str)
                .str.lower()
                .isin(["failure", "denied", "error", "failed"])
            )
        else:
            valid_audit["is_failure"] = False

        if "privileged_action" in valid_audit.columns:
            valid_audit["is_priv"] = valid_audit["privileged_action"].fillna(False).astype(bool)
        else:
            valid_audit["is_priv"] = False

        if "mfa_used" in valid_audit.columns:
            valid_audit["has_mfa"] = valid_audit["mfa_used"].fillna(False).astype(bool)
        else:
            valid_audit["has_mfa"] = False

        if "bytes_transferred" in valid_audit.columns:
            valid_audit["bytes"] = (
                pd.to_numeric(valid_audit["bytes_transferred"], errors="coerce")
                .fillna(0)
                .clip(lower=0)
            )
        else:
            valid_audit["bytes"] = 0.0

        audit_agg = (
            valid_audit.groupby("identity_id")
            .agg(
                total_events=("event_id", "count")
                if "event_id" in valid_audit.columns
                else ("account_id", "count"),
                off_hours_events=("is_off_hours", "sum"),
                failure_events=("is_failure", "sum"),
                priv_events=("is_priv", "sum"),
                mfa_events=("has_mfa", "sum"),
                distinct_ips=("source_ip", "nunique")
                if "source_ip" in valid_audit.columns
                else ("is_priv", "count"),
                distinct_countries=("geo_country", "nunique")
                if "geo_country" in valid_audit.columns
                else ("is_priv", "count"),
                total_bytes_transferred=("bytes", "sum"),
                max_bytes_transferred=("bytes", "max"),
                earliest_event=("timestamp", "min"),
                latest_event=("timestamp", "max"),
            )
            .reset_index()
        )

        span_days = (
            audit_agg["latest_event"] - audit_agg["earliest_event"]
        ).dt.total_seconds() / 86400.0
        active_days = np.maximum(1.0, span_days)
        audit_agg["events_per_day"] = audit_agg["total_events"] / active_days
        audit_agg["off_hours_share"] = audit_agg["off_hours_events"] / audit_agg["total_events"]
        audit_agg["failure_rate"] = audit_agg["failure_events"] / audit_agg["total_events"]
        audit_agg["privileged_action_share"] = audit_agg["priv_events"] / audit_agg["total_events"]
        audit_agg["mfa_rate"] = audit_agg["mfa_events"] / audit_agg["total_events"]
    else:
        audit_agg = pd.DataFrame(
            columns=[
                "identity_id",
                "total_events",
                "events_per_day",
                "off_hours_share",
                "distinct_ips",
                "distinct_countries",
                "max_bytes_transferred",
                "total_bytes_transferred",
                "failure_rate",
                "privileged_action_share",
                "mfa_rate",
            ]
        )

    # 4. Group memberships count per identity
    group_counts: dict[str, int] = {}
    if ad_membership_df is not None and not ad_membership_df.empty:
        mem_col = "member" if "member" in ad_membership_df.columns else "account_id"
        if mem_col in ad_membership_df.columns:
            for acc, count in ad_membership_df.groupby(mem_col).size().items():
                iid = acc_to_ident.get(str(acc))
                if iid:
                    group_counts[iid] = group_counts.get(iid, 0) + int(count)

    if aws_user_groups_df is not None and not aws_user_groups_df.empty:
        u_col = "user_id" if "user_id" in aws_user_groups_df.columns else "account_id"
        if u_col in aws_user_groups_df.columns:
            for acc, count in aws_user_groups_df.groupby(u_col).size().items():
                iid = acc_to_ident.get(str(acc))
                if iid:
                    group_counts[iid] = group_counts.get(iid, 0) + int(count)

    if okta_group_membership_df is not None and not okta_group_membership_df.empty:
        o_col = "okta_id" if "okta_id" in okta_group_membership_df.columns else "account_id"
        if o_col in okta_group_membership_df.columns:
            for acc, count in okta_group_membership_df.groupby(o_col).size().items():
                iid = acc_to_ident.get(str(acc))
                if iid:
                    group_counts[iid] = group_counts.get(iid, 0) + int(count)

    # 5. Role changes history
    role_change_ids: set[str] = set()
    if role_changes_df is not None and not role_changes_df.empty:
        emp_col = "employee_id" if "employee_id" in role_changes_df.columns else "identity_id"
        if emp_col in role_changes_df.columns:
            if "change_date" in role_changes_df.columns:
                c_dates = pd.to_datetime(role_changes_df["change_date"])
                valid_rc = role_changes_df[c_dates <= snap_dt]
            else:
                valid_rc = role_changes_df
            role_change_ids = set(valid_rc[emp_col].astype(str))

    # 6. API Tokens aggregation
    token_stats: dict[str, dict[str, Any]] = {}
    if tokens_df is not None and not tokens_df.empty:
        t_df = tokens_df.copy()
        if "created_at" in t_df.columns:
            t_df = t_df[pd.to_datetime(t_df["created_at"]) <= snap_dt]

        for _, t_row in t_df.iterrows():
            tid = str(t_row.get("identity_id", ""))
            if not tid or tid == "nan":
                acc = str(t_row.get("account_id", ""))
                tid = acc_to_ident.get(acc, "")
            if not tid:
                continue

            entry = token_stats.setdefault(tid, {"count": 0, "min_scope_tier": 9})
            entry["count"] += 1
            st = t_row.get("scope_tier")
            if pd.notna(st):
                entry["min_scope_tier"] = min(entry["min_scope_tier"], int(st))

    # 7. Department mapping from HR records
    dept_map: dict[str, str] = {}
    if hr_records_df is not None and not hr_records_df.empty:
        emp_c = "employee_id" if "employee_id" in hr_records_df.columns else "identity_id"
        dept_c = "department" if "department" in hr_records_df.columns else None
        if emp_c in hr_records_df.columns and dept_c:
            dept_map = dict(
                zip(
                    hr_records_df[emp_c].astype(str),
                    hr_records_df[dept_c].fillna("Unknown").astype(str),
                )
            )

    # 8. Assemble base records for all resolved identities
    records: list[dict[str, Any]] = []
    priv_lookup = {str(r["identity_id"]): r for _, r in privilege_df.iterrows()}
    audit_lookup = {str(r["identity_id"]): r for _, r in audit_agg.iterrows()}

    for _, row in resolved_identities.iterrows():
        iid = str(row["identity_id"])
        ikind = str(row.get("identity_kind", "human")).lower()

        # Department classification for peer grouping
        if ikind == "service":
            peer_group = "service_accounts"
        else:
            peer_group = f"dept:{dept_map.get(iid, 'Unknown')}"

        # Privilege metrics from M3
        p_row = priv_lookup.get(iid)
        eff_tier = int(p_row["overall_effective_tier"]) if p_row is not None else 3
        # Inverted tier score (Tier 0 -> 3, Tier 1 -> 2, Tier 2 -> 1, Tier 3 -> 0)
        eff_tier_score = float(max(0, 3 - eff_tier))

        # Audit activity metrics
        a_row = audit_lookup.get(iid)
        tot_evts = float(a_row["total_events"]) if a_row is not None else 0.0
        evts_day = float(a_row["events_per_day"]) if a_row is not None else 0.0
        off_hours = float(a_row["off_hours_share"]) if a_row is not None else 0.0
        dist_ips = float(a_row["distinct_ips"]) if a_row is not None else 0.0
        dist_countries = float(a_row["distinct_countries"]) if a_row is not None else 0.0
        max_bytes = float(a_row["max_bytes_transferred"]) if a_row is not None else 0.0
        tot_bytes = float(a_row["total_bytes_transferred"]) if a_row is not None else 0.0
        fail_rate = float(a_row["failure_rate"]) if a_row is not None else 0.0
        priv_share = float(a_row["privileged_action_share"]) if a_row is not None else 0.0
        mfa_r = float(a_row["mfa_rate"]) if a_row is not None else 0.0

        # Privilege utilization gap (high tier granted, but zero/low privileged actions used)
        priv_gap = eff_tier_score - (priv_share * 3.0)

        # Groups, tokens, role history
        grp_count = float(group_counts.get(iid, 0))
        rc_flag = 1.0 if iid in role_change_ids else 0.0

        t_info = token_stats.get(iid, {"count": 0, "min_scope_tier": 9})
        t_count = float(t_info["count"])
        min_st = float(max(0, 3 - t_info["min_scope_tier"])) if t_info["count"] > 0 else 0.0

        records.append(
            {
                "identity_id": iid,
                "identity_kind": ikind,
                "peer_group": peer_group,
                "total_events": tot_evts,
                "events_per_day": evts_day,
                "off_hours_share": off_hours,
                "distinct_ips": dist_ips,
                "distinct_countries": dist_countries,
                "max_bytes_transferred": max_bytes,
                "total_bytes_transferred": tot_bytes,
                "failure_rate": fail_rate,
                "privileged_action_share": priv_share,
                "mfa_rate": mfa_r,
                "total_groups_count": grp_count,
                "has_role_change": rc_flag,
                "effective_tier_score": eff_tier_score,
                "privilege_utilization_gap": priv_gap,
                "token_count": t_count,
                "min_token_scope_tier": min_st,
            }
        )

    feat_df = pd.DataFrame(records)
    if feat_df.empty:
        return feat_df, {}, {}

    # 9. Compute unlabelled peer medians and spreads (z-scores)
    peer_medians: dict[str, dict[str, float]] = {}
    peer_stds: dict[str, dict[str, float]] = {}

    numeric_cols = [
        "events_per_day",
        "off_hours_share",
        "distinct_ips",
        "distinct_countries",
        "max_bytes_transferred",
        "total_bytes_transferred",
        "failure_rate",
        "privileged_action_share",
        "total_groups_count",
        "effective_tier_score",
        "privilege_utilization_gap",
    ]

    for pg, group in feat_df.groupby("peer_group"):
        p_med = group[numeric_cols].median().to_dict()
        p_std = group[numeric_cols].std(ddof=0).fillna(1.0).to_dict()
        peer_medians[str(pg)] = p_med
        peer_stds[str(pg)] = p_std

    # Fallback overall medians for rare departments (< 3 members)
    overall_human = feat_df[feat_df["identity_kind"] == "human"]
    overall_human_med = (
        overall_human[numeric_cols].median().to_dict()
        if not overall_human.empty
        else {c: 0.0 for c in numeric_cols}
    )
    overall_human_std = (
        overall_human[numeric_cols].std(ddof=0).fillna(1.0).to_dict()
        if not overall_human.empty
        else {c: 1.0 for c in numeric_cols}
    )

    # Calculate z-scores per identity against peer baseline
    peer_z_epd: list[float] = []
    peer_z_off: list[float] = []
    peer_z_ips: list[float] = []
    peer_z_bytes: list[float] = []
    peer_z_priv: list[float] = []
    peer_z_groups: list[float] = []
    peer_z_tier: list[float] = []

    for _, r in feat_df.iterrows():
        pg = str(r["peer_group"])
        meds = peer_medians.get(pg, overall_human_med)
        stds = peer_stds.get(pg, overall_human_std)

        def _calc_z(col: str) -> float:
            m = meds.get(col, 0.0)
            s = max(1e-4, stds.get(col, 1.0))
            return float((r[col] - m) / s)

        peer_z_epd.append(_calc_z("events_per_day"))
        peer_z_off.append(_calc_z("off_hours_share"))
        peer_z_ips.append(_calc_z("distinct_ips"))
        peer_z_bytes.append(_calc_z("max_bytes_transferred"))
        peer_z_priv.append(_calc_z("privileged_action_share"))
        peer_z_groups.append(_calc_z("total_groups_count"))
        peer_z_tier.append(_calc_z("effective_tier_score"))

    feat_df["peer_events_per_day_zscore"] = peer_z_epd
    feat_df["peer_off_hours_zscore"] = peer_z_off
    feat_df["peer_distinct_ips_zscore"] = peer_z_ips
    feat_df["peer_bytes_zscore"] = peer_z_bytes
    feat_df["peer_priv_action_zscore"] = peer_z_priv
    feat_df["peer_group_count_zscore"] = peer_z_groups
    feat_df["peer_tier_zscore"] = peer_z_tier

    return feat_df, peer_medians, peer_stds
