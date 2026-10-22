"""Identity resolution orchestrator.

This module resolves accounts from Active Directory (AD), AWS IAM, and Okta
to canonical HR identities, producing:
1. `resolved_identities`: Canonical human and service identity records.
2. `unresolved_accounts`: Orphan accounts, conflicting accounts, and low-confidence
   matches kept for downstream rule analysis.

WHY:
- In identity governance, unlinked accounts are critical audit findings rather than junk
  to discard. Keeping an explicit unresolved_accounts table ensures later rules
  (e.g., orphan detection, offboarded access) have complete visibility.
- Service accounts represent non-human system identities and must remain distinct from
  their human owners while tracking whether their owner_employee_id is valid, missing,
  or invalid.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from accessatlas.resolution.matcher import (
    AccountResolution,
    build_hr_index,
    match_account,
)
from accessatlas.utils import load_config


@dataclass
class ResolutionResult:
    """The complete result of running identity resolution."""

    resolved_identities: pd.DataFrame
    unresolved_accounts: pd.DataFrame
    summary: dict[str, Any]


def _extract_ad_fields(row: pd.Series) -> dict[str, Any]:
    """Extract matching fields from an AD_Users record."""
    return {
        "account_id": str(row["account_id"]),
        "account_type": str(row.get("account_type", "human")),
        "raw_id": row.get("employee_id"),
        "raw_email": row.get("mail") or row.get("user_principal_name"),
        "raw_username": row.get("sam_account_name"),
        "raw_display_name": row.get("display_name"),
        "owner_employee_id": row.get("owner_employee_id"),
    }


def _extract_aws_fields(row: pd.Series) -> dict[str, Any]:
    """Extract matching fields from an AWS_Users record."""
    return {
        "account_id": str(row["user_id"]),
        "account_type": str(row.get("account_type", "human")),
        "raw_id": row.get("tag_employee_id"),
        "raw_email": row.get("tag_email"),
        "raw_username": row.get("user_name"),
        "raw_display_name": None,
        "owner_employee_id": row.get("owner_employee_id"),
    }


def _extract_okta_fields(row: pd.Series) -> dict[str, Any]:
    """Extract matching fields from an Okta_Users record."""
    fn = str(row.get("first_name", "")).strip() if pd.notna(row.get("first_name")) else ""
    ln = str(row.get("last_name", "")).strip() if pd.notna(row.get("last_name")) else ""
    display_name = f"{fn} {ln}".strip() or None

    return {
        "account_id": str(row["okta_id"]),
        "account_type": str(row.get("account_type", "human")),
        "raw_id": row.get("employee_number"),
        "raw_email": row.get("email") or row.get("login"),
        "raw_username": row.get("login"),
        "raw_display_name": display_name,
        "owner_employee_id": row.get("owner_employee_id"),
    }


def resolve_identities(
    hr_df: pd.DataFrame,
    ad_df: pd.DataFrame,
    aws_df: pd.DataFrame,
    okta_df: pd.DataFrame,
    fuzzy_threshold: float | None = None,
    config_path: str | Path = "config.yaml",
) -> ResolutionResult:
    """Resolve accounts across AD, AWS, and Okta into canonical identities.

    Parameters
    ----------
    hr_df : pd.DataFrame
        HR employee records (source of truth).
    ad_df : pd.DataFrame
        Active Directory accounts.
    aws_df : pd.DataFrame
        AWS IAM accounts.
    okta_df : pd.DataFrame
        Okta accounts.
    fuzzy_threshold : float | None, optional
        RapidFuzz score threshold (0-100). If None, loads from config.yaml.
    config_path : str | Path, optional
        Path to config.yaml.

    Returns
    -------
    ResolutionResult
        Contains resolved_identities DataFrame, unresolved_accounts DataFrame,
        and execution summary.
    """
    ambiguity_margin = 3.0
    try:
        cfg = load_config(config_path)
        if fuzzy_threshold is None:
            fuzzy_threshold = float(cfg.get("resolution", {}).get("fuzzy_threshold", 85.0))
        ambiguity_margin = float(cfg.get("resolution", {}).get("ambiguity_margin", 3.0))
    except Exception:
        if fuzzy_threshold is None:
            fuzzy_threshold = 85.0

    hr_index = build_hr_index(hr_df)
    hr_emp_ids = set(hr_index["id_to_emp"].keys())

    resolved_rows: list[dict[str, Any]] = []
    unresolved_rows: list[dict[str, Any]] = []

    # Map from employee_id -> platform -> AccountResolution
    human_links: dict[str, dict[str, AccountResolution]] = {
        emp_id: {} for emp_id in hr_index["id_to_emp"]
    }

    platforms_data = [
        ("ad", ad_df, _extract_ad_fields, "ad_account_id"),
        ("aws", aws_df, _extract_aws_fields, "aws_user_id"),
        ("okta", okta_df, _extract_okta_fields, "okta_id"),
    ]

    for platform_name, df, extract_fn, platform_key in platforms_data:
        # Track accounts assigned to employees on this platform to detect collisions
        claimed_employees: dict[str, list[AccountResolution]] = {}

        for _, row in df.iterrows():
            fields = extract_fn(row)
            account_id = fields["account_id"]
            account_type = fields["account_type"]
            owner_emp_id = fields["owner_employee_id"]

            # --- 1. Service Accounts ---
            if account_type == "service":
                # Determine owner status
                if pd.isna(owner_emp_id) or not str(owner_emp_id).strip():
                    owner_status = "missing"
                    clean_owner_id = None
                elif str(owner_emp_id).strip() in hr_emp_ids:
                    owner_status = "valid"
                    clean_owner_id = str(owner_emp_id).strip()
                else:
                    owner_status = "invalid"
                    clean_owner_id = str(owner_emp_id).strip()

                service_id = f"svc:{platform_name}:{account_id}"
                resolved_rows.append(
                    {
                        "identity_id": service_id,
                        "identity_kind": "service",
                        "ad_account_id": account_id if platform_name == "ad" else None,
                        "aws_user_id": account_id if platform_name == "aws" else None,
                        "okta_id": account_id if platform_name == "okta" else None,
                        "owner_employee_id": clean_owner_id,
                        "owner_status": owner_status,
                        "confidence": 1.0,
                        "signals": "service_tag",
                    }
                )
                continue

            # --- 2. Orphan Accounts ---
            if account_type == "orphan":
                unresolved_rows.append(
                    {
                        "platform": platform_name,
                        "account_id": account_id,
                        "account_type": "orphan",
                        "reason": "orphan_account",
                        "candidate_employee_id": None,
                        "confidence": None,
                        "signal": None,
                        "detail": "Account is tagged as orphan; no HR record exists",
                    }
                )
                continue

            # --- 3. Human Accounts ---
            res = match_account(
                platform=platform_name,
                account_id=account_id,
                account_type=account_type,
                raw_id=fields["raw_id"],
                raw_email=fields["raw_email"],
                raw_username=fields["raw_username"],
                raw_display_name=fields["raw_display_name"],
                hr_index=hr_index,
                fuzzy_threshold=fuzzy_threshold,
                ambiguity_margin=ambiguity_margin,
            )

            if not res.is_resolved:
                unresolved_rows.append(
                    {
                        "platform": platform_name,
                        "account_id": account_id,
                        "account_type": account_type,
                        "reason": res.unresolved_reason,
                        "candidate_employee_id": res.employee_id,
                        "confidence": res.confidence,
                        "signal": res.signal,
                        "detail": res.detail,
                    }
                )
            else:
                emp_id = res.employee_id
                assert emp_id is not None
                if emp_id not in claimed_employees:
                    claimed_employees[emp_id] = []
                claimed_employees[emp_id].append(res)

        # Handle any collision on this platform (two accounts claiming same employee_id)
        for emp_id, matches in claimed_employees.items():
            if len(matches) == 1:
                human_links[emp_id][platform_name] = matches[0]
            else:
                # Sort descending by confidence
                matches.sort(key=lambda m: m.confidence or 0.0, reverse=True)
                winner = matches[0]
                runner_up = matches[1]
                if (winner.confidence or 0.0) > (runner_up.confidence or 0.0):
                    human_links[emp_id][platform_name] = winner
                    for loser in matches[1:]:
                        unresolved_rows.append(
                            {
                                "platform": platform_name,
                                "account_id": loser.account_id,
                                "account_type": loser.account_type,
                                "reason": "signal_conflict",
                                "candidate_employee_id": emp_id,
                                "confidence": loser.confidence,
                                "signal": loser.signal,
                                "detail": (
                                    f"Account collided with {winner.account_id} for "
                                    f"employee {emp_id}; lower confidence"
                                ),
                            }
                        )
                else:
                    # Tied collision: do not guess; route all tied matches to unresolved
                    for tied in matches:
                        unresolved_rows.append(
                            {
                                "platform": platform_name,
                                "account_id": tied.account_id,
                                "account_type": tied.account_type,
                                "reason": "signal_conflict",
                                "candidate_employee_id": emp_id,
                                "confidence": tied.confidence,
                                "signal": tied.signal,
                                "detail": (
                                    f"Ambiguous collision: multiple accounts on {platform_name} "
                                    f"tied for employee {emp_id}"
                                ),
                            }
                        )

    # Assemble human resolved identities
    for emp_id, links in human_links.items():
        ad_match = links.get("ad")
        aws_match = links.get("aws")
        okta_match = links.get("okta")

        matched_signals: list[str] = []
        confidences: list[float] = []

        if ad_match:
            matched_signals.append(f"ad:{ad_match.signal}")
            if ad_match.confidence:
                confidences.append(ad_match.confidence)
        if aws_match:
            matched_signals.append(f"aws:{aws_match.signal}")
            if aws_match.confidence:
                confidences.append(aws_match.confidence)
        if okta_match:
            matched_signals.append(f"okta:{okta_match.signal}")
            if okta_match.confidence:
                confidences.append(okta_match.confidence)

        avg_conf = sum(confidences) / len(confidences) if confidences else 1.0

        resolved_rows.append(
            {
                "identity_id": emp_id,
                "identity_kind": "human",
                "ad_account_id": ad_match.account_id if ad_match else None,
                "aws_user_id": aws_match.account_id if aws_match else None,
                "okta_id": okta_match.account_id if okta_match else None,
                "owner_employee_id": None,
                "owner_status": None,
                "confidence": round(avg_conf, 4),
                "signals": ";".join(matched_signals) if matched_signals else "hr_only",
            }
        )

    resolved_df = pd.DataFrame(resolved_rows)
    unresolved_df = pd.DataFrame(
        unresolved_rows,
        columns=[
            "platform",
            "account_id",
            "account_type",
            "reason",
            "candidate_employee_id",
            "confidence",
            "signal",
            "detail",
        ],
    )

    summary = {
        "total_resolved": len(resolved_df),
        "total_unresolved": len(unresolved_df),
        "human_resolved": int((resolved_df["identity_kind"] == "human").sum()),
        "service_resolved": int((resolved_df["identity_kind"] == "service").sum()),
        "unresolved_by_reason": unresolved_df["reason"].value_counts().to_dict(),
        "unresolved_by_platform": unresolved_df["platform"].value_counts().to_dict(),
        "fuzzy_threshold_used": fuzzy_threshold,
    }

    return ResolutionResult(
        resolved_identities=resolved_df,
        unresolved_accounts=unresolved_df,
        summary=summary,
    )
