"""Evaluation module for identity resolution (Milestone 2).

This module is the ONLY place allowed to read GT_ sheets (enforced by test_gt_isolation.py).
It maps resolution outputs to ground truth using account IDs (ad_account_id, aws_user_id, okta_id)
and computes precision, recall, and unresolved rate:
- overall
- by identity kind (human, service, orphan)
- by signal (id, email, fuzzy)
- for train, test, and holdout separately.

Definitions of correctness:
1. Human: the set of accounts linked to employee_id equals the set in ground truth.
2. Service: the account is identified as a service identity with the correct owner status.
3. Orphan: the account is correctly left unresolved.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from accessatlas.resolution.resolver import ResolutionResult, resolve_identities


@dataclass
class KindMetrics:
    """Metrics for a specific identity kind (human, service, orphan)."""

    kind: str
    total_gt: int
    tp: int
    fp: int
    fn: int
    unresolved_count: int
    precision: float
    recall: float
    unresolved_rate: float


@dataclass
class SignalMetrics:
    """Metrics for an individual matching signal (id, email, fuzzy)."""

    signal: str
    count: int
    tp: int
    fp: int
    precision: float
    recall: float


@dataclass
class EvaluationReport:
    """Complete evaluation report for a given dataset split."""

    split: str
    overall_precision: float
    overall_recall: float
    overall_unresolved_rate: float
    total_gt_identities: int
    total_gt_accounts: int
    by_kind: dict[str, KindMetrics]
    by_signal: dict[str, SignalMetrics]
    error_analysis: dict[str, Any]


def load_gt_identity_data(
    gt_dir: str | Path = "data/processed/gt",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load ground truth identity links and labels.

    Only evaluation code may call this function.
    """
    gt_path = Path(gt_dir)
    links_path = gt_path / "GT_IdentityLinks.parquet"
    labels_path = gt_path / "GT_Labels.parquet"

    if not links_path.exists():
        raise FileNotFoundError(f"GT links not found: {links_path.resolve()}")
    if not labels_path.exists():
        raise FileNotFoundError(f"GT labels not found: {labels_path.resolve()}")

    gt_links = pd.read_parquet(links_path)
    gt_labels = pd.read_parquet(labels_path)
    return gt_links, gt_labels


def _build_account_to_gt(
    gt_links: pd.DataFrame,
    gt_labels: pd.DataFrame,
    split: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Build a lookup mapping every platform account to its GT identity."""
    merged = gt_links.merge(gt_labels[["identity_id", "split"]], on="identity_id", how="left")
    if split is not None:
        merged = merged[merged["split"] == split]

    account_to_gt: dict[str, dict[str, Any]] = {}
    for _, row in merged.iterrows():
        gt_id = str(row["identity_id"])
        kind = str(row["identity_kind"])
        sp = str(row["split"])

        for col, platform in [
            ("ad_account_id", "ad"),
            ("aws_user_id", "aws"),
            ("okta_id", "okta"),
        ]:
            acc = row.get(col)
            if pd.notna(acc) and str(acc).strip():
                clean_acc = str(acc).strip()
                account_to_gt[clean_acc] = {
                    "account_id": clean_acc,
                    "platform": platform,
                    "gt_identity_id": gt_id,
                    "gt_kind": kind,
                    "split": sp,
                }
    return account_to_gt


def evaluate_identity_resolution(
    result: ResolutionResult,
    gt_links: pd.DataFrame,
    gt_labels: pd.DataFrame,
    split: str | None = None,
    core_tables: dict[str, pd.DataFrame] | None = None,
) -> EvaluationReport:
    """Evaluate resolution output against ground truth.

    Parameters
    ----------
    result : ResolutionResult
        Output of resolve_identities().
    gt_links : pd.DataFrame
        GT_IdentityLinks table.
    gt_labels : pd.DataFrame
        GT_Labels table.
    split : str | None, optional
        Filter by 'train', 'test', 'holdout', or None for overall.
    core_tables : dict[str, pd.DataFrame] | None, optional
        Core tables (HR, AD, AWS, Okta) used to derive true service owner status.

    Returns
    -------
    EvaluationReport
        Precision, recall, unresolved rates overall, by kind, and by signal.
    """
    account_to_gt = _build_account_to_gt(gt_links, gt_labels, split=split)
    gt_accounts = set(account_to_gt.keys())

    # Build GT identity-to-accounts map for the target split
    merged_gt = gt_links.merge(gt_labels[["identity_id", "split"]], on="identity_id", how="left")
    if split is not None:
        merged_gt = merged_gt[merged_gt["split"] == split]

    gt_identities_map: dict[str, dict[str, Any]] = {}
    for _, row in merged_gt.iterrows():
        gid = str(row["identity_id"])
        kind = str(row["identity_kind"])
        accs = set()
        for col in ["ad_account_id", "aws_user_id", "okta_id"]:
            val = row.get(col)
            if pd.notna(val) and str(val).strip():
                accs.add(str(val).strip())
        gt_identities_map[gid] = {
            "identity_id": gid,
            "identity_kind": kind,
            "accounts": accs,
            "split": row.get("split"),
        }

    # Derive true service owner status if core_tables provided
    true_service_owner_status: dict[str, str] = {}
    if core_tables and "HR_Records" in core_tables:
        hr_emp_ids = set(core_tables["HR_Records"]["employee_id"].astype(str).str.strip())
        for platform, p_key, col in [
            ("ad", "AD_Users", "account_id"),
            ("aws", "AWS_Users", "user_id"),
            ("okta", "Okta_Users", "okta_id"),
        ]:
            if p_key in core_tables:
                p_df = core_tables[p_key]
                svc_rows = p_df[p_df.get("account_type") == "service"]
                for _, s_row in svc_rows.iterrows():
                    acc_id = str(s_row[col]).strip()
                    owner = s_row.get("owner_employee_id")
                    if pd.isna(owner) or not str(owner).strip():
                        st = "missing"
                    elif str(owner).strip() in hr_emp_ids:
                        st = "valid"
                    else:
                        st = "invalid"
                    true_service_owner_status[acc_id] = st

    # Index resolved identities
    resolved_df = result.resolved_identities
    unresolved_df = result.unresolved_accounts

    # Account -> where was it resolved?
    resolved_account_links: dict[str, dict[str, Any]] = {}
    for _, row in resolved_df.iterrows():
        ident_id = str(row["identity_id"])
        kind = str(row["identity_kind"])
        owner_status = row.get("owner_status")

        signals_str = str(row.get("signals", ""))
        # Parse platform signals if available (e.g. ad:id;aws:fuzzy)
        platform_sig_map: dict[str, str] = {}
        for part in signals_str.split(";"):
            if ":" in part:
                p_name, sig_name = part.split(":", 1)
                platform_sig_map[p_name] = sig_name

        for col, p_name in [
            ("ad_account_id", "ad"),
            ("aws_user_id", "aws"),
            ("okta_id", "okta"),
        ]:
            val = row.get(col)
            if pd.notna(val) and str(val).strip():
                acc = str(val).strip()
                resolved_account_links[acc] = {
                    "account_id": acc,
                    "resolved_identity_id": ident_id,
                    "resolved_kind": kind,
                    "owner_status": owner_status,
                    "signal": platform_sig_map.get(p_name, signals_str),
                }

    # Index unresolved accounts
    unresolved_account_map: dict[str, dict[str, Any]] = {}
    for _, row in unresolved_df.iterrows():
        acc = str(row["account_id"]).strip()
        unresolved_account_map[acc] = {
            "account_id": acc,
            "reason": str(row.get("reason")),
            "signal": row.get("signal"),
        }

    # --- 1. Evaluate Human Accounts ---
    human_gt_accs = [
        acc_info for acc_info in account_to_gt.values() if acc_info["gt_kind"] == "human"
    ]
    human_tp = 0
    human_fp = 0
    human_fn = 0
    human_unresolved = 0

    # Also track by signal
    signal_counts: dict[str, dict[str, int]] = {
        "id": {"tp": 0, "fp": 0, "count": 0},
        "email": {"tp": 0, "fp": 0, "count": 0},
        "fuzzy": {"tp": 0, "fp": 0, "count": 0},
    }

    wrong_links_list: list[dict[str, Any]] = []

    for acc_info in human_gt_accs:
        acc = acc_info["account_id"]
        true_emp = acc_info["gt_identity_id"]

        if acc in resolved_account_links:
            link = resolved_account_links[acc]
            res_emp = link["resolved_identity_id"]
            res_kind = link["resolved_kind"]
            sig = link["signal"]

            if sig in signal_counts:
                signal_counts[sig]["count"] += 1

            if res_kind == "human" and res_emp == true_emp:
                human_tp += 1
                if sig in signal_counts:
                    signal_counts[sig]["tp"] += 1
            else:
                human_fp += 1
                human_fn += 1
                if sig in signal_counts:
                    signal_counts[sig]["fp"] += 1
                wrong_links_list.append(
                    {
                        "account_id": acc,
                        "true_emp": true_emp,
                        "resolved_emp": res_emp,
                        "signal": sig,
                        "type": "wrong_link",
                    }
                )
        else:
            # Not resolved
            human_fn += 1
            human_unresolved += 1
            unres_info = unresolved_account_map.get(acc, {})
            wrong_links_list.append(
                {
                    "account_id": acc,
                    "true_emp": true_emp,
                    "resolved_emp": None,
                    "signal": unres_info.get("signal"),
                    "reason": unres_info.get("reason", "unresolved"),
                    "type": "unresolved",
                }
            )

    human_prec = human_tp / (human_tp + human_fp) if (human_tp + human_fp) > 0 else 1.0
    human_rec = human_tp / (human_tp + human_fn) if (human_tp + human_fn) > 0 else 0.0
    human_unres_rate = human_unresolved / len(human_gt_accs) if human_gt_accs else 0.0

    # --- 2. Evaluate Service Accounts ---
    svc_gt_accs = [
        acc_info for acc_info in account_to_gt.values() if acc_info["gt_kind"] == "service"
    ]
    svc_tp = 0
    svc_fp = 0
    svc_fn = 0
    svc_unresolved = 0

    for acc_info in svc_gt_accs:
        acc = acc_info["account_id"]
        true_owner_st = true_service_owner_status.get(acc)

        if acc in resolved_account_links:
            link = resolved_account_links[acc]
            res_kind = link["resolved_kind"]
            res_owner_st = link["owner_status"]

            # Service accounts must be identified as service with matching owner_status
            matches_owner = (true_owner_st is None) or (res_owner_st == true_owner_st)
            if res_kind == "service" and matches_owner:
                svc_tp += 1
            else:
                svc_fp += 1
                svc_fn += 1
        else:
            svc_fn += 1
            svc_unresolved += 1

    svc_prec = svc_tp / (svc_tp + svc_fp) if (svc_tp + svc_fp) > 0 else 1.0
    svc_rec = svc_tp / (svc_tp + svc_fn) if (svc_tp + svc_fn) > 0 else 0.0
    svc_unres_rate = svc_unresolved / len(svc_gt_accs) if svc_gt_accs else 0.0

    # --- 3. Evaluate Orphan Accounts ---
    orph_gt_accs = [
        acc_info for acc_info in account_to_gt.values() if acc_info["gt_kind"] == "orphan"
    ]
    orph_tp = 0
    orph_fp = 0
    orph_fn = 0

    for acc_info in orph_gt_accs:
        acc = acc_info["account_id"]
        if acc in unresolved_account_map:
            # Correctly left unresolved
            orph_tp += 1
        else:
            # Incorrectly resolved!
            orph_fn += 1
            orph_fp += 1

    orph_prec = orph_tp / (orph_tp + orph_fp) if (orph_tp + orph_fp) > 0 else 1.0
    orph_rec = orph_tp / len(orph_gt_accs) if orph_gt_accs else 1.0
    orph_unres_rate = orph_tp / len(orph_gt_accs) if orph_gt_accs else 1.0

    # --- 4. Overall Metrics ---
    total_accs = len(account_to_gt)
    total_tp = human_tp + svc_tp + orph_tp
    total_fp = human_fp + svc_fp + orph_fp
    total_fn = human_fn + svc_fn + orph_fn

    overall_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    overall_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0

    # Overall unresolved rate: fraction of accounts left unresolved
    unresolved_in_split = sum(1 for acc in gt_accounts if acc in unresolved_account_map)
    overall_unres_rate = unresolved_in_split / total_accs if total_accs > 0 else 0.0

    # Signal metrics structure
    by_signal: dict[str, SignalMetrics] = {}
    for sig_name, counts in signal_counts.items():
        c = counts["count"]
        tp = counts["tp"]
        fp = counts["fp"]
        p = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        r = tp / c if c > 0 else 0.0
        by_signal[sig_name] = SignalMetrics(
            signal=sig_name,
            count=c,
            tp=tp,
            fp=fp,
            precision=round(p, 4),
            recall=round(r, 4),
        )

    by_kind = {
        "human": KindMetrics(
            kind="human",
            total_gt=len(human_gt_accs),
            tp=human_tp,
            fp=human_fp,
            fn=human_fn,
            unresolved_count=human_unresolved,
            precision=round(human_prec, 4),
            recall=round(human_rec, 4),
            unresolved_rate=round(human_unres_rate, 4),
        ),
        "service": KindMetrics(
            kind="service",
            total_gt=len(svc_gt_accs),
            tp=svc_tp,
            fp=svc_fp,
            fn=svc_fn,
            unresolved_count=svc_unresolved,
            precision=round(svc_prec, 4),
            recall=round(svc_rec, 4),
            unresolved_rate=round(svc_unres_rate, 4),
        ),
        "orphan": KindMetrics(
            kind="orphan",
            total_gt=len(orph_gt_accs),
            tp=orph_tp,
            fp=orph_fp,
            fn=orph_fn,
            unresolved_count=orph_tp,
            precision=round(orph_prec, 4),
            recall=round(orph_rec, 4),
            unresolved_rate=round(orph_unres_rate, 4),
        ),
    }

    # Error analysis breakdown
    error_reasons: dict[str, int] = {}
    error_signals: dict[str, int] = {}
    for err in wrong_links_list:
        reason = err.get("reason") or err.get("type", "unknown")
        error_reasons[reason] = error_reasons.get(reason, 0) + 1
        sig = err.get("signal") or "none"
        error_signals[sig] = error_signals.get(sig, 0) + 1

    error_analysis = {
        "total_errors": len(wrong_links_list),
        "by_reason": error_reasons,
        "by_signal": error_signals,
        "sample_errors": wrong_links_list[:10],
    }

    return EvaluationReport(
        split=split or "all",
        overall_precision=round(overall_prec, 4),
        overall_recall=round(overall_rec, 4),
        overall_unresolved_rate=round(overall_unres_rate, 4),
        total_gt_identities=len(gt_identities_map),
        total_gt_accounts=total_accs,
        by_kind=by_kind,
        by_signal=by_signal,
        error_analysis=error_analysis,
    )


def tune_fuzzy_threshold(
    hr_df: pd.DataFrame,
    ad_df: pd.DataFrame,
    aws_df: pd.DataFrame,
    okta_df: pd.DataFrame,
    gt_links: pd.DataFrame,
    gt_labels: pd.DataFrame,
    thresholds: list[float] | None = None,
) -> tuple[pd.DataFrame, float, dict[str, Any]]:
    """Sweep candidate fuzzy thresholds on the TRAIN split only.

    Parameters
    ----------
    thresholds : list[float] | None
        List of candidate thresholds to test (e.g. 70 to 95).

    Returns
    -------
    tuple[pd.DataFrame, float, dict[str, Any]]
        - Sweep table DataFrame (threshold, precision, recall, f1, unresolved_rate, etc.)
        - Selected threshold (maximizing F1 on train)
        - Train signal count and error analysis
    """
    if thresholds is None:
        thresholds = [70.0, 75.0, 80.0, 82.0, 84.0, 85.0, 86.0, 88.0, 90.0, 92.0, 95.0]

    core_tables = {
        "HR_Records": hr_df,
        "AD_Users": ad_df,
        "AWS_Users": aws_df,
        "Okta_Users": okta_df,
    }

    sweep_records = []
    best_f1 = -1.0
    best_threshold = 85.0
    train_error_analysis: dict[str, Any] = {}

    for t in thresholds:
        res = resolve_identities(
            hr_df,
            ad_df,
            aws_df,
            okta_df,
            fuzzy_threshold=t,
        )
        report = evaluate_identity_resolution(
            res,
            gt_links,
            gt_labels,
            split="train",
            core_tables=core_tables,
        )

        p = report.overall_precision
        r = report.overall_recall
        f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

        fuzzy_metrics = report.by_signal.get("fuzzy")
        fuzzy_p = fuzzy_metrics.precision if fuzzy_metrics else 1.0
        fuzzy_r = fuzzy_metrics.recall if fuzzy_metrics else 0.0

        sweep_records.append(
            {
                "threshold": t,
                "overall_precision": p,
                "overall_recall": r,
                "overall_f1": round(f1, 4),
                "unresolved_rate": report.overall_unresolved_rate,
                "fuzzy_count": fuzzy_metrics.count if fuzzy_metrics else 0,
                "fuzzy_precision": fuzzy_p,
                "fuzzy_recall": fuzzy_r,
            }
        )

        if f1 > best_f1:
            best_f1 = f1
            best_threshold = t
            train_error_analysis = report.error_analysis

    sweep_df = pd.DataFrame(sweep_records)
    return sweep_df, best_threshold, train_error_analysis


def count_train_fuzzy_candidates(aws_df: pd.DataFrame, gt_dir: Path | None = None) -> int:
    """Count how many AWS human accounts reach the fuzzy matching stage on train."""
    g_dir = gt_dir or Path("data/processed/gt")
    gt_links, gt_labels = load_gt_identity_data(g_dir)
    aws_train_gt = gt_links.merge(gt_labels[["identity_id", "split"]], on="identity_id", how="left")
    aws_train_ids = set(aws_train_gt[aws_train_gt["split"] == "train"]["aws_user_id"].dropna())
    aws_train_human_no_tags = aws_df[
        aws_df["user_id"].isin(aws_train_ids)
        & (aws_df["account_type"] == "human")
        & aws_df["tag_employee_id"].isna()
        & aws_df["tag_email"].isna()
    ]
    return len(aws_train_human_no_tags)


def evaluate_resolution_for_split(
    res: ResolutionResult,
    split: str,
    core_tables: dict[str, pd.DataFrame] | None = None,
    gt_dir: Path | None = None,
) -> EvaluationReport:
    """Evaluate resolution result for a specific split using GT data directly inside evaluation package."""
    g_dir = gt_dir or Path("data/processed/gt")
    gt_links, gt_labels = load_gt_identity_data(g_dir)
    return evaluate_identity_resolution(
        res, gt_links, gt_labels, split=split, core_tables=core_tables
    )


def tune_fuzzy_threshold_pipeline(
    hr_df: pd.DataFrame,
    ad_df: pd.DataFrame,
    aws_df: pd.DataFrame,
    okta_df: pd.DataFrame,
    thresholds: list[float] | None = None,
    gt_dir: Path | None = None,
) -> tuple[pd.DataFrame, float, dict[str, Any]]:
    """Tune fuzzy threshold across train identities using GT data directly inside evaluation package."""
    g_dir = gt_dir or Path("data/processed/gt")
    gt_links, gt_labels = load_gt_identity_data(g_dir)
    return tune_fuzzy_threshold(
        hr_df=hr_df,
        ad_df=ad_df,
        aws_df=aws_df,
        okta_df=okta_df,
        gt_links=gt_links,
        gt_labels=gt_labels,
        thresholds=thresholds,
    )
