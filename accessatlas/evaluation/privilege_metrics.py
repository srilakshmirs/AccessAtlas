"""Evaluation module for privilege graph and effective entitlements (Milestone 3).

This module is part of the evaluation subpackage (the ONLY place allowed to read
GT_ sheets, enforced by tests/test_gt_isolation.py).

Computes:
1. Tier accuracy against GT_EffectivePrivilege:
   - ad_effective_tier
   - aws_effective_tier
   - okta_tier
   - overall_effective_tier
2. Hidden-escalation metrics:
   - Confusion matrix (TP, FP, TN, FN)
   - Precision and Recall with raw counts
3. Path correctness:
   - For AD and federation: compares granting group or role names.
   - For AWS: scores the tier only (path is always "AWS: direct/group policy").
4. Breakdown by identity kind (human, service, orphan) and split (train, test, holdout).
5. Error categorization with counts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from accessatlas.graph.builder import build_privilege_graph
from accessatlas.graph.privilege import compute_identity_privileges
from accessatlas.resolution.resolver import resolve_identities


@dataclass
class TierAccuracy:
    """Accuracy metrics for privilege tier calculations."""

    ad_acc: float
    aws_acc: float
    okta_acc: float
    overall_acc: float
    total: int
    ad_correct: int
    aws_correct: int
    okta_correct: int
    overall_correct: int


@dataclass
class EscalationMetrics:
    """Confusion matrix, precision, and recall for hidden escalation."""

    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    accuracy: float


@dataclass
class PathAccuracy:
    """Path correctness statistics."""

    overall_correct: int
    overall_total: int
    overall_acc: float
    privileged_correct: int
    privileged_total: int
    privileged_acc: float


@dataclass
class KindPrivilegeMetrics:
    """Privilege and escalation metrics for a specific identity kind."""

    kind: str
    total: int
    ad_acc: float
    aws_acc: float
    okta_acc: float
    overall_acc: float
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float


@dataclass
class PrivilegeEvaluationReport:
    """Complete privilege evaluation report for a dataset split."""

    split: str
    total_identities: int
    tier_accuracy: TierAccuracy
    escalation_metrics: EscalationMetrics
    path_accuracy: PathAccuracy
    by_kind: dict[str, KindPrivilegeMetrics]
    error_breakdown: dict[str, int]


def load_gt_privilege_data(
    gt_dir: str | Path = "data/processed/gt",
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load ground truth privilege, link, and label tables.

    Only evaluation code may call this function.
    """
    gt_path = Path(gt_dir)
    priv_path = gt_path / "GT_EffectivePrivilege.parquet"
    links_path = gt_path / "GT_IdentityLinks.parquet"
    labels_path = gt_path / "GT_Labels.parquet"

    for p in [priv_path, links_path, labels_path]:
        if not p.exists():
            raise FileNotFoundError(f"GT file not found: {p.resolve()}")

    priv_df = pd.read_parquet(priv_path)
    links_df = pd.read_parquet(links_path)
    labels_df = pd.read_parquet(labels_path)
    return priv_df, links_df, labels_df


def extract_granting_entity(path: str | None) -> str:
    """Extract the terminal granting group or role name from a grant path.

    - For AD: returns the final group in the chain (e.g. "Domain Admins").
    - For federation: returns the AWS role name (e.g. "AdministratorAccess").
    - For AWS direct/group policy: returns the raw label.
    - For Okta: returns the raw label.
    """
    if not isinstance(path, str) or not path:
        return ""
    if path.startswith("AD:"):
        return path.split("->")[-1].replace("AD:", "").strip()
    if "(federation)" in path:
        return path.split("->")[-1].replace("(federation)", "").replace("AWS role", "").strip()
    return path.strip()


def evaluate_privilege_resolution(
    pred_df: pd.DataFrame,
    gt_dir: str | Path = "data/processed/gt",
    split: str = "train",
) -> PrivilegeEvaluationReport:
    """Evaluate predicted privilege entitlements against GT_EffectivePrivilege.

    Parameters
    ----------
    pred_df : pd.DataFrame
        Predicted identity privilege DataFrame from compute_identity_privileges.
    gt_dir : str | Path, optional
        Path to processed GT directory.
    split : str, optional
        Dataset split: 'train', 'test', 'holdout', or 'all'.

    Returns
    -------
    PrivilegeEvaluationReport
        Structured evaluation metrics.
    """
    gt_priv, gt_links, gt_labels = load_gt_privilege_data(gt_dir)

    # Filter GT to the requested split
    if split != "all":
        valid_ids = set(gt_labels[gt_labels["split"] == split]["identity_id"])
    else:
        valid_ids = set(gt_labels["identity_id"])

    # Build account_id -> GT identity_id mapping
    acc_to_gt: dict[str, str] = {}
    for _, row in gt_links.iterrows():
        iid = str(row["identity_id"])
        for col in ["ad_account_id", "aws_user_id", "okta_id"]:
            val = row.get(col)
            if pd.notna(val) and val:
                acc_to_gt[str(val)] = iid

    # Map predicted rows to GT identity_ids
    mapped_rows: list[dict[str, Any]] = []
    for _, row in pred_df.iterrows():
        pid = str(row["identity_id"])
        kind = str(row["identity_kind"])

        if kind == "human":
            gt_id = pid
        else:
            acc_id = pid.split(":")[-1]
            gt_id = acc_to_gt.get(acc_id, pid)

        if gt_id in valid_ids:
            r = row.to_dict()
            r["gt_identity_id"] = gt_id
            mapped_rows.append(r)

    mapped_df = (
        pd.DataFrame(mapped_rows)
        .drop_duplicates(subset=["gt_identity_id"])
        .set_index("gt_identity_id")
    )
    target_gt = gt_priv[gt_priv["identity_id"].isin(valid_ids)].set_index("identity_id")

    # Align indexes
    common_idx = [i for i in target_gt.index if i in mapped_df.index]
    sub_pred = mapped_df.loc[common_idx]
    sub_gt = target_gt.loc[common_idx]
    total = len(common_idx)

    # 1. Tier accuracies
    ad_corr = int((sub_pred["ad_effective_tier"] == sub_gt["ad_effective_tier"]).sum())
    aws_corr = int((sub_pred["aws_effective_tier"] == sub_gt["aws_effective_tier"]).sum())
    okta_corr = int((sub_pred["okta_tier"] == sub_gt["okta_tier"]).sum())
    overall_corr = int(
        (sub_pred["overall_effective_tier"] == sub_gt["overall_effective_tier"]).sum()
    )

    tier_acc = TierAccuracy(
        ad_acc=ad_corr / total if total > 0 else 0.0,
        aws_acc=aws_corr / total if total > 0 else 0.0,
        okta_acc=okta_corr / total if total > 0 else 0.0,
        overall_acc=overall_corr / total if total > 0 else 0.0,
        total=total,
        ad_correct=ad_corr,
        aws_correct=aws_corr,
        okta_correct=okta_corr,
        overall_correct=overall_corr,
    )

    # 2. Hidden escalation
    p_esc = sub_pred["hidden_escalation"].astype(int)
    g_esc = sub_gt["hidden_escalation"].astype(int)

    tp = int(((p_esc == 1) & (g_esc == 1)).sum())
    fp = int(((p_esc == 1) & (g_esc == 0)).sum())
    tn = int(((p_esc == 0) & (g_esc == 0)).sum())
    fn = int(((p_esc == 0) & (g_esc == 1)).sum())

    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    esc_acc = (tp + tn) / total if total > 0 else 0.0

    escalation_metrics = EscalationMetrics(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=prec,
        recall=rec,
        f1=f1,
        accuracy=esc_acc,
    )

    # 3. Path accuracy and error categories
    path_corr = 0
    priv_path_corr = 0
    priv_total = 0

    error_breakdown = {
        "tier_mismatch_ad": 0,
        "tier_mismatch_aws": 0,
        "tier_mismatch_okta": 0,
        "path_granting_entity_mismatch": 0,
        "hidden_escalation_fp": fp,
        "hidden_escalation_fn": fn,
    }

    for iid in common_idx:
        p_path = sub_pred.loc[iid, "grant_path"]
        g_path = sub_gt.loc[iid, "grant_path"]
        g_tier = sub_gt.loc[iid, "overall_effective_tier"]
        p_tier = sub_pred.loc[iid, "overall_effective_tier"]

        # Track tier mismatches
        if sub_pred.loc[iid, "ad_effective_tier"] != sub_gt.loc[iid, "ad_effective_tier"]:
            error_breakdown["tier_mismatch_ad"] += 1
        if sub_pred.loc[iid, "aws_effective_tier"] != sub_gt.loc[iid, "aws_effective_tier"]:
            error_breakdown["tier_mismatch_aws"] += 1
        if sub_pred.loc[iid, "okta_tier"] != sub_gt.loc[iid, "okta_tier"]:
            error_breakdown["tier_mismatch_okta"] += 1

        # Path scoring rule:
        # AWS direct/group policy: score tier only
        # AD and federation: compare granting entity name
        is_path_correct = False
        if g_path == "AWS: direct/group policy":
            is_path_correct = bool(p_tier == g_tier)
        else:
            g_ent = extract_granting_entity(g_path)
            p_ent = extract_granting_entity(p_path)
            is_path_correct = bool(g_ent == p_ent and p_tier == g_tier)

        if is_path_correct:
            path_corr += 1
        else:
            error_breakdown["path_granting_entity_mismatch"] += 1

        if g_tier <= 2:
            priv_total += 1
            if is_path_correct:
                priv_path_corr += 1

    path_accuracy = PathAccuracy(
        overall_correct=path_corr,
        overall_total=total,
        overall_acc=path_corr / total if total > 0 else 0.0,
        privileged_correct=priv_path_corr,
        privileged_total=priv_total,
        privileged_acc=priv_path_corr / priv_total if priv_total > 0 else 0.0,
    )

    # 4. Metrics by identity kind
    by_kind: dict[str, KindPrivilegeMetrics] = {}
    for kind in ["human", "service", "orphan"]:
        kind_pred = sub_pred[sub_pred["identity_kind"] == kind]
        if kind_pred.empty:
            continue
        k_gt = sub_gt.loc[kind_pred.index]
        k_tot = len(kind_pred)

        k_ad = int((kind_pred["ad_effective_tier"] == k_gt["ad_effective_tier"]).sum())
        k_aws = int((kind_pred["aws_effective_tier"] == k_gt["aws_effective_tier"]).sum())
        k_okta = int((kind_pred["okta_tier"] == k_gt["okta_tier"]).sum())
        k_ov = int((kind_pred["overall_effective_tier"] == k_gt["overall_effective_tier"]).sum())

        k_tp = int(((kind_pred["hidden_escalation"] == 1) & (k_gt["hidden_escalation"] == 1)).sum())
        k_fp = int(((kind_pred["hidden_escalation"] == 1) & (k_gt["hidden_escalation"] == 0)).sum())
        k_tn = int(((kind_pred["hidden_escalation"] == 0) & (k_gt["hidden_escalation"] == 0)).sum())
        k_fn = int(((kind_pred["hidden_escalation"] == 0) & (k_gt["hidden_escalation"] == 1)).sum())

        k_prec = k_tp / (k_tp + k_fp) if (k_tp + k_fp) > 0 else 0.0
        k_rec = k_tp / (k_tp + k_fn) if (k_tp + k_fn) > 0 else 0.0

        by_kind[kind] = KindPrivilegeMetrics(
            kind=kind,
            total=k_tot,
            ad_acc=k_ad / k_tot if k_tot > 0 else 0.0,
            aws_acc=k_aws / k_tot if k_tot > 0 else 0.0,
            okta_acc=k_okta / k_tot if k_tot > 0 else 0.0,
            overall_acc=k_ov / k_tot if k_tot > 0 else 0.0,
            tp=k_tp,
            fp=k_fp,
            tn=k_tn,
            fn=k_fn,
            precision=k_prec,
            recall=k_rec,
        )

    return PrivilegeEvaluationReport(
        split=split,
        total_identities=total,
        tier_accuracy=tier_acc,
        escalation_metrics=escalation_metrics,
        path_accuracy=path_accuracy,
        by_kind=by_kind,
        error_breakdown=error_breakdown,
    )


def run_full_privilege_evaluation(
    data_dir: str | Path = "data/processed",
    gt_dir: str | Path = "data/processed/gt",
    splits: list[str] | None = None,
) -> dict[str, PrivilegeEvaluationReport]:
    """Execute the end-to-end privilege evaluation pipeline across specified splits.

    Loads core data, constructs the privilege graph, runs identity resolution,
    computes effective entitlements, and evaluates accuracy against GT_EffectivePrivilege.

    Parameters
    ----------
    data_dir : str | Path, optional
        Path to processed dataset directory.
    gt_dir : str | Path, optional
        Path to ground truth directory.
    splits : list[str] | None, optional
        Splits to evaluate. Defaults to ['train', 'test', 'holdout'].

    Returns
    -------
    dict[str, PrivilegeEvaluationReport]
        Evaluation reports keyed by split name.
    """
    if splits is None:
        splits = ["train", "test", "holdout"]

    d_path = Path(data_dir)
    core_path = d_path / "core" if (d_path / "core").exists() else d_path

    # Load core tables
    hr_df = pd.read_parquet(core_path / "HR_Records.parquet")
    ad_users_df = pd.read_parquet(core_path / "AD_Users.parquet")
    aws_users_df = pd.read_parquet(core_path / "AWS_Users.parquet")
    okta_users_df = pd.read_parquet(core_path / "Okta_Users.parquet")

    ad_groups_df = pd.read_parquet(core_path / "AD_Groups.parquet")
    ad_membership_df = pd.read_parquet(core_path / "AD_GroupMembership.parquet")
    aws_groups_df = pd.read_parquet(core_path / "AWS_Groups.parquet")
    aws_policies_df = pd.read_parquet(core_path / "AWS_Policies.parquet")
    aws_user_groups_df = pd.read_parquet(core_path / "AWS_UserGroups.parquet")
    aws_policy_attach_df = pd.read_parquet(core_path / "AWS_PolicyAttach.parquet")
    okta_admin_roles_df = pd.read_parquet(core_path / "Okta_AdminRoles.parquet")
    okta_group_membership_df = pd.read_parquet(core_path / "Okta_GroupMembership.parquet")
    okta_aws_federation_df = pd.read_parquet(core_path / "Okta_AWS_Federation.parquet")
    tier_mapping_df = pd.read_parquet(core_path / "Tier_Mapping.parquet")

    # 1. Build unified graph
    graph = build_privilege_graph(
        ad_groups_df=ad_groups_df,
        ad_membership_df=ad_membership_df,
        aws_groups_df=aws_groups_df,
        aws_policies_df=aws_policies_df,
        aws_user_groups_df=aws_user_groups_df,
        aws_policy_attach_df=aws_policy_attach_df,
        okta_admin_roles_df=okta_admin_roles_df,
        okta_group_membership_df=okta_group_membership_df,
        okta_aws_federation_df=okta_aws_federation_df,
        tier_mapping_df=tier_mapping_df,
        ad_users_df=ad_users_df,
        aws_users_df=aws_users_df,
        okta_users_df=okta_users_df,
    )

    # 2. Resolve identities via Milestone 2
    res = resolve_identities(
        hr_df=hr_df,
        ad_df=ad_users_df,
        aws_df=aws_users_df,
        okta_df=okta_users_df,
    )

    # 3. Compute effective privileges
    pred_df = compute_identity_privileges(
        graph=graph,
        resolved_identities=res.resolved_identities,
        unresolved_accounts=res.unresolved_accounts,
    )

    # 4. Evaluate per split
    reports: dict[str, PrivilegeEvaluationReport] = {}
    for sp in splits:
        reports[sp] = evaluate_privilege_resolution(
            pred_df=pred_df,
            gt_dir=gt_dir,
            split=sp,
        )

    return reports
