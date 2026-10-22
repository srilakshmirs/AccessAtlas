"""Tests for Milestone 3 privilege evaluation metrics.

Covers:
- Granting entity extraction from AD and federation paths
- Ground truth loading from fixture directory
- Synthetic privilege evaluation metric verification (precision, recall, tier accuracy)
- End-to-end evaluation on committed fixture data
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from accessatlas.evaluation.privilege_metrics import (
    evaluate_privilege_resolution,
    extract_granting_entity,
    load_gt_privilege_data,
    run_full_privilege_evaluation,
)


def test_extract_granting_entity() -> None:
    """Extract terminal granting entity name across AD, federation, AWS, and Okta paths."""
    assert extract_granting_entity("AD: GRP-VPN-Users") == "GRP-VPN-Users"
    assert extract_granting_entity("AD: IT-Ops -> Server-Admins") == "Server-Admins"
    assert (
        extract_granting_entity(
            "AD: Contractor-Support -> Vendor-Mgmt -> Legacy-Apps-Admins -> Domain Admins"
        )
        == "Domain Admins"
    )
    assert (
        extract_granting_entity(
            "Okta group okta-aws-admins -> AWS role AdministratorAccess (federation)"
        )
        == "AdministratorAccess"
    )
    assert (
        extract_granting_entity("Okta group okta-aws-dev -> AWS role PowerUserAccess (federation)")
        == "PowerUserAccess"
    )
    assert extract_granting_entity("AWS: direct/group policy") == "AWS: direct/group policy"
    assert extract_granting_entity("Okta: admin role") == "Okta: admin role"
    assert extract_granting_entity("") == ""
    assert extract_granting_entity(None) == ""


def test_load_gt_privilege_data(fixture_dir: Path) -> None:
    """Test loading ground truth privilege fixtures."""
    gt_dir = fixture_dir / "gt"
    priv_df, links_df, labels_df = load_gt_privilege_data(gt_dir)

    assert not priv_df.empty
    assert not links_df.empty
    assert not labels_df.empty

    assert "overall_effective_tier" in priv_df.columns
    assert "hidden_escalation" in priv_df.columns
    assert "grant_path" in priv_df.columns
    assert "identity_id" in links_df.columns
    assert "split" in labels_df.columns


def test_evaluate_privilege_resolution_synthetic(tmp_path: Path) -> None:
    """Test privilege evaluation metrics on synthetic data with known ground truth."""
    gt_dir = tmp_path / "gt"
    gt_dir.mkdir(parents=True)

    # 4 identities:
    # E01: tier 0, hidden escalation = 1 (TP)
    # E02: tier 2, hidden escalation = 0, pred = 1 (FP)
    # E03: tier 3, hidden escalation = 0, pred = 0 (TN)
    # E04: tier 1, hidden escalation = 1, pred = 0 (FN)
    gt_priv = pd.DataFrame(
        [
            {
                "identity_id": "E01",
                "identity_kind": "human",
                "ad_direct_tier": 3,
                "ad_effective_tier": 0,
                "aws_direct_tier": 9,
                "aws_effective_tier": 9,
                "okta_tier": 3,
                "overall_effective_tier": 0,
                "hidden_escalation": 1,
                "platforms_with_tier_le1": 1,
                "grant_path": "AD: IT-Ops -> Domain Admins",
            },
            {
                "identity_id": "E02",
                "identity_kind": "human",
                "ad_direct_tier": 2,
                "ad_effective_tier": 2,
                "aws_direct_tier": 9,
                "aws_effective_tier": 9,
                "okta_tier": 3,
                "overall_effective_tier": 2,
                "hidden_escalation": 0,
                "platforms_with_tier_le1": 0,
                "grant_path": "AD: Prod-Deployers",
            },
            {
                "identity_id": "E03",
                "identity_kind": "human",
                "ad_direct_tier": 3,
                "ad_effective_tier": 3,
                "aws_direct_tier": 9,
                "aws_effective_tier": 9,
                "okta_tier": 3,
                "overall_effective_tier": 3,
                "hidden_escalation": 0,
                "platforms_with_tier_le1": 0,
                "grant_path": "AD: GRP-VPN-Users",
            },
            {
                "identity_id": "E04",
                "identity_kind": "human",
                "ad_direct_tier": 3,
                "ad_effective_tier": 1,
                "aws_direct_tier": 9,
                "aws_effective_tier": 9,
                "okta_tier": 3,
                "overall_effective_tier": 1,
                "hidden_escalation": 1,
                "platforms_with_tier_le1": 1,
                "grant_path": "AD: IT-Ops -> Server-Admins",
            },
        ]
    )
    gt_links = pd.DataFrame(
        [
            {"identity_id": "E01", "ad_account_id": "AD-01", "aws_user_id": None, "okta_id": None},
            {"identity_id": "E02", "ad_account_id": "AD-02", "aws_user_id": None, "okta_id": None},
            {"identity_id": "E03", "ad_account_id": "AD-03", "aws_user_id": None, "okta_id": None},
            {"identity_id": "E04", "ad_account_id": "AD-04", "aws_user_id": None, "okta_id": None},
        ]
    )
    gt_labels = pd.DataFrame(
        [
            {"identity_id": "E01", "split": "train"},
            {"identity_id": "E02", "split": "train"},
            {"identity_id": "E03", "split": "train"},
            {"identity_id": "E04", "split": "train"},
        ]
    )

    gt_priv.to_parquet(gt_dir / "GT_EffectivePrivilege.parquet", index=False)
    gt_links.to_parquet(gt_dir / "GT_IdentityLinks.parquet", index=False)
    gt_labels.to_parquet(gt_dir / "GT_Labels.parquet", index=False)

    pred_df = pd.DataFrame(
        [
            {
                "identity_id": "E01",
                "identity_kind": "human",
                "ad_direct_tier": 3,
                "ad_effective_tier": 0,
                "aws_direct_tier": 9,
                "aws_effective_tier": 9,
                "okta_tier": 3,
                "overall_effective_tier": 0,
                "hidden_escalation": 1,  # TP
                "grant_path": "AD: IT-Ops -> Domain Admins",
            },
            {
                "identity_id": "E02",
                "identity_kind": "human",
                "ad_direct_tier": 9,
                "ad_effective_tier": 2,
                "aws_direct_tier": 9,
                "aws_effective_tier": 9,
                "okta_tier": 3,
                "overall_effective_tier": 2,
                "hidden_escalation": 1,  # FP
                "grant_path": "AD: Sub -> Prod-Deployers",
            },
            {
                "identity_id": "E03",
                "identity_kind": "human",
                "ad_direct_tier": 3,
                "ad_effective_tier": 3,
                "aws_direct_tier": 9,
                "aws_effective_tier": 9,
                "okta_tier": 3,
                "overall_effective_tier": 3,
                "hidden_escalation": 0,  # TN
                "grant_path": "AD: GRP-VPN-Users",
            },
            {
                "identity_id": "E04",
                "identity_kind": "human",
                "ad_direct_tier": 1,
                "ad_effective_tier": 1,
                "aws_direct_tier": 9,
                "aws_effective_tier": 9,
                "okta_tier": 3,
                "overall_effective_tier": 1,
                "hidden_escalation": 0,  # FN
                "grant_path": "AD: Server-Admins",
            },
        ]
    )

    report = evaluate_privilege_resolution(pred_df, gt_dir=gt_dir, split="train")

    assert report.total_identities == 4
    assert report.tier_accuracy.overall_acc == 1.0
    assert report.escalation_metrics.tp == 1
    assert report.escalation_metrics.fp == 1
    assert report.escalation_metrics.tn == 1
    assert report.escalation_metrics.fn == 1
    assert report.escalation_metrics.precision == 0.5
    assert report.escalation_metrics.recall == 0.5


def test_fixture_privilege_evaluation(fixture_dir: Path) -> None:
    """Run full privilege evaluation against committed test fixtures."""
    gt_dir = fixture_dir / "gt"
    reports = run_full_privilege_evaluation(
        data_dir=fixture_dir,
        gt_dir=gt_dir,
        splits=["train"],
    )

    assert "train" in reports
    rep = reports["train"]
    assert rep.total_identities > 0
    assert 0.0 <= rep.tier_accuracy.overall_acc <= 1.0
    assert 0.0 <= rep.escalation_metrics.precision <= 1.0
    assert 0.0 <= rep.escalation_metrics.recall <= 1.0
    assert rep.path_accuracy.overall_total == rep.total_identities
