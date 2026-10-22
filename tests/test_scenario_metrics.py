"""Tests for M4 scenario metrics evaluation."""

from pathlib import Path

import pandas as pd
import pytest

from accessatlas.evaluation.scenario_metrics import (
    evaluate_scenario_findings,
    load_gt_scenario_data,
)
from accessatlas.rules.models import Finding


@pytest.mark.skipif(
    not Path("data/processed/gt").exists(),
    reason="Full GT data is not available in CI (data/ is gitignored)",
)
def test_load_gt_scenario_data():
    """Verify that GT scenario data loads valid DataFrames."""
    gt_labels, gt_links = load_gt_scenario_data()
    assert isinstance(gt_labels, pd.DataFrame)
    assert isinstance(gt_links, pd.DataFrame)
    assert "scenario" in gt_labels.columns
    assert "is_anomaly" in gt_labels.columns
    assert "is_trap" in gt_labels.columns


def test_evaluate_scenario_findings_synthetic():
    """Test scenario evaluation calculation on synthetic findings and labels."""
    gt_labels = pd.DataFrame(
        [
            # Train anomalies
            {
                "identity_id": "E10001",
                "scenario": "offboarding_gap",
                "is_anomaly": 1,
                "is_trap": 0,
                "split": "train",
            },
            {
                "identity_id": "E10002",
                "scenario": "offboarding_gap",
                "is_anomaly": 1,
                "is_trap": 0,
                "split": "train",
            },
            {
                "identity_id": "E10003",
                "scenario": "cross_platform_admin",
                "is_anomaly": 1,
                "is_trap": 0,
                "split": "train",
            },
            # Uncovered anomaly
            {
                "identity_id": "E10004",
                "scenario": "privilege_creep",
                "is_anomaly": 1,
                "is_trap": 0,
                "split": "train",
            },
            # Train traps
            {
                "identity_id": "E10005",
                "scenario": "oncall_engineer",
                "is_anomaly": 0,
                "is_trap": 1,
                "split": "train",
            },
            {
                "identity_id": "E10006",
                "scenario": "scheduled_night_job",
                "is_anomaly": 0,
                "is_trap": 1,
                "split": "train",
            },
            # Normal
            {
                "identity_id": "E10007",
                "scenario": "normal",
                "is_anomaly": 0,
                "is_trap": 0,
                "split": "train",
            },
        ]
    )
    gt_links = pd.DataFrame(
        [
            {"identity_id": "E10001", "ad_account_id": "AD-01"},
            {"identity_id": "E10002", "ad_account_id": "AD-02"},
            {"identity_id": "E10003", "ad_account_id": "AD-03"},
            {"identity_id": "E10004", "ad_account_id": "AD-04"},
            {"identity_id": "E10005", "ad_account_id": "AD-05"},
            {"identity_id": "E10006", "ad_account_id": "AD-06"},
            {"identity_id": "E10007", "ad_account_id": "AD-07"},
        ]
    )

    findings = [
        # TP for offboarding_gap (E10001)
        Finding(
            finding_id="F1",
            rule="offboarding_gap",
            identity_id="E10001",
            severity="high",
            recommended_action="Remediate",
        ),
        # FP for offboarding_gap (E10007 is normal)
        Finding(
            finding_id="F2",
            rule="offboarding_gap",
            identity_id="E10007",
            severity="high",
            recommended_action="Remediate",
        ),
        # TP for cross_platform_admin (E10003)
        Finding(
            finding_id="F3",
            rule="cross_platform_admin",
            identity_id="E10003",
            severity="high",
            recommended_action="Remediate",
        ),
    ]

    report = evaluate_scenario_findings(findings, gt_labels, gt_links, split="train")

    assert report.total_identities == 7
    assert report.total_findings == 3

    # offboarding_gap: TP=1, FP=1, FN=1 -> precision=0.5, recall=0.5
    og = report.scenarios["offboarding_gap"]
    assert og.covered is True
    assert og.tp == 1
    assert og.fp == 1
    assert og.fn == 1
    assert og.precision == 0.5
    assert og.recall == 0.5

    # privilege_creep: not covered -> fn=1
    pc = report.scenarios["privilege_creep"]
    assert pc.covered is False
    assert pc.fn == 1

    # oncall_engineer: trap not flagged -> FAR = 0.0
    oe = report.traps["oncall_engineer"]
    assert oe.total_traps == 1
    assert oe.flagged_traps == 0
    assert oe.false_alarm_rate == 0.0
    assert oe.has_firing_rule is True

    # scheduled_night_job: behavioral trap -> has_firing_rule is False
    snj = report.traps["scheduled_night_job"]
    assert snj.total_traps == 1
    assert snj.has_firing_rule is False
