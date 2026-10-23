"""Unit tests for M5 behavioral anomaly detection features, models, and evidence formatting."""

from pathlib import Path

import pandas as pd
import pytest

from accessatlas.graph import build_privilege_graph, compute_identity_privileges
from accessatlas.ingestion.loader import load_table
from accessatlas.ml.features import (
    HUMAN_FEATURE_COLS,
    SERVICE_FEATURE_COLS,
    extract_behavioral_features,
)
from accessatlas.ml.model import BehavioralAnomalyDetector
from accessatlas.resolution import resolve_identities
from accessatlas.rules.models import Finding
from accessatlas.utils import load_config

FIXTURES_DIR = Path("tests/fixtures")


def test_generic_feature_columns_definition():
    """Verify feature sets are generic and contain no scenario-specific column names."""
    for col in HUMAN_FEATURE_COLS + SERVICE_FEATURE_COLS:
        col_lower = col.lower()
        assert "token_misuse" not in col_lower
        assert "privilege_creep" not in col_lower
        assert "excessive_service_privilege" not in col_lower


def test_synthetic_behavioral_feature_extraction():
    """Test feature extraction and peer grouping on controlled synthetic data."""
    snapshot_date = pd.Timestamp("2026-10-12 23:59:59")

    # 1 human and 1 service identity
    resolved_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "identity_kind": "human",
                "ad_account_id": "AD-01",
                "aws_user_id": None,
                "okta_id": None,
            },
            {
                "identity_id": "svc:aws:backup-bot",
                "identity_kind": "service",
                "ad_account_id": None,
                "aws_user_id": "AWS-SVC-01",
                "okta_id": None,
            },
        ]
    )

    priv_df = pd.DataFrame(
        [
            {"identity_id": "E10001", "overall_effective_tier": 1},
            {"identity_id": "svc:aws:backup-bot", "overall_effective_tier": 0},
        ]
    )

    hr_df = pd.DataFrame([{"employee_id": "E10001", "department": "Security"}])

    # Audit events
    audit_df = pd.DataFrame(
        [
            {
                "event_id": "EVT-1",
                "account_id": "AD-01",
                "timestamp": pd.Timestamp("2026-10-09 14:00:00"),  # weekday business hours
                "source_ip": "10.0.0.1",
                "geo_country": "US",
                "privileged_action": False,
                "mfa_used": True,
                "result": "Success",
                "bytes_transferred": 100,
            },
            {
                "event_id": "EVT-2",
                "account_id": "AD-01",
                "timestamp": pd.Timestamp("2026-10-11 23:00:00"),  # off-hours
                "source_ip": "10.0.0.2",
                "geo_country": "US",
                "privileged_action": True,
                "mfa_used": True,
                "result": "Success",
                "bytes_transferred": 500,
            },
            {
                "event_id": "EVT-3",
                "account_id": "AWS-SVC-01",
                "timestamp": pd.Timestamp("2026-10-10 02:00:00"),
                "source_ip": "172.16.0.5",
                "geo_country": "US",
                "privileged_action": False,
                "mfa_used": False,
                "result": "Success",
                "bytes_transferred": 2000,
            },
        ]
    )

    feat_df, peer_med, peer_std = extract_behavioral_features(
        audit_events_df=audit_df,
        resolved_identities=resolved_df,
        privilege_df=priv_df,
        snapshot_date=snapshot_date,
        hr_records_df=hr_df,
    )

    assert len(feat_df) == 2
    human_row = feat_df[feat_df["identity_id"] == "E10001"].iloc[0]
    service_row = feat_df[feat_df["identity_id"] == "svc:aws:backup-bot"].iloc[0]

    # Verify peer groups: humans get dept:<Department>, services get service_accounts
    assert human_row["peer_group"] == "dept:Security"
    assert service_row["peer_group"] == "service_accounts"

    # Verify peer statistics dictionaries contain both groups
    assert "dept:Security" in peer_med
    assert "service_accounts" in peer_med
    assert "dept:Security" in peer_std
    assert "service_accounts" in peer_std

    # Verify metrics
    assert human_row["total_events"] == 2
    assert human_row["off_hours_share"] == 0.5
    assert human_row["distinct_ips"] == 2
    assert service_row["total_events"] == 1


def test_detector_fit_score_and_evidence():
    """Test BehavioralAnomalyDetector fitting, thresholding, and evidence formatting."""
    # Synthetic dataset with 25 baseline identities and 1 outlier
    records = []
    for i in range(25):
        records.append(
            {
                "identity_id": f"E100{i:02d}",
                "identity_kind": "human",
                "peer_group": "dept:Engineering",
                "events_per_day": 10.0 + (i % 3),
                "total_events": 50.0 + i,
                "off_hours_share": 0.05,
                "distinct_ips": 1.0,
                "distinct_countries": 1.0,
                "max_bytes_transferred": 1000.0,
                "total_bytes_transferred": 5000.0,
                "failure_rate": 0.01,
                "privileged_action_share": 0.05,
                "mfa_rate": 0.95,
                "total_groups_count": 3.0,
                "has_role_change": 0.0,
                "effective_tier_score": 1.0,
                "privilege_utilization_gap": 0.85,
                "token_count": 0.0,
                "min_token_scope_tier": 0.0,
                "peer_events_per_day_zscore": 0.1,
                "peer_off_hours_zscore": 0.0,
                "peer_distinct_ips_zscore": 0.0,
                "peer_bytes_zscore": 0.0,
                "peer_priv_action_zscore": 0.0,
                "peer_group_count_zscore": 0.0,
                "peer_tier_zscore": 0.0,
            }
        )

    # 1 Extreme Outlier
    records.append(
        {
            "identity_id": "E10099",
            "identity_kind": "human",
            "peer_group": "dept:Engineering",
            "events_per_day": 500.0,
            "total_events": 2500.0,
            "off_hours_share": 0.95,
            "distinct_ips": 15.0,
            "distinct_countries": 4.0,
            "max_bytes_transferred": 80000000.0,
            "total_bytes_transferred": 90000000.0,
            "failure_rate": 0.40,
            "privileged_action_share": 0.90,
            "mfa_rate": 0.10,
            "total_groups_count": 25.0,
            "has_role_change": 1.0,
            "effective_tier_score": 3.0,
            "privilege_utilization_gap": 0.30,
            "token_count": 5.0,
            "min_token_scope_tier": 3.0,
            "peer_events_per_day_zscore": 15.0,
            "peer_off_hours_zscore": 12.0,
            "peer_distinct_ips_zscore": 10.0,
            "peer_bytes_zscore": 25.0,
            "peer_priv_action_zscore": 8.0,
            "peer_group_count_zscore": 9.0,
            "peer_tier_zscore": 6.0,
        }
    )

    feat_df = pd.DataFrame(records)

    peer_med = {
        "dept:Engineering": {
            "events_per_day": 11.0,
            "off_hours_share": 0.05,
            "distinct_ips": 1.0,
            "distinct_countries": 1.0,
            "max_bytes_transferred": 1000.0,
            "total_bytes_transferred": 5000.0,
            "failure_rate": 0.01,
            "privileged_action_share": 0.05,
            "total_groups_count": 3.0,
            "effective_tier_score": 1.0,
            "privilege_utilization_gap": 0.85,
            "token_count": 0.0,
        }
    }
    peer_std = {
        "dept:Engineering": {
            "events_per_day": 2.0,
            "off_hours_share": 0.02,
            "distinct_ips": 0.5,
            "distinct_countries": 0.2,
            "max_bytes_transferred": 500.0,
            "total_bytes_transferred": 1000.0,
            "failure_rate": 0.01,
            "privileged_action_share": 0.02,
            "total_groups_count": 1.0,
            "effective_tier_score": 0.5,
            "privilege_utilization_gap": 0.2,
            "token_count": 0.5,
        }
    }

    # Set alert budget to flag ~4% (top 1 out of 26)
    detector = BehavioralAnomalyDetector(alert_budget_percentile=4.0, random_state=42)
    detector.fit(feat_df)
    assert detector.is_fitted

    scored_df = detector.score(feat_df)
    assert "anomaly_score" in scored_df.columns
    assert "anomaly_threshold" in scored_df.columns
    assert "is_anomaly" in scored_df.columns

    # Outlier must be detected
    outlier_row = scored_df[scored_df["identity_id"] == "E10099"].iloc[0]
    assert outlier_row["is_anomaly"]

    findings = detector.generate_findings(scored_df, peer_med, peer_std)
    assert len(findings) >= 1

    outlier_finding = next((f for f in findings if f.identity_id == "E10099"), None)
    assert outlier_finding is not None
    assert isinstance(outlier_finding, Finding)
    assert outlier_finding.rule == "behavioural_anomaly"
    assert outlier_finding.severity == "medium"
    assert outlier_finding.finding_id == "FND-behavioural_anomaly-E10099"

    # Requirement 6: evidence must show top 3 deviating features with value, peer median and z-score
    evidence = outlier_finding.evidence
    assert len(evidence) >= 4  # overview line + 3 deviating features
    feature_evidence_lines = evidence[1:4]
    for line in feature_evidence_lines:
        assert "value=" in line
        assert "peer median=" in line
        assert "z-score=" in line


@pytest.mark.skipif(
    not (FIXTURES_DIR / "Audit_Events.parquet").exists(),
    reason="Fixture parquets not found; skipping fixture integration test",
)
def test_ml_pipeline_with_fixtures():
    """Verify behavioral feature extraction and model execution using test fixtures."""
    cfg = load_config()

    # Load fixtures
    hr = load_table("HR_Records", config=cfg, fixture_dir=FIXTURES_DIR)
    ad = load_table("AD_Users", config=cfg, fixture_dir=FIXTURES_DIR)
    aws = load_table("AWS_Users", config=cfg, fixture_dir=FIXTURES_DIR)
    okta = load_table("Okta_Users", config=cfg, fixture_dir=FIXTURES_DIR)
    tokens = load_table("API_Tokens", config=cfg, fixture_dir=FIXTURES_DIR)
    role_changes = load_table("HR_RoleChanges", config=cfg, fixture_dir=FIXTURES_DIR)
    audit = load_table("Audit_Events", config=cfg, fixture_dir=FIXTURES_DIR, validate=False)
    ad_mem = load_table("AD_GroupMembership", config=cfg, fixture_dir=FIXTURES_DIR)
    aws_ug = load_table("AWS_UserGroups", config=cfg, fixture_dir=FIXTURES_DIR)
    okta_mem = load_table("Okta_GroupMembership", config=cfg, fixture_dir=FIXTURES_DIR)

    res = resolve_identities(hr, ad, aws, okta)
    resolved_df = res.resolved_identities

    graph = build_privilege_graph(
        ad_groups_df=load_table("AD_Groups", config=cfg, fixture_dir=FIXTURES_DIR),
        ad_membership_df=ad_mem,
        aws_groups_df=load_table("AWS_Groups", config=cfg, fixture_dir=FIXTURES_DIR),
        aws_policies_df=load_table("AWS_Policies", config=cfg, fixture_dir=FIXTURES_DIR),
        aws_user_groups_df=aws_ug,
        aws_policy_attach_df=load_table("AWS_PolicyAttach", config=cfg, fixture_dir=FIXTURES_DIR),
        okta_admin_roles_df=load_table("Okta_AdminRoles", config=cfg, fixture_dir=FIXTURES_DIR),
        okta_group_membership_df=okta_mem,
        okta_aws_federation_df=load_table(
            "Okta_AWS_Federation", config=cfg, fixture_dir=FIXTURES_DIR
        ),
        tier_mapping_df=load_table("Tier_Mapping", config=cfg, fixture_dir=FIXTURES_DIR),
        ad_users_df=ad,
        aws_users_df=aws,
        okta_users_df=okta,
    )
    priv_df = compute_identity_privileges(graph, resolved_df)

    feat_df, peer_med, peer_std = extract_behavioral_features(
        audit_events_df=audit,
        resolved_identities=resolved_df,
        privilege_df=priv_df,
        snapshot_date=pd.Timestamp(cfg.get("snapshot_date", "2026-10-12")),
        tokens_df=tokens,
        role_changes_df=role_changes,
        ad_membership_df=ad_mem,
        aws_user_groups_df=aws_ug,
        okta_group_membership_df=okta_mem,
        hr_records_df=hr,
    )

    assert not feat_df.empty
    assert "events_per_day" in feat_df.columns
    assert "peer_events_per_day_zscore" in feat_df.columns

    # Fit detector and generate findings
    detector = BehavioralAnomalyDetector(alert_budget_percentile=5.0)
    detector.fit(feat_df)
    scored = detector.score(feat_df)
    findings = detector.generate_findings(
        scored, peer_med, peer_std, resolved_identities=resolved_df
    )

    assert isinstance(findings, list)
    for f in findings:
        assert f.rule == "behavioural_anomaly"
        assert f.severity == "medium"
        assert any("z-score=" in line for line in f.evidence)
