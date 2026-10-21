"""Tests for the identity resolution evaluation metrics (Milestone 2).

These tests run inside tests/ and verify that evaluation metrics (precision,
recall, unresolved rates, and breakdowns by kind and signal) work accurately
using the test fixture in tests/fixtures/gt/.
"""

from __future__ import annotations

import pandas as pd
import pytest

from accessatlas.evaluation.identity_metrics import (
    evaluate_identity_resolution,
    load_gt_identity_data,
)
from accessatlas.resolution.resolver import resolve_identities


@pytest.fixture
def fixture_gt_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load GT fixtures from tests/fixtures/gt/."""
    return load_gt_identity_data("tests/fixtures/gt")


def test_load_gt_fixture(fixture_gt_data: tuple[pd.DataFrame, pd.DataFrame]) -> None:
    """Verify loading GT fixtures works and contains fixture data."""
    links, labels = fixture_gt_data
    assert not links.empty
    assert not labels.empty
    assert "identity_id" in links.columns
    assert "identity_id" in labels.columns
    assert "split" in labels.columns


def test_evaluate_fixture_resolution(
    fixture_gt_data: tuple[pd.DataFrame, pd.DataFrame],
) -> None:
    """Run resolution on fixture tables and evaluate against fixture GT."""
    links, labels = fixture_gt_data

    hr = pd.read_parquet("tests/fixtures/HR_Records.parquet")
    ad = pd.read_parquet("tests/fixtures/AD_Users.parquet")
    aws = pd.read_parquet("tests/fixtures/AWS_Users.parquet")
    okta = pd.read_parquet("tests/fixtures/Okta_Users.parquet")

    core_tables = {
        "HR_Records": hr,
        "AD_Users": ad,
        "AWS_Users": aws,
        "Okta_Users": okta,
    }

    res = resolve_identities(hr, ad, aws, okta, fuzzy_threshold=85.0)
    report = evaluate_identity_resolution(res, links, labels, core_tables=core_tables)

    assert report.total_gt_accounts > 0
    assert report.overall_precision >= 0.99
    assert report.overall_recall >= 0.95
    assert "human" in report.by_kind
    assert "id" in report.by_signal
    assert report.by_signal["id"].precision >= 0.99


def test_synthetic_service_and_orphan_metrics() -> None:
    """Verify evaluation metric calculations for service and orphan scenarios."""
    # Synthetic GT
    gt_links = pd.DataFrame(
        [
            {
                "identity_id": "E001",
                "identity_kind": "human",
                "ad_account_id": "AD-01",
                "aws_user_id": None,
                "okta_id": None,
            },
            {
                "identity_id": "SVC-01",
                "identity_kind": "service",
                "ad_account_id": "AD-SVC-01",
                "aws_user_id": None,
                "okta_id": None,
            },
            {
                "identity_id": "ORPH-01",
                "identity_kind": "orphan",
                "ad_account_id": "AD-ORPH-01",
                "aws_user_id": None,
                "okta_id": None,
            },
        ]
    )
    gt_labels = pd.DataFrame(
        [
            {"identity_id": "E001", "split": "test"},
            {"identity_id": "SVC-01", "split": "test"},
            {"identity_id": "ORPH-01", "split": "test"},
        ]
    )

    hr = pd.DataFrame(
        [
            {
                "employee_id": "E001",
                "first_name": "Test",
                "last_name": "User",
                "email": "test@example.com",
            }
        ]
    )
    ad = pd.DataFrame(
        [
            {
                "account_id": "AD-01",
                "account_type": "human",
                "employee_id": "E001",
                "mail": "test@example.com",
            },
            {
                "account_id": "AD-SVC-01",
                "account_type": "service",
                "employee_id": None,
                "mail": None,
                "owner_employee_id": "E001",
            },
            {
                "account_id": "AD-ORPH-01",
                "account_type": "orphan",
                "employee_id": None,
                "mail": None,
                "owner_employee_id": None,
            },
        ]
    )
    empty_df = pd.DataFrame(
        columns=[
            "user_id",
            "okta_id",
            "account_type",
            "tag_employee_id",
            "tag_email",
            "employee_number",
            "email",
            "login",
            "owner_employee_id",
        ]
    )

    core_tables = {
        "HR_Records": hr,
        "AD_Users": ad,
        "AWS_Users": empty_df,
        "Okta_Users": empty_df,
    }

    res = resolve_identities(hr, ad, empty_df, empty_df)
    report = evaluate_identity_resolution(
        res, gt_links, gt_labels, split="test", core_tables=core_tables
    )

    assert report.overall_precision == 1.0
    assert report.overall_recall == 1.0
    assert report.by_kind["human"].precision == 1.0
    assert report.by_kind["service"].precision == 1.0
    assert report.by_kind["orphan"].precision == 1.0
    assert report.by_kind["orphan"].unresolved_rate == 1.0
