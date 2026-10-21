"""Tests for pandera schema validation (accessatlas.ingestion.schemas)."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from accessatlas.ingestion.loader import load_table
from accessatlas.ingestion.schemas import SCHEMAS
from tests.conftest import CORE_FIXTURE_TABLES

# Tables we have schemas for (excludes reference tables with no schema yet)
VALIDATED_TABLES = [t for t in CORE_FIXTURE_TABLES if t in SCHEMAS]


@pytest.mark.parametrize("table_name", VALIDATED_TABLES)
def test_schema_validates_fixture(fixture_dir: Path, table_name: str) -> None:
    """Every fixture table must pass its pandera schema validation."""
    # Load without validation first to get the raw DataFrame.
    df = load_table(table_name, validate=False, fixture_dir=fixture_dir)
    schema = SCHEMAS[table_name]
    # lazy=True collects all errors before raising, giving a full error report.
    validated = schema.validate(df, lazy=True)
    assert isinstance(validated, pd.DataFrame)


def test_hr_records_status_values(fixture_dir: Path) -> None:
    """HR_Records.status must only contain 'active', 'terminated', or 'on_leave'."""
    df = load_table("HR_Records", validate=False, fixture_dir=fixture_dir)
    bad = df[~df["status"].isin(["active", "terminated", "on_leave"])]["status"].unique()
    assert len(bad) == 0, f"Unexpected HR status values: {bad}"


def test_hr_offboarding_date_columns_are_datetime(fixture_dir: Path) -> None:
    """After cleaning, all *_date columns in HR_Offboarding must be datetime (or NaT)."""
    df = load_table("HR_Offboarding", validate=False, fixture_dir=fixture_dir)
    date_cols = [
        "termination_date",
        "ad_disabled_date",
        "okta_deactivated_date",
        "aws_access_removed_date",
    ]
    for col in date_cols:
        if col in df.columns:
            assert pd.api.types.is_datetime64_any_dtype(df[col]), (
                f"HR_Offboarding.{col} is not datetime dtype after cleaning"
            )


def test_ad_users_enabled_is_boolean(fixture_dir: Path) -> None:
    """AD_Users.enabled must be a boolean (nullable) after cleaning."""
    df = load_table("AD_Users", validate=False, fixture_dir=fixture_dir)
    assert pd.api.types.is_bool_dtype(df["enabled"]) or str(df["enabled"].dtype) == "boolean", (
        f"AD_Users.enabled dtype is {df['enabled'].dtype}, expected bool/boolean"
    )


def test_aws_users_bool_columns(fixture_dir: Path) -> None:
    """AWS_Users boolean columns must not be stored as strings after cleaning."""
    df = load_table("AWS_Users", validate=False, fixture_dir=fixture_dir)
    for col in ("console_access", "mfa_enabled"):
        if col in df.columns:
            dtype_str = str(df[col].dtype)
            assert dtype_str in ("bool", "boolean"), (
                f"AWS_Users.{col} dtype is '{dtype_str}', expected bool/boolean"
            )


def test_tier_mapping_tier_range(fixture_dir: Path) -> None:
    """Tier_Mapping.common_tier must be between 0 and 3 inclusive."""
    df = load_table("Tier_Mapping", validate=False, fixture_dir=fixture_dir)
    bad = df[~df["common_tier"].between(0, 3)]
    assert bad.empty, f"Out-of-range tiers: {bad[['platform', 'role_or_group', 'common_tier']]}"


def test_audit_events_platform_values(fixture_dir: Path) -> None:
    """Audit_Events.platform must only contain 'ad', 'aws', or 'okta'."""
    df = load_table("Audit_Events", validate=False, fixture_dir=fixture_dir)
    bad = df[~df["platform"].isin(["ad", "aws", "okta"])]["platform"].unique()
    assert len(bad) == 0, f"Unexpected platform values in Audit_Events: {bad}"
