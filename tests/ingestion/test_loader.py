"""Tests for the Parquet loader (accessatlas.ingestion.loader)."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from accessatlas.ingestion.loader import load_all_core, load_table
from tests.helpers import CORE_FIXTURE_TABLES


@pytest.mark.parametrize("table_name", CORE_FIXTURE_TABLES)
def test_load_table_returns_dataframe(fixture_dir: Path, table_name: str) -> None:
    """Every fixture table must load without error and return a non-empty DataFrame."""
    df = load_table(table_name, validate=False, fixture_dir=fixture_dir)
    assert isinstance(df, pd.DataFrame), f"{table_name} did not return a DataFrame"
    assert len(df) > 0, f"{table_name} fixture is empty"


def test_load_table_missing_file_raises() -> None:
    """Loading a table that has no Parquet file must raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="convert_data"):
        load_table("HR_Records", fixture_dir=Path("/nonexistent/path"))


def test_load_all_core_returns_all_tables(fixture_dir: Path) -> None:
    """load_all_core must return a dict containing every core table."""
    tables = load_all_core(validate=False, fixture_dir=fixture_dir)
    # Audit_Events is not in the core set (it has its own path), so exclude it.
    core_only = {t for t in CORE_FIXTURE_TABLES if t != "Audit_Events"}
    for name in core_only:
        assert name in tables, f"load_all_core() missing table: {name}"


def test_hr_records_employee_id_unique(fixture_dir: Path) -> None:
    """HR_Records must have unique employee_ids (PK constraint)."""
    df = load_table("HR_Records", validate=False, fixture_dir=fixture_dir)
    dupes = df[df["employee_id"].duplicated()]
    assert dupes.empty, f"Duplicate employee_ids in HR_Records: {dupes['employee_id'].tolist()}"


def test_audit_events_load(fixture_dir: Path) -> None:
    """Audit_Events fixture must load and have the expected columns."""
    df = load_table("Audit_Events", validate=False, fixture_dir=fixture_dir)
    required = {"event_id", "timestamp", "platform", "account_id", "username"}
    missing = required - set(df.columns)
    assert not missing, f"Audit_Events missing columns: {missing}"
