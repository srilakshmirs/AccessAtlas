"""Unit tests for accessatlas.normalization.common and reporter.

Tests each individual normalizer function, edge cases, deterministic ID generation,
and quality reporting without relying on external datasets.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from accessatlas.normalization.common import (
    DeterministicIdGenerator,
    deduplicate_rows,
    load_normalization_config,
    normalize_boolean,
    normalize_categorical,
    normalize_datetime,
    normalize_email,
    normalize_missing,
    normalize_name,
    normalize_tier,
    normalize_whitespace,
    parse_time_window,
)
from accessatlas.normalization.reporter import QualityReporter

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "normalization"


def test_load_normalization_config() -> None:
    """Config loads valid YAML containing dataset configurations."""
    cfg = load_normalization_config()
    assert "common" in cfg
    assert "datasets" in cfg
    assert "dataset_c" in cfg["datasets"]
    assert "dataset_a" in cfg["datasets"]


def test_normalize_missing() -> None:
    """Missing markers (N/A, None, whitespace) are transformed to pd.NA/nan."""
    s = pd.Series(["valid", "N/A", "None", "  ", "", "null", "-", "actual_val"])
    cleaned, count = normalize_missing(s)
    assert count == 6
    assert cleaned.iloc[0] == "valid"
    assert pd.isna(cleaned.iloc[1])
    assert pd.isna(cleaned.iloc[2])
    assert pd.isna(cleaned.iloc[3])
    assert pd.isna(cleaned.iloc[4])
    assert pd.isna(cleaned.iloc[5])
    assert pd.isna(cleaned.iloc[6])
    assert cleaned.iloc[7] == "actual_val"


def test_normalize_whitespace() -> None:
    """Leading/trailing and duplicate whitespace is collapsed."""
    s = pd.Series(["  john   smith  ", "clean text", "  extra   spaces  here "])
    cleaned, count = normalize_whitespace(s)
    assert count == 2
    assert cleaned.iloc[0] == "john smith"
    assert cleaned.iloc[1] == "clean text"
    assert cleaned.iloc[2] == "extra spaces here"


def test_normalize_email() -> None:
    """Emails are trimmed and lowercased; missing markers become NaN."""
    s = pd.Series(["  Alice.Smith@Acme.Com  ", "BOB@EXAMPLE.ORG", "N/A"])
    cleaned, count = normalize_email(s)
    assert cleaned.iloc[0] == "alice.smith@acme.com"
    assert cleaned.iloc[1] == "bob@example.org"
    assert count == 2


def test_normalize_name() -> None:
    """Names are capitalized and hyphenated parts are preserved."""
    s = pd.Series(["  john  smith ", "mary-jane watson", "o'connor"])
    cleaned, count = normalize_name(s)
    assert cleaned.iloc[0] == "John Smith"
    assert cleaned.iloc[1] == "Mary-Jane Watson"
    assert count >= 2


def test_normalize_boolean() -> None:
    """Boolean strings, integers, and case variations are coerced to boolean dtype."""
    s = pd.Series(["TRUE", "false", "YES", "no", "1", "0", "N/A"])
    cleaned, count = normalize_boolean(s)
    assert str(cleaned.dtype) == "boolean"
    assert cleaned.iloc[0] is True or cleaned.iloc[0] == True  # noqa: E712
    assert cleaned.iloc[1] is False or cleaned.iloc[1] == False  # noqa: E712
    assert cleaned.iloc[2] is True or cleaned.iloc[2] == True  # noqa: E712
    assert cleaned.iloc[3] is False or cleaned.iloc[3] == False  # noqa: E712
    assert cleaned.iloc[4] is True or cleaned.iloc[4] == True  # noqa: E712
    assert cleaned.iloc[5] is False or cleaned.iloc[5] == False  # noqa: E712
    assert pd.isna(cleaned.iloc[6])
    assert count == 6


def test_normalize_boolean_from_fixture() -> None:
    """Test boolean normalization on fixture CSV file."""
    df = pd.read_csv(FIXTURES_DIR / "sample_booleans.csv")
    cleaned, count = normalize_boolean(df["raw_bool"])
    assert count == 6
    assert str(cleaned.dtype) == "boolean"


def test_normalize_datetime_heterogeneous() -> None:
    """Coerces varied date styles (DD-MON-YYYY, MM/DD/YYYY HH:MM:SS, ISO-Z, epoch) to UTC naive."""
    s = pd.Series(
        [
            "15-JUL-2026",
            "07/16/2026 14:30:00",
            "2026-07-17T09:15:30Z",
            "1721200000",
            "N/A",
        ]
    )
    cleaned, count = normalize_datetime(
        s, date_formats=["%d-%b-%Y", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"]
    )
    assert count == 4
    assert str(cleaned.dtype) == "datetime64[ns]"
    assert cleaned.iloc[0] == pd.Timestamp("2026-07-15 00:00:00")
    assert cleaned.iloc[1] == pd.Timestamp("2026-07-16 14:30:00")
    assert cleaned.iloc[2] == pd.Timestamp("2026-07-17 09:15:30")
    assert pd.isna(cleaned.iloc[4])


def test_normalize_datetime_from_fixture() -> None:
    """Test datetime normalizer on fixture CSV file."""
    df = pd.read_csv(FIXTURES_DIR / "sample_dates.csv")
    cleaned, count = normalize_datetime(
        df["raw_date"], date_formats=["%d-%b-%Y", "%m/%d/%Y %H:%M:%S"]
    )
    assert count == 4
    assert str(cleaned.dtype) == "datetime64[ns]"


def test_normalize_categorical() -> None:
    """Maps status and platform words with case and whitespace insensitivity."""
    s_status = pd.Series(["ACTIVE", "Terminated", "  on leave  ", "DISABLED", "UNKNOWN"])
    status_map = {
        "active": "active",
        "terminated": "terminated",
        "on leave": "on_leave",
        "disabled": "terminated",
    }
    mapped_status, count = normalize_categorical(s_status, status_map)
    assert count == 4
    assert mapped_status.iloc[0] == "active"
    assert mapped_status.iloc[1] == "terminated"
    assert mapped_status.iloc[2] == "on_leave"
    assert mapped_status.iloc[3] == "terminated"
    assert pd.isna(mapped_status.iloc[4])

    s_plat = pd.Series(["Active Directory", "AWS IAM", "okta"])
    plat_map = {"active directory": "ad", "aws iam": "aws", "okta": "okta"}
    mapped_plat, _ = normalize_categorical(s_plat, plat_map)
    assert list(mapped_plat) == ["ad", "aws", "okta"]


def test_normalize_tier() -> None:
    """Maps text labels and integers to 0..3 tier scale."""
    s = pd.Series(["Tier-0 Administrator", "PowerUsers", "Delegated Admin", "ReadOnly", "0", 3, 9])
    tier_map = {
        "tier-0 administrator": 0,
        "powerusers": 1,
        "delegated admin": 2,
        "readonly": 3,
    }
    cleaned, count = normalize_tier(s, tier_mapping=tier_map)
    assert count == 7
    assert list(cleaned) == [0, 1, 2, 3, 0, 3, 9]


def test_deduplicate_rows() -> None:
    """Removes exact duplicate rows and reports count."""
    df = pd.DataFrame(
        {
            "id": [1, 2, 2, 3, 3, 3],
            "name": ["a", "b", "b", "c", "c", "c"],
        }
    )
    deduped, removed = deduplicate_rows(df)
    assert removed == 3
    assert len(deduped) == 3


def test_parse_time_window() -> None:
    """Parses varied time window strings into two-digit window_start and window_end."""
    df = pd.read_csv(FIXTURES_DIR / "sample_time_windows.csv")
    starts, ends, count = parse_time_window(df["time_window"])
    assert count == 3
    assert starts.iloc[0] == "02:00"
    assert ends.iloc[0] == "04:00"
    assert starts.iloc[1] == "01:00"
    assert ends.iloc[1] == "05:00"
    assert starts.iloc[2] == "09:30"
    assert ends.iloc[2] == "17:00"
    assert pd.isna(starts.iloc[3])
    assert pd.isna(ends.iloc[3])


def test_deterministic_id_generator(tmp_path: Path) -> None:
    """Generates deterministic canonical IDs and writes id_map.csv."""
    gen = DeterministicIdGenerator()
    ad1 = gen.get_or_generate_id("ad", "john.doe")
    ad1_repeat = gen.get_or_generate_id("ad", "john.doe")
    ad2 = gen.get_or_generate_id("ad", "jane.smith")
    aws1 = gen.get_or_generate_id("aws", "jdoe-admin")

    assert ad1 == ad1_repeat
    assert ad1 != ad2
    assert ad1.startswith("AD-")
    assert aws1.startswith("AWS-USR-")

    # Already canonical ID should be preserved
    preserved_ad = gen.get_or_generate_id("ad", "AD-000123")
    assert preserved_ad == "AD-000123"

    # Export mapping
    map_file = tmp_path / "id_map.csv"
    gen.export_id_map(map_file)
    assert map_file.is_file()
    lines = map_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 4  # header + 4 keys


def test_quality_reporter(tmp_path: Path) -> None:
    """Quality reporter records fixes, duplicates, rejects, unavailable columns and saves outputs."""
    reporter = QualityReporter(dataset_name="test_run")
    stats = reporter.get_or_create_table("HR_Records")
    stats.rows_read = 100
    stats.duplicates_removed = 5
    stats.rows_output = 95
    stats.columns_unavailable = ["notes"]
    stats.record_fix("datetime_coerced", 20)
    stats.record_fix("whitespace_trimmed", 10)
    stats.record_rejection("missing_employee_id", 0)

    reporter.mark_unavailable("Scheduled_Jobs", "Not in source")

    json_path, md_path = reporter.write_reports(tmp_path)
    assert json_path.is_file()
    assert md_path.is_file()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["dataset"] == "test_run"
    assert "HR_Records" in data["tables"]
    assert data["tables"]["HR_Records"]["rows_output"] == 95
    assert data["tables"]["Scheduled_Jobs"]["status"] == "not available in source"

    md_content = md_path.read_text(encoding="utf-8")
    assert "# Data Normalization Quality Report: test_run" in md_content
    assert "`HR_Records`" in md_content
    assert "`Scheduled_Jobs`" in md_content
