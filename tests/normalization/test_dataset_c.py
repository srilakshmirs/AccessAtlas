"""Integration tests for the Dataset C normalizer (Step 2 of Normalization module).

Tests run against hand-made miniature fixtures in
tests/fixtures/normalization/dataset_c/ that mirror Dataset C's format and column
names WITHOUT touching any file under data/.

Coverage:
  - normalize_dataset_c() produces all 23 canonical Parquet tables in a tmp dir
  - Every table passes Pandera SCHEMAS validation (strict=False)
  - Deterministic id_map.csv is created with the right structure
  - quality_report.json contains the expected keys and table inventory
  - quality_report.md is created and starts with the right header
  - Deduplication: AD_GroupMembership and AWS_UserGroups have 1 duplicate each
  - AD_Users: svc-deploy-001 labelled "service"; asmith and bjones labelled "human"
  - HR_Offboarding: all_platforms_revoked is null (not in source)
  - Audit_Events: unknown account "ghostuser" receives deterministic fallback ID
  - Pandera nullable columns remain null and are listed in columns_unavailable
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from accessatlas.ingestion.schemas import SCHEMAS
from accessatlas.normalization.dataset_c import normalize_dataset_c
from accessatlas.normalization.reporter import QualityReporter

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "normalization" / "dataset_c"
ALL_TABLE_NAMES = list(SCHEMAS.keys())


@pytest.fixture(scope="module")
def normalized_output() -> dict:
    """Run the full normalizer against mini fixtures once per test module.

    Returns a dict with:
      - "tables": dict[str, pd.DataFrame]  — all 23 loaded Parquet tables
      - "reporter": QualityReporter
      - "out_dir": Path  — tmpdir (kept alive for the module scope)
      - "id_map": pd.DataFrame
      - "quality_json": dict
      - "quality_md": str
    """
    # tmpdir must stay alive for the whole module; we keep the TemporaryDirectory
    # object in the returned dict so Python does not delete it early.
    tmpdir = tempfile.TemporaryDirectory()
    out = Path(tmpdir.name)

    reporter: QualityReporter = normalize_dataset_c(FIXTURES_DIR, out)

    tables: dict[str, pd.DataFrame] = {}
    for name in SCHEMAS:
        pf = out / f"{name}.parquet"
        if pf.is_file():
            tables[name] = pd.read_parquet(pf)

    id_map = pd.read_csv(out / "id_map.csv")

    with open(out / "quality_report.json", encoding="utf-8") as f:
        quality_json = json.load(f)

    quality_md = (out / "quality_report.md").read_text(encoding="utf-8")

    return {
        "_tmpdir": tmpdir,  # keep alive
        "tables": tables,
        "reporter": reporter,
        "out_dir": out,
        "id_map": id_map,
        "quality_json": quality_json,
        "quality_md": quality_md,
    }


# ---------------------------------------------------------------------------
# 1. All 23 tables are present
# ---------------------------------------------------------------------------


def test_all_23_tables_present(normalized_output: dict) -> None:
    """Every canonical table must have a Parquet file in the output directory."""
    tables = normalized_output["tables"]
    missing = [name for name in ALL_TABLE_NAMES if name not in tables]
    assert not missing, f"Missing Parquet files for tables: {missing}"


# ---------------------------------------------------------------------------
# 2. Pandera schema validation for all 23 tables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("table_name", ALL_TABLE_NAMES)
def test_schema_validation(normalized_output: dict, table_name: str) -> None:
    """Each table must pass its Pandera schema (strict=False)."""
    df = normalized_output["tables"].get(table_name)
    assert df is not None, f"{table_name}.parquet was not produced"
    # Will raise SchemaError on failure
    SCHEMAS[table_name].validate(df, lazy=True)


# ---------------------------------------------------------------------------
# 3. Reporter: all tables marked "available"
# ---------------------------------------------------------------------------


def test_all_tables_reported_available(normalized_output: dict) -> None:
    """Quality reporter must mark all 23 tables as 'available' (not 'not available in source')."""
    reporter: QualityReporter = normalized_output["reporter"]
    not_avail = [name for name, t in reporter.tables.items() if t.status != "available"]
    assert not not_avail, f"Tables not available in source: {not_avail}"


# ---------------------------------------------------------------------------
# 4. id_map.csv structure
# ---------------------------------------------------------------------------


def test_id_map_created(normalized_output: dict) -> None:
    """id_map.csv must exist and contain expected columns."""
    id_map = normalized_output["id_map"]
    assert not id_map.empty, "id_map.csv is empty"
    # Columns must include at least: platform, raw_key, account_id
    for col in ("platform", "source_identifier", "canonical_account_id"):
        assert col in id_map.columns, f"id_map.csv missing column '{col}'"


def test_id_map_no_duplicate_account_ids(normalized_output: dict) -> None:
    """Every account_id in id_map.csv must be unique within its platform."""
    id_map = normalized_output["id_map"]
    dupes = id_map.groupby(["platform", "canonical_account_id"]).size()
    assert (dupes == 1).all(), "Duplicate account_id entries in id_map.csv"


# ---------------------------------------------------------------------------
# 5. quality_report.json structure
# ---------------------------------------------------------------------------


def test_quality_report_json_structure(normalized_output: dict) -> None:
    """quality_report.json must contain the expected top-level keys and all 23 tables."""
    qr = normalized_output["quality_json"]
    assert "dataset" in qr
    assert "total_tables" in qr
    assert "tables" in qr
    assert qr["dataset"] == "dataset_c"
    assert qr["total_tables"] == len(SCHEMAS)
    for name in SCHEMAS:
        assert name in qr["tables"], f"quality_report.json missing table '{name}'"


def test_quality_report_json_table_fields(normalized_output: dict) -> None:
    """Every table entry in quality_report.json must have the required stat fields."""
    qr = normalized_output["quality_json"]
    required_fields = {
        "table_name",
        "status",
        "rows_read",
        "duplicates_removed",
        "rows_output",
    }
    for name, entry in qr["tables"].items():
        missing = required_fields - entry.keys()
        assert not missing, f"Table '{name}' missing fields: {missing}"


# ---------------------------------------------------------------------------
# 6. quality_report.md
# ---------------------------------------------------------------------------


def test_quality_report_md_created(normalized_output: dict) -> None:
    """quality_report.md must exist and start with the expected Markdown header."""
    md = normalized_output["quality_md"]
    assert md.startswith("# Data Normalization Quality Report: dataset_c"), (
        f"Unexpected quality_report.md header: {md[:80]!r}"
    )


def test_quality_report_md_contains_all_tables(normalized_output: dict) -> None:
    """quality_report.md must mention every canonical table name."""
    md = normalized_output["quality_md"]
    for name in SCHEMAS:
        assert name in md, f"quality_report.md missing table '{name}'"


# ---------------------------------------------------------------------------
# 7. Deduplication
# ---------------------------------------------------------------------------


def test_ad_group_membership_deduplication(normalized_output: dict) -> None:
    """AD_GroupMembership fixture has 2 raw rows; 1 exact duplicate must be removed."""
    reporter: QualityReporter = normalized_output["reporter"]
    t = reporter.tables["AD_GroupMembership"]
    assert t.duplicates_removed == 1, (
        f"Expected 1 duplicate removed from AD_GroupMembership, got {t.duplicates_removed}"
    )
    assert t.rows_output == 1


def test_aws_user_groups_deduplication(normalized_output: dict) -> None:
    """AWS_UserGroups fixture has 3 raw rows with 1 exact duplicate; expect 2 output rows."""
    reporter: QualityReporter = normalized_output["reporter"]
    t = reporter.tables["AWS_UserGroups"]
    assert t.duplicates_removed == 1, (
        f"Expected 1 duplicate removed from AWS_UserGroups, got {t.duplicates_removed}"
    )
    assert t.rows_output == 2


# ---------------------------------------------------------------------------
# 8. account_type labelling
# ---------------------------------------------------------------------------


def test_ad_service_account_labelled(normalized_output: dict) -> None:
    """svc-deploy-001 is in service_account_inventory.csv (AD) → account_type must be 'service'."""
    df = normalized_output["tables"]["AD_Users"]
    svc_rows = df[df["sam_account_name"] == "svc-deploy-001"]
    assert len(svc_rows) == 1, "svc-deploy-001 not found in AD_Users output"
    assert svc_rows.iloc[0]["account_type"] == "service"


def test_ad_human_accounts_labelled(normalized_output: dict) -> None:
    """asmith and bjones are not in the AD service inventory → account_type must be 'human'."""
    df = normalized_output["tables"]["AD_Users"]
    for sam in ("asmith", "bjones"):
        rows = df[df["sam_account_name"] == sam]
        assert len(rows) == 1, f"{sam} not found in AD_Users output"
        assert rows.iloc[0]["account_type"] == "human", (
            f"{sam} should be 'human', got '{rows.iloc[0]['account_type']}'"
        )


def test_no_orphan_account_type(normalized_output: dict) -> None:
    """Normalization must never label any account 'orphan'. That is the resolver's job."""
    for name in ("AD_Users", "AWS_Users", "Okta_Users"):
        df = normalized_output["tables"].get(name, pd.DataFrame())
        if df.empty:
            continue
        col = "account_id" if name != "Okta_Users" else "okta_id"
        type_col = "account_type"
        if type_col in df.columns:
            orphans = df[df[type_col] == "orphan"]
            assert orphans.empty, (
                f"{name} contains rows labelled 'orphan': {orphans[[col, type_col]].to_dict()}"
            )


# ---------------------------------------------------------------------------
# 9. Nullable fields — intentionally null in source
# ---------------------------------------------------------------------------


def test_hr_offboarding_all_platforms_revoked_null(normalized_output: dict) -> None:
    """all_platforms_revoked is not in Dataset C source → must be null and in columns_unavailable."""
    df = normalized_output["tables"]["HR_Offboarding"]
    assert "all_platforms_revoked" in df.columns
    assert df["all_platforms_revoked"].isna().all(), (
        "all_platforms_revoked must be fully null (not in source)"
    )
    reporter: QualityReporter = normalized_output["reporter"]
    t = reporter.tables["HR_Offboarding"]
    assert "all_platforms_revoked" in t.columns_unavailable, (
        "all_platforms_revoked must be listed in columns_unavailable"
    )


def test_okta_users_created_at_null(normalized_output: dict) -> None:
    """Okta created_at is not in Dataset C source → must be null and in columns_unavailable."""
    df = normalized_output["tables"]["Okta_Users"]
    assert df["created_at"].isna().all(), "Okta_Users.created_at must be fully null"
    reporter: QualityReporter = normalized_output["reporter"]
    t = reporter.tables["Okta_Users"]
    assert "created_at" in t.columns_unavailable


def test_okta_admin_roles_assigned_at_null(normalized_output: dict) -> None:
    """Okta_AdminRoles.assigned_at is not in source → must be null and in columns_unavailable."""
    df = normalized_output["tables"]["Okta_AdminRoles"]
    assert df["assigned_at"].isna().all(), "Okta_AdminRoles.assigned_at must be fully null"
    reporter: QualityReporter = normalized_output["reporter"]
    t = reporter.tables["Okta_AdminRoles"]
    assert "assigned_at" in t.columns_unavailable


def test_exceptions_revocation_confirmed_null(normalized_output: dict) -> None:
    """Exceptions.revocation_confirmed is not in source → must be null."""
    df = normalized_output["tables"]["Exceptions"]
    assert df["revocation_confirmed"].isna().all(), (
        "Exceptions.revocation_confirmed must be fully null (not in source)"
    )


# ---------------------------------------------------------------------------
# 10. Audit Events fallback ID for unknown accounts
# ---------------------------------------------------------------------------


def test_audit_events_fallback_id_for_unknown_account(normalized_output: dict) -> None:
    """'ghostuser' has no match in any platform directory → fallback ID must be non-null
    and must follow the PLATFORM-UNK-{hash} pattern."""
    df = normalized_output["tables"]["Audit_Events"]
    ghost_rows = df[df["username"] == "ghostuser"]
    assert len(ghost_rows) == 1, "Expected 1 audit event for 'ghostuser'"
    acc_id = ghost_rows.iloc[0]["account_id"]
    assert acc_id is not None and str(acc_id) != ""
    # Fallback IDs follow pattern like "OKTA-UNK-xxxxxx" or "AD-UNK-xxxxxx"
    assert "UNK" in str(acc_id).upper(), (
        f"Fallback ID for unknown account should contain 'UNK', got '{acc_id}'"
    )


def test_audit_events_known_accounts_resolved(normalized_output: dict) -> None:
    """asmith's audit events must have a canonical account_id (not a fallback ID)."""
    df = normalized_output["tables"]["Audit_Events"]
    asmith_rows = df[df["username"] == "asmith"]
    assert len(asmith_rows) == 2, "Expected 2 audit events for 'asmith'"
    for acc_id in asmith_rows["account_id"]:
        assert acc_id is not None and str(acc_id) != ""
        # Canonical IDs don't contain UNK
        assert "UNK" not in str(acc_id).upper(), (
            f"asmith should have a canonical ID, not a fallback: '{acc_id}'"
        )


# ---------------------------------------------------------------------------
# 11. Date normalisation sanity checks
# ---------------------------------------------------------------------------


def test_hr_records_hire_date_is_datetime(normalized_output: dict) -> None:
    """hire_date must be parsed to datetime64[ns] (UTC-naive) with no NaTs for active employees."""
    df = normalized_output["tables"]["HR_Records"]
    assert pd.api.types.is_datetime64_any_dtype(df["hire_date"])
    # Both rows in fixture have valid hire_dates
    assert df["hire_date"].notna().all()


def test_ad_users_created_at_is_datetime(normalized_output: dict) -> None:
    """AD_Users.created_at must be datetime64[ns]."""
    df = normalized_output["tables"]["AD_Users"]
    assert pd.api.types.is_datetime64_any_dtype(df["created_at"])


def test_audit_events_timestamp_is_datetime(normalized_output: dict) -> None:
    """Audit_Events.timestamp must be datetime64[ns]."""
    df = normalized_output["tables"]["Audit_Events"]
    assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])
    assert df["timestamp"].notna().all()


# ---------------------------------------------------------------------------
# 12. Boolean normalisation
# ---------------------------------------------------------------------------


def test_ad_users_enabled_is_boolean(normalized_output: dict) -> None:
    """AD_Users.enabled must be boolean dtype."""
    df = normalized_output["tables"]["AD_Users"]
    assert str(df["enabled"].dtype) in ("boolean", "bool"), (
        f"AD_Users.enabled must be boolean, got {df['enabled'].dtype}"
    )
    # asmith -> NORMAL_ACCOUNT -> enabled=True; bjones -> ACCOUNTDISABLE -> False
    asmith = df[df["sam_account_name"] == "asmith"].iloc[0]
    bjones = df[df["sam_account_name"] == "bjones"].iloc[0]
    assert bool(asmith["enabled"]) is True
    assert bool(bjones["enabled"]) is False


# ---------------------------------------------------------------------------
# 13. Schema column completeness
# ---------------------------------------------------------------------------


def test_all_required_columns_present(normalized_output: dict) -> None:
    """Every required column defined in the schema must exist in the output DataFrame."""
    for table_name, schema in SCHEMAS.items():
        df = normalized_output["tables"].get(table_name)
        if df is None:
            pytest.fail(f"{table_name}.parquet was not produced")
        for col_name in schema.columns:
            assert col_name in df.columns, (
                f"{table_name}: required column '{col_name}' missing from output"
            )


# ---------------------------------------------------------------------------
# 14. HR status and worker_type mapping
# ---------------------------------------------------------------------------


def test_hr_records_status_mapping(normalized_output: dict) -> None:
    """HR status values must be mapped to canonical vocabulary (active / terminated / on_leave)."""
    df = normalized_output["tables"]["HR_Records"]
    allowed = {"active", "terminated", "on_leave"}
    bad = df[~df["status"].isin(allowed)]["status"].unique().tolist()
    assert not bad, f"Non-canonical HR status values found: {bad}"


def test_hr_records_worker_type_mapping(normalized_output: dict) -> None:
    """HR worker_type must be mapped to 'employee' or 'contractor'."""
    df = normalized_output["tables"]["HR_Records"]
    allowed = {"employee", "contractor"}
    bad = df[~df["worker_type"].isin(allowed)]["worker_type"].unique().tolist()
    assert not bad, f"Non-canonical worker_type values found: {bad}"


# ---------------------------------------------------------------------------
# 15. Tier normalisation
# ---------------------------------------------------------------------------


def test_ad_groups_tier_range(normalized_output: dict) -> None:
    """AD_Groups.declared_tier must be an integer in [0, 3]."""
    df = normalized_output["tables"]["AD_Groups"]
    assert df["declared_tier"].between(0, 3).all(), (
        f"AD_Groups tiers out of range: {df['declared_tier'].unique()}"
    )


def test_aws_policies_tier_range(normalized_output: dict) -> None:
    """AWS_Policies.declared_tier must be an integer in [0, 3]."""
    df = normalized_output["tables"]["AWS_Policies"]
    assert df["declared_tier"].between(0, 3).all()


# ---------------------------------------------------------------------------
# 16. Deterministic IDs — stable across repeated runs
# ---------------------------------------------------------------------------


def test_deterministic_ids_stable(normalized_output: dict) -> None:
    """Running the normalizer twice on the same fixtures must produce identical id_map.csv."""
    with tempfile.TemporaryDirectory() as tmp2:
        out2 = Path(tmp2)
        normalize_dataset_c(FIXTURES_DIR, out2)
        id_map2 = pd.read_csv(out2 / "id_map.csv")

    id_map1 = normalized_output["id_map"]
    merged = id_map1.merge(id_map2, on=["platform", "source_identifier"], suffixes=("_1", "_2"))
    mismatch = merged[merged["canonical_account_id_1"] != merged["canonical_account_id_2"]]
    assert mismatch.empty, (
        f"Deterministic IDs differ across runs:\n{mismatch[['platform', 'source_identifier', 'account_id_1', 'account_id_2']].to_string()}"
    )


# ---------------------------------------------------------------------------
# 17. Okta group ID → group name resolution
# ---------------------------------------------------------------------------


def test_okta_group_membership_uses_names(normalized_output: dict) -> None:
    """Okta_GroupMembership must store human-readable group names, not raw IDs like 'grp-dev'."""
    df = normalized_output["tables"]["Okta_GroupMembership"]
    # Raw group IDs in fixture: grp-admin, grp-dev
    # Resolved names: Okta-Admins, Developers
    raw_ids = {"grp-admin", "grp-dev", "grp-read", "grp-app"}
    group_names = set(df["group_name"].astype(str))
    overlap = raw_ids & group_names
    assert not overlap, f"Okta_GroupMembership contains raw group IDs (should be names): {overlap}"


# ---------------------------------------------------------------------------
# 18. OnCall_Roster time window parsing
# ---------------------------------------------------------------------------


def test_oncall_roster_shift_dates_parsed(normalized_output: dict) -> None:
    """OnCall_Roster shift_start and shift_end must be datetime64[ns]."""
    df = normalized_output["tables"]["OnCall_Roster"]
    assert pd.api.types.is_datetime64_any_dtype(df["shift_start"])
    assert pd.api.types.is_datetime64_any_dtype(df["shift_end"])
    assert df["shift_start"].notna().all()
    assert df["shift_end"].notna().all()


# ---------------------------------------------------------------------------
# 19. Scheduled Jobs → service account linking
# ---------------------------------------------------------------------------


def test_scheduled_jobs_linked_to_service_account(normalized_output: dict) -> None:
    """Scheduled_Jobs.service_account_id must resolve to a known SVC ID from inventory."""
    df = normalized_output["tables"]["Scheduled_Jobs"]
    # Fixture: job_name=svc-deploy-001-job → strips -job → svc-deploy-001 → SVC0001
    assert len(df) == 1
    assert df.iloc[0]["service_account_id"] == "SVC0001", (
        f"Expected SVC0001, got '{df.iloc[0]['service_account_id']}'"
    )


# ---------------------------------------------------------------------------
# 20. Exceptions status mapping
# ---------------------------------------------------------------------------


def test_exceptions_status_mapping(normalized_output: dict) -> None:
    """Exceptions status must be mapped to 'active', 'expired', or 'revoked'."""
    df = normalized_output["tables"]["Exceptions"]
    allowed = {"active", "expired", "revoked"}
    bad = df[~df["status"].isin(allowed)]["status"].unique().tolist()
    assert not bad, f"Non-canonical Exceptions.status values: {bad}"
    # Fixture has APPROVED → active
    assert "active" in df["status"].values
