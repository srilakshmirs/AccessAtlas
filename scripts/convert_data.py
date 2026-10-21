#!/usr/bin/env python3
"""Convert XLSX source files to Parquet and (optionally) generate a fixture sample.

Usage
-----
  # Convert everything (run once before first use):
  python scripts/convert_data.py

  # Also generate tests/fixtures/ for CI (run once after first conversion):
  python scripts/convert_data.py --fixture

  # Re-run with verbose output:
  python scripts/convert_data.py --fixture --verbose

The script is intentionally idempotent: re-running overwrites existing Parquet
files.  The --fixture flag also overwrites existing fixture files.

WHY Parquet?  The two events files are ~32 MB of XLSX (~372 k rows).  XLSX is
read row-by-row by openpyxl; Parquet is columnar and memory-mapped.  Measured
load times on this machine are recorded at the end of this script's output.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

import pandas as pd
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Bootstrap: make `accessatlas` importable when running from the repo root
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent))

from accessatlas.ingestion.cleaning import CLEANERS  # noqa: E402
from accessatlas.ingestion.schemas import SCHEMAS  # noqa: E402
from accessatlas.utils import load_config, setup_logging  # noqa: E402

logger = logging.getLogger(__name__)

# Sheet names to skip entirely (documentation only)
_SKIP_SHEETS = {"README"}

# GT_ sheets must ONLY be handled by evaluation; the converter skips them for
# processed/ output but writes them to a separate gt/ subdirectory so the
# evaluation module can load them as Parquet too.
_GT_PREFIX = "GT_"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--fixture",
        action="store_true",
        help="After conversion, generate tests/fixtures/ with a small sample.",
    )
    p.add_argument(
        "--fixture-size",
        type=int,
        default=None,
        help="Number of HR employees in the fixture (default: from config.yaml).",
    )
    p.add_argument("--verbose", action="store_true", help="Enable DEBUG logging.")
    return p.parse_args()


def _write_parquet(df: pd.DataFrame, path: Path) -> None:
    """Write a DataFrame to Parquet, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(path, index=False, engine="pyarrow")


def convert_core(raw_dir: Path, processed_dir: Path) -> dict[str, pd.DataFrame]:
    """Read every non-GT, non-README sheet from the core XLSX, clean, validate,
    and write to data/processed/core/<SheetName>.parquet.

    GT_ sheets are written to data/processed/gt/ and skipped from the main
    processed/ output.

    Returns a dict of sheet_name → cleaned DataFrame for later fixture use.
    """
    core_file = raw_dir / "AccessAtlas_Dataset_Core.xlsx"
    logger.info("Opening core XLSX: %s", core_file)

    xl = pd.ExcelFile(core_file, engine="openpyxl")
    sheet_names = [s for s in xl.sheet_names if s not in _SKIP_SHEETS]

    core_dfs: dict[str, pd.DataFrame] = {}

    for sheet in tqdm(sheet_names, desc="Core sheets", unit="sheet"):
        logger.debug("  Reading sheet: %s", sheet)
        df = xl.parse(sheet)

        # Apply cleaning rules if we have them for this sheet.
        cleaner = CLEANERS.get(sheet)
        if cleaner:
            df = cleaner(df)

        is_gt = sheet.startswith(_GT_PREFIX)
        if is_gt:
            # GT sheets go to a separate directory; not part of processed/core/
            out_path = processed_dir / "gt" / f"{sheet}.parquet"
        else:
            out_path = processed_dir / "core" / f"{sheet}.parquet"
            # Validate non-GT sheets before writing.
            if sheet in SCHEMAS:
                try:
                    SCHEMAS[sheet].validate(df, lazy=True)
                    logger.debug("  Schema OK: %s", sheet)
                except Exception as exc:
                    logger.warning("  Schema warning for %s: %s", sheet, exc)

        _write_parquet(df, out_path)
        logger.debug("  Written: %s (%d rows)", out_path.name, len(df))

        if not is_gt:
            core_dfs[sheet] = df

    logger.info("Core conversion done: %d non-GT sheets written.", len(core_dfs))
    return core_dfs


def convert_events(raw_dir: Path, processed_dir: Path) -> pd.DataFrame:
    """Concatenate both events XLSX files and write a single Parquet file.

    WHY one file: downstream queries always need the full event history; split
    files would require callers to remember to load both.
    """
    event_files = [
        raw_dir / "AccessAtlas_Dataset_Events_Part1.xlsx",
        raw_dir / "AccessAtlas_Dataset_Events_Part2.xlsx",
    ]
    parts: list[pd.DataFrame] = []
    for ef in tqdm(event_files, desc="Event files", unit="file"):
        logger.info("Reading events: %s", ef.name)
        df = pd.read_excel(ef, sheet_name="Audit_Events", engine="openpyxl")
        from accessatlas.ingestion.cleaning import clean_audit_events

        df = clean_audit_events(df)
        parts.append(df)
        logger.info("  %s: %d rows", ef.name, len(df))

    events = pd.concat(parts, ignore_index=True)
    logger.info("Total events after concat: %d rows", len(events))

    # Schema validation on the combined frame
    if "Audit_Events" in SCHEMAS:
        try:
            SCHEMAS["Audit_Events"].validate(events, lazy=True)
            logger.info("Audit_Events schema OK")
        except Exception as exc:
            logger.warning("Audit_Events schema warning: %s", exc)

    out_path = processed_dir / "events" / "Audit_Events.parquet"
    _write_parquet(events, out_path)
    logger.info("Events written to %s", out_path)
    return events


def generate_fixture(
    core_dfs: dict[str, pd.DataFrame],
    events_df: pd.DataFrame,
    fixture_dir: Path,
    sample_size: int,
) -> None:
    """Create a small but referentially consistent sample for CI tests.

    Strategy
    --------
    1. Sample `sample_size` employee_ids from HR_Records (seed=42 for
       reproducibility).
    2. For tables with a direct employee_id column, filter to those IDs.
    3. For platform user tables without direct employee_id (AWS_Users has
       tag_employee_id; Okta_Users has employee_number), use those FK columns.
    4. For membership/association tables, include rows for the platform
       accounts that were kept in step 3.
    5. For reference tables (Tier_Mapping, AWS_Policies, AD_Groups, etc.)
       include everything — they are small and needed for graph traversal.
    6. For Audit_Events, keep events whose account_id or username matches any
       platform account in the sample.

    WHY seed=42: reproducible fixture so CI does not silently break when
    the fixture changes on re-generation.
    """
    fixture_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Generating fixture (%d employees, seed=42) → %s", sample_size, fixture_dir)

    hr = core_dfs["HR_Records"]
    sample_eids = set(
        hr.sample(n=min(sample_size, len(hr)), random_state=42)["employee_id"].tolist()
    )
    logger.info("  Sampled %d employee_ids", len(sample_eids))

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------
    def _keep(df: pd.DataFrame, col: str, values: set) -> pd.DataFrame:
        """Keep rows where df[col] is in values; return all rows if col missing."""
        if col not in df.columns:
            return df
        return df[df[col].isin(values)]

    def _save(name: str, df: pd.DataFrame) -> None:
        path = fixture_dir / f"{name}.parquet"
        df.to_parquet(path, index=False, engine="pyarrow")
        logger.info("  fixture/%s.parquet: %d rows", name, len(df))

    # ------------------------------------------------------------------
    # HR tables
    # ------------------------------------------------------------------
    hr_sample = _keep(hr, "employee_id", sample_eids)
    _save("HR_Records", hr_sample)
    _save(
        "HR_RoleChanges",
        _keep(core_dfs.get("HR_RoleChanges", pd.DataFrame()), "employee_id", sample_eids),
    )
    _save(
        "HR_Offboarding",
        _keep(core_dfs.get("HR_Offboarding", pd.DataFrame()), "employee_id", sample_eids),
    )

    # ------------------------------------------------------------------
    # AD
    # ------------------------------------------------------------------
    ad_users_sample = _keep(core_dfs.get("AD_Users", pd.DataFrame()), "employee_id", sample_eids)
    ad_account_ids = (
        set(ad_users_sample["account_id"].tolist())
        if "account_id" in ad_users_sample.columns
        else set()
    )
    ad_sam_names = (
        set(ad_users_sample["sam_account_name"].tolist())
        if "sam_account_name" in ad_users_sample.columns
        else set()
    )
    _save("AD_Users", ad_users_sample)
    # Keep all groups (small) so membership checks work
    _save("AD_Groups", core_dfs.get("AD_Groups", pd.DataFrame()))
    # Keep membership rows for our sampled AD accounts
    ad_gm = core_dfs.get("AD_GroupMembership", pd.DataFrame())
    ad_gm_sample = (
        ad_gm[ad_gm["member"].isin(ad_sam_names) | ad_gm["member_type"].eq("group")]
        if not ad_gm.empty
        else ad_gm
    )
    _save("AD_GroupMembership", ad_gm_sample)

    # ------------------------------------------------------------------
    # AWS
    # ------------------------------------------------------------------
    aws_users = core_dfs.get("AWS_Users", pd.DataFrame())
    aws_users_sample = _keep(aws_users, "tag_employee_id", sample_eids)
    aws_user_ids = (
        set(aws_users_sample["user_id"].tolist())
        if "user_id" in aws_users_sample.columns
        else set()
    )
    _save("AWS_Users", aws_users_sample)
    _save("AWS_Groups", core_dfs.get("AWS_Groups", pd.DataFrame()))  # small reference table
    _save("AWS_Policies", core_dfs.get("AWS_Policies", pd.DataFrame()))  # small reference table
    _save(
        "AWS_UserGroups",
        _keep(core_dfs.get("AWS_UserGroups", pd.DataFrame()), "user_id", aws_user_ids),
    )
    _save("AWS_PolicyAttach", core_dfs.get("AWS_PolicyAttach", pd.DataFrame()))  # keep all (small)

    # ------------------------------------------------------------------
    # Okta
    # ------------------------------------------------------------------
    okta_users = core_dfs.get("Okta_Users", pd.DataFrame())
    okta_users_sample = _keep(okta_users, "employee_number", sample_eids)
    okta_ids = (
        set(okta_users_sample["okta_id"].tolist())
        if "okta_id" in okta_users_sample.columns
        else set()
    )
    _save("Okta_Users", okta_users_sample)
    _save("Okta_Groups", core_dfs.get("Okta_Groups", pd.DataFrame()))
    _save(
        "Okta_GroupMembership",
        _keep(core_dfs.get("Okta_GroupMembership", pd.DataFrame()), "okta_id", okta_ids),
    )
    _save(
        "Okta_AdminRoles",
        _keep(core_dfs.get("Okta_AdminRoles", pd.DataFrame()), "okta_id", okta_ids),
    )
    _save("Okta_Apps", _keep(core_dfs.get("Okta_Apps", pd.DataFrame()), "okta_id", okta_ids))
    _save("Okta_AWS_Federation", core_dfs.get("Okta_AWS_Federation", pd.DataFrame()))  # small

    # ------------------------------------------------------------------
    # Reference / context tables (include in full — all are small)
    # ------------------------------------------------------------------
    _save("Tier_Mapping", core_dfs.get("Tier_Mapping", pd.DataFrame()))
    _save(
        "API_Tokens", _keep(core_dfs.get("API_Tokens", pd.DataFrame()), "identity_id", sample_eids)
    )
    _save(
        "Exceptions", _keep(core_dfs.get("Exceptions", pd.DataFrame()), "employee_id", sample_eids)
    )
    _save(
        "OnCall_Roster",
        _keep(core_dfs.get("OnCall_Roster", pd.DataFrame()), "employee_id", sample_eids),
    )
    _save(
        "Scheduled_Jobs",
        _keep(core_dfs.get("Scheduled_Jobs", pd.DataFrame()), "owner_employee_id", sample_eids),
    )

    # ------------------------------------------------------------------
    # Events — keep those whose account_id or username matches sample accounts
    # ------------------------------------------------------------------
    all_account_ids = ad_account_ids | aws_user_ids | okta_ids
    # Also include okta login/email as username in events
    okta_logins = (
        set(okta_users_sample["login"].tolist()) if "login" in okta_users_sample.columns else set()
    )

    ev_mask = events_df["account_id"].isin(all_account_ids) | events_df["username"].isin(
        ad_sam_names | okta_logins
    )
    events_sample = events_df[ev_mask].copy()
    _save("Audit_Events", events_sample)

    logger.info("Fixture generation complete.")


def measure_load_times(processed_dir: Path, fixture_dir: Path) -> None:
    """Measure and log actual Parquet vs fixture load times.

    WHY: The docs/decisions/ADR-001 cites load-time difference as the reason
    for converting to Parquet. We report the measured figures, not estimates.
    """
    events_parquet = processed_dir / "events" / "Audit_Events.parquet"
    fixture_events = fixture_dir / "Audit_Events.parquet"

    if events_parquet.exists():
        t0 = time.perf_counter()
        df = pd.read_parquet(events_parquet)
        elapsed = time.perf_counter() - t0
        logger.info("TIMING — Audit_Events Parquet (%d rows): %.3f s", len(df), elapsed)

    if fixture_events.exists():
        t0 = time.perf_counter()
        df2 = pd.read_parquet(fixture_events)
        elapsed2 = time.perf_counter() - t0
        logger.info("TIMING — Audit_Events fixture  (%d rows): %.3f s", len(df2), elapsed2)


def main() -> None:
    args = _parse_args()
    setup_logging("DEBUG" if args.verbose else "INFO")

    cfg = load_config()
    raw_dir = Path(cfg["paths"]["raw"])
    processed_dir = Path(cfg["paths"]["processed"])
    fixture_dir = Path(cfg["paths"]["fixtures"])
    sample_size = args.fixture_size or cfg["ingestion"]["fixture_sample_size"]

    # ------------------------------------------------------------------
    # Step 1: Convert core XLSX
    # ------------------------------------------------------------------
    logger.info("=== Step 1: Converting core XLSX ===")
    core_dfs = convert_core(raw_dir, processed_dir)

    # ------------------------------------------------------------------
    # Step 2: Convert events XLSX (slow — ~32 MB of spreadsheet data)
    # ------------------------------------------------------------------
    logger.info("=== Step 2: Converting events XLSX ===")
    events_df = convert_events(raw_dir, processed_dir)

    # ------------------------------------------------------------------
    # Step 3 (optional): Generate fixture for CI tests
    # ------------------------------------------------------------------
    if args.fixture:
        logger.info("=== Step 3: Generating CI fixture ===")
        generate_fixture(core_dfs, events_df, fixture_dir, sample_size)
        measure_load_times(processed_dir, fixture_dir)

    logger.info("All done. Processed data is in: %s", processed_dir.resolve())


if __name__ == "__main__":
    main()
