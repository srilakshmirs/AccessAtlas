"""Parquet loader — the runtime entry point for all downstream modules.

All code that needs data should call functions from this module rather than
reading files directly. This keeps path logic in one place.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd

from accessatlas.ingestion.schemas import SCHEMAS
from accessatlas.utils import load_config

if TYPE_CHECKING:
    import pandera.pandas as pa

logger = logging.getLogger(__name__)

# Tables whose Parquet files come from data/processed/core/
_CORE_TABLES = {
    "HR_Records",
    "HR_RoleChanges",
    "HR_Offboarding",
    "AD_Users",
    "AD_Groups",
    "AD_GroupMembership",
    "AWS_Users",
    "AWS_Groups",
    "AWS_Policies",
    "AWS_UserGroups",
    "AWS_PolicyAttach",
    "Okta_Users",
    "Okta_Groups",
    "Okta_GroupMembership",
    "Okta_AdminRoles",
    "Okta_Apps",
    "Okta_AWS_Federation",
    "Tier_Mapping",
    "API_Tokens",
    "Exceptions",
    "OnCall_Roster",
    "Scheduled_Jobs",
}

# Audit events live in data/processed/events/
_EVENTS_TABLE = "Audit_Events"


def _get_processed_root(config: dict | None = None) -> Path:
    """Return the root of the processed data directory from config."""
    if config is None:
        config = load_config()
    return Path(config["paths"]["processed"])


def load_table(
    table_name: str,
    *,
    config: dict | None = None,
    validate: bool = True,
    fixture_dir: Path | None = None,
) -> pd.DataFrame:
    """Load a single table from Parquet and optionally validate its schema.

    Parameters
    ----------
    table_name:
        Sheet/table name (e.g. 'HR_Records', 'Audit_Events').
    config:
        Parsed config dict. If None, loads from config.yaml in cwd.
    validate:
        If True, run the pandera schema check after loading.
    fixture_dir:
        If given, load from this directory instead of data/processed/.
        Used in tests to load the committed fixture files.
    """
    if fixture_dir is not None:
        parquet_path = fixture_dir / f"{table_name}.parquet"
    elif table_name == _EVENTS_TABLE:
        parquet_path = _get_processed_root(config) / "events" / f"{table_name}.parquet"
    else:
        parquet_path = _get_processed_root(config) / "core" / f"{table_name}.parquet"

    if not parquet_path.exists():
        raise FileNotFoundError(
            f"Parquet file not found: {parquet_path}. Run `python scripts/convert_data.py` first."
        )

    logger.debug("Loading %s from %s", table_name, parquet_path)
    df = pd.read_parquet(parquet_path)

    if validate and table_name in SCHEMAS:
        schema: pa.DataFrameSchema = SCHEMAS[table_name]
        try:
            df = schema.validate(df, lazy=True)
        except Exception as exc:
            # Re-raise with context so the error message names the table.
            raise ValueError(f"Schema validation failed for {table_name}: {exc}") from exc

    logger.info("Loaded %s: %d rows × %d cols", table_name, len(df), len(df.columns))
    return df


def load_all_core(
    *,
    config: dict | None = None,
    validate: bool = True,
    fixture_dir: Path | None = None,
) -> dict[str, pd.DataFrame]:
    """Load every core table and return them as a dict keyed by table name."""
    return {
        name: load_table(name, config=config, validate=validate, fixture_dir=fixture_dir)
        for name in sorted(_CORE_TABLES)
    }
