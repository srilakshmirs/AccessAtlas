"""Common normalizers, cleaners, and deterministic ID generators.

Transforms raw values into canonical types and formats matching the schemas in
accessatlas/ingestion/schemas.py.
"""

from __future__ import annotations

import csv
import hashlib
import re
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml

DEFAULT_MISSING_MARKERS: frozenset[str] = frozenset(
    {"n/a", "na", "n.a.", "none", "null", "-", "", "undefined", "nan"}
)

DEFAULT_BOOLEAN_MAP: dict[str, bool] = {
    "true": True,
    "false": False,
    "1": True,
    "0": False,
    "yes": True,
    "no": False,
    "y": True,
    "n": False,
    "t": True,
    "f": False,
}


def load_normalization_config(config_path: Path | str | None = None) -> dict[str, Any]:
    """Load configuration from config/normalization.yaml."""
    if config_path is None:
        # Default to repo root config/normalization.yaml
        config_path = Path(__file__).resolve().parents[2] / "config" / "normalization.yaml"
    path = Path(config_path)
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def normalize_missing(
    series: pd.Series, markers: frozenset[str] | set[str] | None = None
) -> tuple[pd.Series, int]:
    """Replace missing value representations with pd.NA or np.nan.

    Returns the cleaned series and the count of cells transformed into null.
    """
    if markers is None:
        markers = DEFAULT_MISSING_MARKERS

    # Fast path: check string representation
    str_series = series.astype(str).str.strip().str.lower()
    mask_to_nullify = str_series.isin(markers) & series.notna()

    count = int(mask_to_nullify.sum())
    if count == 0:
        return series.copy(), 0

    res = series.copy()
    res[mask_to_nullify] = np.nan
    return res, count


def normalize_whitespace(series: pd.Series) -> tuple[pd.Series, int]:
    """Strip leading/trailing whitespace and collapse internal consecutive whitespace.

    Returns the cleaned series and the count of modified non-null entries.
    """

    def _collapse(val: Any) -> Any:
        if pd.isna(val) or not isinstance(val, str):
            return val
        collapsed = " ".join(val.split())
        return collapsed

    original = series.copy()
    res = series.map(_collapse)
    # Count where non-null value changed
    modified = ((original.notna()) & (res != original)).sum()
    return res, int(modified)


def normalize_email(series: pd.Series) -> tuple[pd.Series, int]:
    """Strip whitespace and lowercase email addresses.

    Returns the normalized series and count of modified emails.
    """
    cleaned, _ = normalize_missing(series)

    def _clean_email(val: Any) -> Any:
        if pd.isna(val) or not isinstance(val, str):
            return val
        clean_str = val.strip().lower()
        return clean_str if clean_str else np.nan

    res = cleaned.map(_clean_email)
    modified = ((cleaned.notna()) & (res != cleaned)).sum()
    return res, int(modified)


def normalize_name(series: pd.Series) -> tuple[pd.Series, int]:
    """Normalize person names with consistent title casing while preserving hyphenated names."""
    cleaned, _ = normalize_missing(series)

    def _format_name(val: Any) -> Any:
        if pd.isna(val) or not isinstance(val, str):
            return val
        clean_str = " ".join(val.split())
        if not clean_str:
            return np.nan
        words = clean_str.split()
        formatted_words = []
        for word in words:
            parts = word.split("-")
            formatted_words.append("-".join(p.capitalize() for p in parts))
        return " ".join(formatted_words)

    res = cleaned.map(_format_name)
    modified = ((cleaned.notna()) & (res != cleaned)).sum()
    return res, int(modified)


def normalize_boolean(
    series: pd.Series, boolean_map: dict[str, bool] | None = None
) -> tuple[pd.Series, int]:
    """Coerce boolean-like inputs to pandas nullable 'boolean' dtype.

    Supports TRUE/FALSE, true/false, YES/NO, Y/N, 1/0. Returns (series, count_converted).
    """
    if boolean_map is None:
        boolean_map = DEFAULT_BOOLEAN_MAP

    if series.dtype == "boolean":
        return series.copy(), 0

    # If already native python bool or int
    def _coerce_val(val: Any) -> Any:
        if pd.isna(val):
            return pd.NA
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float, np.integer, np.floating)):
            if np.isnan(val):
                return pd.NA
            return bool(int(val))
        val_str = str(val).strip().lower()
        if val_str in boolean_map:
            return boolean_map[val_str]
        return pd.NA

    original = series.copy()
    res = series.map(_coerce_val).astype("boolean")
    # Count converted non-null values
    converted = (original.notna() & res.notna()).sum()
    return res, int(converted)


def normalize_datetime(
    series: pd.Series,
    date_formats: list[str] | None = None,
    epoch_unit: str = "s",
) -> tuple[pd.Series, int]:
    """Parse heterogeneous datetime strings, epoch timestamps, or dates into UTC naive datetime64[ns].

    Handles DD-MON-YYYY, MM/DD/YYYY HH:MM:SS, ISO 8601 with Z or timezone offset, and epoch numbers.
    Treats missing markers as NaT. Returns (series, count_valid_datetimes).
    """
    cleaned, _ = normalize_missing(series)
    parsed = pd.Series(pd.NaT, index=cleaned.index, dtype="datetime64[ns]")

    mask_notna = cleaned.notna()
    if not mask_notna.any():
        return parsed, 0

    to_parse = cleaned[mask_notna]

    # Attempt custom date_formats sequentially if provided
    if date_formats:
        for fmt in date_formats:
            unparsed = to_parse.index[parsed[to_parse.index].isna()]
            if len(unparsed) == 0:
                break
            attempt = pd.to_datetime(to_parse.loc[unparsed], format=fmt, errors="coerce", utc=True)
            valid = attempt.notna()
            if valid.any():
                parsed.loc[unparsed[valid]] = attempt[valid].dt.tz_localize(None)

    # Check for remaining unparsed entries
    unparsed = to_parse.index[parsed[to_parse.index].isna()]
    if len(unparsed) > 0:
        sub_series = to_parse.loc[unparsed]

        # Check for numeric or string digits (epochs)
        num_attempt = pd.to_numeric(sub_series, errors="coerce")
        num_mask = num_attempt.notna() & (num_attempt > 100000000)
        if num_mask.any():
            epoch_parsed = pd.to_datetime(
                num_attempt[num_mask], unit=epoch_unit, errors="coerce", utc=True
            )
            parsed.loc[sub_series.index[num_mask]] = epoch_parsed.dt.tz_localize(None)

        # Check remaining for ISO or flexible datetime
        still_unparsed = to_parse.index[parsed[to_parse.index].isna()]
        if len(still_unparsed) > 0:
            iso_attempt = pd.to_datetime(to_parse.loc[still_unparsed], errors="coerce", utc=True)
            valid_iso = iso_attempt.notna()
            if valid_iso.any():
                parsed.loc[still_unparsed[valid_iso]] = iso_attempt[valid_iso].dt.tz_localize(None)

    count_valid = int(parsed.notna().sum())
    return parsed, count_valid


def normalize_categorical(
    series: pd.Series,
    mapping: dict[str, Any],
    default: Any = pd.NA,
) -> tuple[pd.Series, int]:
    """Map categorical text values against standard vocabularies (case-insensitive).

    Returns (series, count_mapped).
    """
    clean_series, _ = normalize_missing(series)

    # Normalize keys in mapping to lower stripped strings
    norm_map = {str(k).strip().lower(): v for k, v in mapping.items()}

    def _mapper(val: Any) -> Any:
        if pd.isna(val):
            return default
        val_str = str(val).strip().lower()
        return norm_map.get(val_str, default)

    res = clean_series.map(_mapper)
    mapped_count = int((res.notna() & (res != default)).sum())
    return res, mapped_count


def normalize_tier(
    series: pd.Series,
    tier_mapping: dict[str, int] | None = None,
    min_tier: int = 0,
    max_tier: int = 3,
    no_access_tier: int = 9,
) -> tuple[pd.Series, int]:
    """Normalize privilege tier to canonical integer scale (0..3, and 9 for no access).

    Handles integer tiers directly or textual tiers using tier_mapping.
    """
    clean_series, _ = normalize_missing(series)

    norm_map = {}
    if tier_mapping:
        norm_map = {str(k).strip().lower(): v for k, v in tier_mapping.items()}

    def _map_tier(val: Any) -> Any:
        if pd.isna(val):
            return pd.NA
        # If integer or float
        if isinstance(val, (int, np.integer)):
            if min_tier <= val <= max_tier or val == no_access_tier:
                return int(val)
        val_str = str(val).strip().lower()
        if val_str in norm_map:
            return norm_map[val_str]
        # Check if digits in string
        if val_str.isdigit():
            v_int = int(val_str)
            if min_tier <= v_int <= max_tier or v_int == no_access_tier:
                return v_int
        # Try extracting digit from e.g. "tier 1", "tier-0"
        m = re.search(r"tier[\s\-_]*([0-39])", val_str)
        if m:
            return int(m.group(1))
        return pd.NA

    res = clean_series.map(_map_tier).astype("Int64")
    valid_count = int(res.notna().sum())
    return res, valid_count


def deduplicate_rows(df: pd.DataFrame, subset: list[str] | None = None) -> tuple[pd.DataFrame, int]:
    """Remove exact duplicate rows and return (deduped_df, duplicates_removed_count)."""
    initial_rows = len(df)
    deduped = df.drop_duplicates(subset=subset).copy()
    duplicates_removed = initial_rows - len(deduped)
    return deduped, duplicates_removed


def parse_time_window(series: pd.Series) -> tuple[pd.Series, pd.Series, int]:
    """Parse time window strings (e.g. '02:00-04:00 UTC' or '01:00 - 05:00') into window_start and window_end.

    Returns (start_series, end_series, parsed_count).
    """
    pattern = re.compile(r"(\d{1,2}:\d{2})\s*[-–]\s*(\d{1,2}:\d{2})")

    starts: list[str | None] = []
    ends: list[str | None] = []
    parsed_count = 0

    for val in series:
        if pd.isna(val) or not isinstance(val, str):
            starts.append(None)
            ends.append(None)
            continue
        m = pattern.search(val.strip())
        if m:
            s, e = m.group(1), m.group(2)
            # Ensure HH:MM two-digit format
            s_fmt = s if len(s.split(":")[0]) == 2 else f"0{s}"
            e_fmt = e if len(e.split(":")[0]) == 2 else f"0{e}"
            starts.append(s_fmt)
            ends.append(e_fmt)
            parsed_count += 1
        else:
            starts.append(None)
            ends.append(None)

    return pd.Series(starts, index=series.index), pd.Series(ends, index=series.index), parsed_count


class DeterministicIdGenerator:
    """Generates stable, unique, deterministic canonical account IDs.

    Maintains a record of all mappings and exports them to id_map.csv.
    """

    def __init__(self) -> None:
        # key: (platform, raw_id) -> canonical_id
        self.mapping: dict[tuple[str, str], str] = {}

    def get_or_generate_id(self, platform: str, raw_key: str, prefix: str | None = None) -> str:
        """Return existing mapped canonical ID or generate a stable deterministic ID."""
        key = (platform.lower(), str(raw_key).strip())
        if key in self.mapping:
            return self.mapping[key]

        # If raw_key already matches the expected canonical pattern, retain it
        raw_str = str(raw_key).strip()
        plat = platform.lower()

        if plat == "ad" and re.match(r"^AD-\d{6}$", raw_str):
            self.mapping[key] = raw_str
            return raw_str

        if plat == "aws" and re.match(r"^AWS-USR-\d{6}$", raw_str):
            self.mapping[key] = raw_str
            return raw_str

        # Generate deterministic 6-digit hex or integer derived from MD5 hash
        digest = hashlib.md5(f"{plat}:{raw_str}".encode()).hexdigest()
        numeric_id = int(digest[:8], 16) % 1000000

        if prefix is not None:
            canonical_id = f"{prefix}{numeric_id:06d}"
        elif plat == "ad":
            canonical_id = f"AD-{numeric_id:06d}"
        elif plat == "aws":
            canonical_id = f"AWS-USR-{numeric_id:06d}"
        elif plat == "okta":
            # Okta IDs typically start with 00u
            canonical_id = f"00u{digest[:17]}"
        else:
            canonical_id = f"{plat.upper()}-{numeric_id:06d}"

        self.mapping[key] = canonical_id
        return canonical_id

    def export_id_map(self, output_file: Path | str) -> Path:
        """Export the generated ID map to id_map.csv."""
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["platform", "source_identifier", "canonical_account_id"])
            for (platform, raw_id), canonical_id in sorted(self.mapping.items()):
                writer.writerow([platform, raw_id, canonical_id])

        return out_path
