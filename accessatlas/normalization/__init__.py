"""Data Normalization and Validation package for AccessAtlas.

Standardizes heterogeneous raw identity and access exports into canonical tables
validated against pandera schemas.
"""

from __future__ import annotations

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
from accessatlas.normalization.reporter import QualityReporter, TableQualityStats

__all__ = [
    "DeterministicIdGenerator",
    "QualityReporter",
    "TableQualityStats",
    "deduplicate_rows",
    "load_normalization_config",
    "normalize_boolean",
    "normalize_categorical",
    "normalize_datetime",
    "normalize_email",
    "normalize_missing",
    "normalize_name",
    "normalize_tier",
    "normalize_whitespace",
    "parse_time_window",
]

