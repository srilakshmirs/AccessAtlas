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
from accessatlas.normalization.dataset_c import normalize_dataset_c
from accessatlas.normalization.pipeline import normalize_dataset
from accessatlas.normalization.reporter import QualityReporter, TableQualityStats

__all__ = [
    "DeterministicIdGenerator",
    "QualityReporter",
    "TableQualityStats",
    "deduplicate_rows",
    "load_normalization_config",
    "normalize_boolean",
    "normalize_categorical",
    "normalize_dataset",
    "normalize_dataset_c",
    "normalize_datetime",
    "normalize_email",
    "normalize_missing",
    "normalize_name",
    "normalize_tier",
    "normalize_whitespace",
    "parse_time_window",
]
