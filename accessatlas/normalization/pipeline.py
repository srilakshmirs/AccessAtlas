"""Pipeline orchestrator for data normalization and validation.

Coordinates dataset-specific loaders, executes normalization rules, validates against
canonical schemas, and outputs quality reports.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from accessatlas.normalization.common import load_normalization_config
from accessatlas.normalization.dataset_c import normalize_dataset_c
from accessatlas.normalization.reporter import QualityReporter

logger = logging.getLogger(__name__)


def normalize_dataset(
    dataset: str,
    input_dir: Path | str,
    output_dir: Path | str,
    config: dict[str, Any] | None = None,
) -> QualityReporter:
    """Normalize a raw dataset by name.

    Parameters
    ----------
    dataset : str
        Dataset identifier (e.g. 'c', 'dataset_c', 'a', 'dataset_a').
    input_dir : Path or str
        Path to raw dataset folder.
    output_dir : Path or str
        Destination directory for canonical Parquet tables and quality reports.
    config : dict, optional
        Loaded configuration dictionary.

    Returns
    -------
    QualityReporter
        Reporter containing execution metrics and quality statistics.
    """
    cfg = config or load_normalization_config()
    ds_key = dataset.lower().strip()

    if ds_key in ("c", "dataset_c"):
        logger.info("Running normalization pipeline for Dataset C...")
        return normalize_dataset_c(input_dir, output_dir, config=cfg)
    elif ds_key in ("a", "dataset_a"):
        raise NotImplementedError("Dataset A normalizer will be implemented in Step 3.")
    else:
        raise ValueError(f"Unknown dataset '{dataset}'. Supported datasets: 'c', 'a'.")
