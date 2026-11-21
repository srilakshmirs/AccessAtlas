#!/usr/bin/env python3
"""CLI utility to normalize raw identity datasets into canonical AccessAtlas tables.

Usage
-----
python scripts/normalize_data.py --dataset c --input data/external/dataset_c --output data/normalized/dataset_c
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from accessatlas.normalization.common import load_normalization_config
from accessatlas.normalization.pipeline import normalize_dataset


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Normalize raw identity and access exports into canonical AccessAtlas Parquet tables."
    )
    parser.add_argument(
        "--dataset",
        "-d",
        required=True,
        choices=["c", "dataset_c", "a", "dataset_a"],
        help="Dataset identifier to normalize (e.g. 'c' or 'a').",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        default=None,
        help="Directory containing raw export files. Defaults to data/external/<dataset>.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Output directory for normalized Parquet tables. Defaults to data/normalized/<dataset>.",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=None,
        help="Path to normalization.yaml configuration file.",
    )
    return parser.parse_args()


def main() -> int:
    """Execute normalization CLI."""
    args = parse_args()
    cfg = load_normalization_config(args.config)

    ds_key = args.dataset.lower()
    full_name = "dataset_c" if ds_key in ("c", "dataset_c") else "dataset_a"

    input_dir = args.input or Path(f"data/external/{full_name}")
    output_dir = args.output or Path(f"data/normalized/{full_name}")

    if not input_dir.is_dir():
        print(f"Error: Raw dataset directory '{input_dir}' not found.", file=sys.stderr)
        return 1

    print(f"Normalizing {full_name}...")
    print(f"  Input:  {input_dir}")
    print(f"  Output: {output_dir}")

    try:
        reporter = normalize_dataset(
            dataset=full_name,
            input_dir=input_dir,
            output_dir=output_dir,
            config=cfg,
        )
    except Exception as exc:
        print(f"Normalization failed: {exc}", file=sys.stderr)
        raise

    print("\nNormalization Complete:")
    print("-" * 75)
    print(f"{'Table':<25} {'Status':<12} {'Read':<10} {'Dedup':<8} {'Output':<10}")
    print("-" * 75)
    for name, stats in sorted(reporter.tables.items()):
        print(
            f"{name:<25} {stats.status:<12} {stats.rows_read:<10} "
            f"{stats.duplicates_removed:<8} {stats.rows_output:<10}"
        )
    print("-" * 75)
    print(f"Quality report and id_map.csv written to: {output_dir}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
