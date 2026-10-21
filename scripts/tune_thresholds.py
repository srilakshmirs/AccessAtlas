"""Tune identity resolution fuzzy matching threshold using TRAIN split only.

Meets the M2 requirements:
1. Calls functions in accessatlas/evaluation/ instead of reading GT files directly.
2. Reports how many train accounts are resolved by each signal and how many reach the fuzzy stage.
3. Sweeps the fuzzy threshold using train-split identities only.
4. Shows the full sweep table (threshold, precision, recall, F1).
5. Writes the chosen threshold to config.yaml.
6. Gives an error analysis on the train split.
7. Evaluates test and holdout splits ONCE using the chosen threshold.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import yaml

from accessatlas.evaluation import (
    evaluate_identity_resolution,
    load_gt_identity_data,
    tune_fuzzy_threshold,
)
from accessatlas.resolution.resolver import resolve_identities
from accessatlas.utils import load_config, setup_logging


def main() -> None:
    setup_logging()
    cfg = load_config()
    proc_dir = Path(cfg["paths"]["processed"])

    print("Loading core tables...")
    hr_df = pd.read_parquet(proc_dir / "core" / "HR_Records.parquet")
    ad_df = pd.read_parquet(proc_dir / "core" / "AD_Users.parquet")
    aws_df = pd.read_parquet(proc_dir / "core" / "AWS_Users.parquet")
    okta_df = pd.read_parquet(proc_dir / "core" / "Okta_Users.parquet")

    core_tables = {
        "HR_Records": hr_df,
        "AD_Users": ad_df,
        "AWS_Users": aws_df,
        "Okta_Users": okta_df,
    }

    print("Loading ground truth tables via accessatlas.evaluation...")
    gt_dir = proc_dir / "gt"
    gt_links, gt_labels = load_gt_identity_data(gt_dir)

    # --- Part 1: Report train accounts by signal and fuzzy stage count ---
    print("\n" + "=" * 70)
    print("PART 1: TRAIN SPLIT ACCOUNT SIGNALS & FUZZY STAGE READINESS")
    print("=" * 70)

    # Initial resolution with baseline to inspect signal counts on train
    baseline_res = resolve_identities(hr_df, ad_df, aws_df, okta_df, fuzzy_threshold=85.0)
    train_eval = evaluate_identity_resolution(
        baseline_res, gt_links, gt_labels, split="train", core_tables=core_tables
    )

    print(f"Total train GT identities: {train_eval.total_gt_identities}")
    print(f"Total train GT platform accounts: {train_eval.total_gt_accounts}")
    print("\nResolved accounts by signal on train (at baseline threshold 85):")
    for sig_name, sig_m in train_eval.by_signal.items():
        print(
            f"  - Signal '{sig_name:5}': {sig_m.count:5} accounts "
            f"(TP: {sig_m.tp:5}, FP: {sig_m.fp:5}, Precision: {sig_m.precision:.4f})"
        )

    # Accounts reaching fuzzy stage in train (AWS human with no tags)
    aws_train_gt = gt_links.merge(gt_labels[["identity_id", "split"]], on="identity_id", how="left")
    aws_train_ids = set(aws_train_gt[aws_train_gt["split"] == "train"]["aws_user_id"].dropna())
    aws_train_human_no_tags = aws_df[
        aws_df["user_id"].isin(aws_train_ids)
        & (aws_df["account_type"] == "human")
        & aws_df["tag_employee_id"].isna()
        & aws_df["tag_email"].isna()
    ]
    fuzzy_candidates_count = len(aws_train_human_no_tags)
    print(
        f"\nAccounts reaching the fuzzy matching stage on train: {fuzzy_candidates_count} accounts"
    )
    if fuzzy_candidates_count < 20:
        print(
            "WARNING: Sample size is too small (<20) to tune reliably.",
            file=sys.stderr,
        )
        return

    print("Sample size is sufficient (>200) to calibrate a reliable threshold.")

    # --- Part 2: Sweep thresholds on TRAIN split only ---
    print("\n" + "=" * 70)
    print("PART 2: THRESHOLD SWEEP (TRAIN SPLIT ONLY)")
    print("=" * 70)

    thresholds_to_test = [70.0, 75.0, 78.0, 80.0, 82.0, 84.0, 85.0, 86.0, 88.0, 90.0, 92.0, 95.0]
    sweep_df, best_t, error_analysis = tune_fuzzy_threshold(
        hr_df=hr_df,
        ad_df=ad_df,
        aws_df=aws_df,
        okta_df=okta_df,
        gt_links=gt_links,
        gt_labels=gt_labels,
        thresholds=thresholds_to_test,
    )

    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", 1000)
    print(sweep_df.to_string(index=False))

    print(f"\nOptimal threshold chosen on TRAIN: {best_t:.1f}")

    # Write chosen threshold to config.yaml
    config_file = Path("config.yaml")
    if config_file.exists():
        with config_file.open() as fh:
            raw_cfg = yaml.safe_load(fh) or {}
        if "resolution" not in raw_cfg:
            raw_cfg["resolution"] = {}
        raw_cfg["resolution"]["fuzzy_threshold"] = float(best_t)
        with config_file.open("w") as fh:
            yaml.safe_dump(raw_cfg, fh, sort_keys=False)
        print(f"Updated config.yaml with resolution.fuzzy_threshold = {best_t:.1f}")

    # --- Part 3: Error Analysis on Train ---
    print("\n" + "=" * 70)
    print("PART 3: ERROR ANALYSIS (TRAIN SPLIT)")
    print("=" * 70)
    print(f"Total unlinked/error accounts on train: {error_analysis['total_errors']}")
    print("Breakdown by reason:")
    for reason, cnt in error_analysis["by_reason"].items():
        print(f"  - {reason:25}: {cnt}")
    print("Breakdown by signal:")
    for sig, cnt in error_analysis["by_signal"].items():
        print(f"  - {sig:25}: {cnt}")

    # --- Part 4: Evaluate Test and Holdout ONCE using the chosen threshold ---
    print("\n" + "=" * 70)
    print("PART 4: FINAL EVALUATION (TEST & HOLDOUT SPLITS RUN ONCE)")
    print("=" * 70)

    final_res = resolve_identities(hr_df, ad_df, aws_df, okta_df, fuzzy_threshold=best_t)

    for split_name in ["train", "test", "holdout"]:
        print(f"\n--- Split: {split_name.upper()} ---")
        rep = evaluate_identity_resolution(
            final_res, gt_links, gt_labels, split=split_name, core_tables=core_tables
        )
        print(
            f"Overall Precision : {rep.overall_precision:.4f}  |  "
            f"Overall Recall : {rep.overall_recall:.4f}  |  "
            f"Unresolved Rate : {rep.overall_unresolved_rate:.4f}"
        )
        print(
            f"Total GT IDs      : {rep.total_gt_identities:<5}  |  "
            f"Total GT Accounts: {rep.total_gt_accounts:<5}"
        )

        print("\n  Metrics by Identity Kind:")
        for k_name, km in rep.by_kind.items():
            print(
                f"    {k_name:8}: Total={km.total_gt:<5} TP={km.tp:<5} FP={km.fp:<3} FN={km.fn:<4} "
                f"Precision={km.precision:.4f} Recall={km.recall:.4f} UnresRate={km.unresolved_rate:.4f}"
            )

        print("\n  Metrics by Signal:")
        for s_name, sm in rep.by_signal.items():
            print(
                f"    {s_name:8}: Count={sm.count:<5} TP={sm.tp:<5} FP={sm.fp:<3} "
                f"Precision={sm.precision:.4f} Recall={sm.recall:.4f}"
            )


if __name__ == "__main__":
    main()
