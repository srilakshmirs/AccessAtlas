"""Evaluation runner for AccessAtlas M4 rules against GT_Labels.

This script delegates entirely to accessatlas.evaluation.scenario_metrics.
It never loads ground truth files directly (enforcing GT isolation).
"""

import argparse

from accessatlas.evaluation.scenario_metrics import run_full_scenario_evaluation


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate M4 detection rules against ground truth."
    )
    parser.add_argument(
        "--splits",
        nargs="+",
        default=["train"],
        choices=["train", "test", "holdout", "all"],
        help="Dataset split(s) to evaluate (default: train).",
    )
    args = parser.parse_args()

    splits = tuple(args.splits)
    print(f"Running M4 rule scenario evaluation for split(s): {splits}...")
    run_full_scenario_evaluation(splits=splits)


if __name__ == "__main__":
    main()
