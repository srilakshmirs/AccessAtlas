"""Milestone 3 privilege evaluation script.

Runs end-to-end evaluation of privilege tier computation, cross-platform
federation, and hidden escalation detection against GT_EffectivePrivilege.

WHY:
- In identity governance, effective privilege accounts for blast radius:
  an identity may hold nominal tier 3 access directly while inheriting tier 0/1
  through nested groups or cloud federation.
- Evaluation code lives entirely in accessatlas/evaluation/ to enforce GT isolation.
  This CLI entry point invokes the evaluation subpackage and formats structured
  results across dataset splits.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from accessatlas.evaluation.privilege_metrics import (
    PrivilegeEvaluationReport,
    run_full_privilege_evaluation,
)
from accessatlas.utils import load_config, setup_logging


def print_report(report: PrivilegeEvaluationReport) -> None:
    """Print a structured Markdown evaluation report for a split."""
    sp = report.split.upper()
    print(f"\n{'=' * 70}")
    print(f"PRIVILEGE EVALUATION REPORT — {sp} SPLIT (n={report.total_identities})")
    print(f"{'=' * 70}\n")

    # 1. Tier Accuracies
    t = report.tier_accuracy
    print("### Tier Accuracies against Ground Truth")
    print("| Entitlement Dimension | Accuracy | Correct / Total |")
    print("| :--- | :--- | :--- |")
    print(f"| AD Effective Tier | {t.ad_acc * 100:.2f}% | {t.ad_correct} / {t.total} |")
    print(f"| AWS Effective Tier | {t.aws_acc * 100:.2f}% | {t.aws_correct} / {t.total} |")
    print(f"| Okta Platform Tier | {t.okta_acc * 100:.2f}% | {t.okta_correct} / {t.total} |")
    print(
        f"| Overall Effective Tier | {t.overall_acc * 100:.2f}% | {t.overall_correct} / {t.total} |"
    )
    print()

    # 2. Hidden Escalation Metrics
    e = report.escalation_metrics
    print("### Hidden Escalation Detection (Indirect Tier <= 2)")
    print("| Metric | Value | Raw Counts / Detail |")
    print("| :--- | :--- | :--- |")
    print(f"| Confusion Matrix | — | TP={e.tp}, FP={e.fp}, TN={e.tn}, FN={e.fn} |")
    print(f"| Precision | {e.precision * 100:.2f}% | {e.tp} / {e.tp + e.fp} |")
    print(f"| Recall | {e.recall * 100:.2f}% | {e.tp} / {e.tp + e.fn} |")
    print(f"| F1 Score | {e.f1 * 100:.2f}% | Harmonic mean |")
    print(f"| Classification Accuracy | {e.accuracy * 100:.2f}% | {e.tp + e.tn} / {t.total} |")
    print()

    # 3. Path Correctness
    p = report.path_accuracy
    print("### Grant-Path Correctness")
    print("| Scope | Path Accuracy | Correct / Total | Scoring Rule |")
    print("| :--- | :--- | :--- | :--- |")
    print(
        f"| Overall (All Tiers) | {p.overall_acc * 100:.2f}% | {p.overall_correct} / {p.overall_total} | Granting group/role match (AWS: tier only) |"
    )
    print(
        f"| Privileged (Tier <= 2) | {p.privileged_acc * 100:.2f}% | {p.privileged_correct} / {p.privileged_total} | Target privileged group or role match |"
    )
    print()

    # 4. Breakdown by Identity Kind
    print("### Entitlement Accuracy by Identity Kind")
    print(
        "| Identity Kind | Count | AD Eff Acc | AWS Eff Acc | Okta Acc | Overall Acc | Escalation (TP/FP/FN) | Esc Prec / Rec |"
    )
    print("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for kind, km in report.by_kind.items():
        print(
            f"| {kind.capitalize()} | {km.total} | "
            f"{km.ad_acc * 100:.1f}% | {km.aws_acc * 100:.1f}% | {km.okta_acc * 100:.1f}% | {km.overall_acc * 100:.1f}% | "
            f"{km.tp} / {km.fp} / {km.fn} | {km.precision * 100:.1f}% / {km.recall * 100:.1f}% |"
        )
    print()

    # 5. Error Breakdown
    print("### Error Breakdown and Diagnosis")
    for cat, count in report.error_breakdown.items():
        print(f"- **{cat}**: {count}")
    print()


def main() -> None:
    setup_logging()
    cfg = load_config()

    parser = argparse.ArgumentParser(description="Evaluate effective privilege calculation.")
    parser.add_argument(
        "--splits",
        nargs="+",
        default=["train", "test", "holdout"],
        help="Dataset splits to evaluate (default: train test holdout)",
    )
    args = parser.parse_args()

    data_dir = Path(cfg["paths"]["processed"])
    gt_dir = data_dir / "gt"

    print("Running Milestone 3 privilege evaluation pipeline...")
    reports = run_full_privilege_evaluation(
        data_dir=data_dir,
        gt_dir=gt_dir,
        splits=args.splits,
    )

    for sp in args.splits:
        if sp in reports:
            print_report(reports[sp])


if __name__ == "__main__":
    main()
