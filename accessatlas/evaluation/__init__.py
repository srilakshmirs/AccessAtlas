"""Evaluation subpackage — the ONLY place that may read GT_ sheets.

All other modules are prohibited from importing GT_ data.
The test_gt_isolation.py test enforces this at CI time.
"""

from accessatlas.evaluation.identity_metrics import (
    EvaluationReport,
    KindMetrics,
    SignalMetrics,
    evaluate_identity_resolution,
    load_gt_identity_data,
    tune_fuzzy_threshold,
)

__all__ = [
    "EvaluationReport",
    "KindMetrics",
    "SignalMetrics",
    "evaluate_identity_resolution",
    "load_gt_identity_data",
    "tune_fuzzy_threshold",
]
