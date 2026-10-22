"""Evaluation subpackage — the ONLY place that may read GT_ sheets.

All other modules are prohibited from importing GT_ data.
The test_gt_isolation.py test enforces this at CI time.
"""

from accessatlas.evaluation.identity_metrics import (
    EvaluationReport,
    KindMetrics,
    SignalMetrics,
    count_train_fuzzy_candidates,
    evaluate_identity_resolution,
    evaluate_resolution_for_split,
    load_gt_identity_data,
    tune_fuzzy_threshold,
    tune_fuzzy_threshold_pipeline,
)
from accessatlas.evaluation.privilege_metrics import (
    EscalationMetrics,
    KindPrivilegeMetrics,
    PathAccuracy,
    PrivilegeEvaluationReport,
    TierAccuracy,
    evaluate_privilege_resolution,
    load_gt_privilege_data,
    run_full_privilege_evaluation,
)
from accessatlas.evaluation.scenario_metrics import (
    ScenarioMetrics,
    SplitEvaluationReport,
    TrapMetrics,
    evaluate_scenario_findings,
    load_gt_scenario_data,
    run_full_scenario_evaluation,
)

__all__ = [
    "EscalationMetrics",
    "EvaluationReport",
    "KindMetrics",
    "KindPrivilegeMetrics",
    "PathAccuracy",
    "PrivilegeEvaluationReport",
    "ScenarioMetrics",
    "SignalMetrics",
    "SplitEvaluationReport",
    "TierAccuracy",
    "TrapMetrics",
    "count_train_fuzzy_candidates",
    "evaluate_identity_resolution",
    "evaluate_privilege_resolution",
    "evaluate_resolution_for_split",
    "evaluate_scenario_findings",
    "load_gt_identity_data",
    "load_gt_privilege_data",
    "load_gt_scenario_data",
    "run_full_privilege_evaluation",
    "run_full_scenario_evaluation",
    "tune_fuzzy_threshold",
    "tune_fuzzy_threshold_pipeline",
]
