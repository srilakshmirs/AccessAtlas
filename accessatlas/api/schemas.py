"""Pydantic schemas for the AccessAtlas REST API."""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

from accessatlas.rules.models import Finding

T = TypeVar("T")


class HealthResponse(BaseModel):
    """Health and status metadata for AccessAtlas API."""

    status: str = "healthy"
    version: str = "0.1.0"
    identities_count: int = 0
    findings_count: int = 0
    snapshot_date: str = "2026-10-12"


class IdentityItem(BaseModel):
    """Summary of a resolved identity."""

    identity_id: str
    identity_kind: str
    ad_account_id: str | None = None
    aws_user_id: str | None = None
    okta_id: str | None = None
    overall_effective_tier: int | None = None
    ad_effective_tier: int | None = None
    aws_effective_tier: int | None = None
    okta_tier: int | None = None
    findings_count: int = 0


class IdentityDetail(IdentityItem):
    """Detailed view of an identity including grant paths and findings."""

    overall_grant_path: str | None = None
    hidden_escalation: bool = False
    findings: list[Finding] = Field(default_factory=list)


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated wrapper for API responses."""

    items: list[T]
    total: int
    page: int
    size: int
    pages: int


class ScenarioMetricItem(BaseModel):
    """Metric item for scenario evaluation."""

    scenario: str
    covered: bool
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    notes: str = ""


class TrapMetricItem(BaseModel):
    """Metric item for trap scenario evaluation."""

    scenario: str
    total_traps: int
    flagged_traps: int
    false_alarm_rate: float
    has_firing_rule: bool
    notes: str = ""


class EvaluationResponse(BaseModel):
    """Evaluation summary response across scenarios and traps."""

    split: str
    total_identities: int
    total_findings: int
    findings_by_rule: dict[str, int]
    findings_by_severity: dict[str, int]
    scenarios: dict[str, ScenarioMetricItem]
    traps: dict[str, TrapMetricItem]
    ml_comparison: dict[str, Any] | None = None
