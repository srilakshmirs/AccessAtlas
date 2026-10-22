"""Data models for AccessAtlas rules, findings, and suppression context."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

SeverityLevel = Literal["critical", "high", "medium", "low"]


class Finding(BaseModel):
    """Represents a single explained security finding or policy violation.

    Attributes
    ----------
    finding_id : str
        Unique deterministic identifier for the finding (e.g. 'FND-offboarding_gap-E100086').
    rule : str
        Name of the detection rule triggered (e.g. 'offboarding_gap', 'dormant_admin').
    identity_id : str
        Canonical identity identifier produced by M2/M3 (employee_id, 'svc:<plat>:<acc>', or account_id).
    account_id : str | None
        Optional specific platform account identifier if the finding pertains to a single account.
    platforms : list[str]
        Platforms involved in this finding (e.g. ['ad'], ['aws', 'okta']).
    severity : SeverityLevel
        Finding severity: 'critical', 'high', 'medium', or 'low'.
    evidence : list[str]
        Human-readable explanation statements with concrete dates, status values, and permissions.
    privilege_path : str | None
        Privilege granting chain or path from M3 if applicable, else None.
    recommended_action : str
        Concrete remediation recommendation for the security/IAM operations team.
    confidence_caveat : str | None
        Optional caveat when confidence is reduced (e.g. unlinked accounts in M2 unresolved table).
    """

    finding_id: str
    rule: str
    identity_id: str
    account_id: str | None = None
    platforms: list[str] = Field(default_factory=list)
    severity: SeverityLevel
    evidence: list[str] = Field(default_factory=list)
    privilege_path: str | None = None
    recommended_action: str
    confidence_caveat: str | None = None
