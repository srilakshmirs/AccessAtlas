"""Unit tests for M4 detection rules, findings models, and context suppression."""

import pandas as pd
import pytest

from accessatlas.rules.detectors import (
    detect_cross_platform_admin,
    detect_dormant_admin,
    detect_expired_exception_active,
    detect_nested_group_escalation,
    detect_offboarding_gap,
    detect_orphan_account,
    detect_orphaned_service_account,
    detect_stale_token,
    detect_unlinked_account_review,
    evaluate_all_rules,
)
from accessatlas.rules.suppression import SuppressionEngine

SNAPSHOT_DATE = pd.Timestamp("2026-10-12 23:59:59")


@pytest.fixture
def empty_suppression() -> SuppressionEngine:
    return SuppressionEngine(snapshot_date=SNAPSHOT_DATE)


# ==============================================================================
# 1. offboarding_gap tests
# ==============================================================================


def test_offboarding_gap_positive(empty_suppression: SuppressionEngine):
    """Terminated employee with active platform account must be flagged."""
    hr_df = pd.DataFrame(
        [{"employee_id": "E10001", "status": "terminated", "termination_date": "2026-05-01"}]
    )
    ad_users_df = pd.DataFrame([{"account_id": "AD-001", "enabled": True}])
    resolved_df = pd.DataFrame(
        [{"identity_id": "E10001", "identity_kind": "human", "ad_account_id": "AD-001"}]
    )

    findings = detect_offboarding_gap(
        hr_df=hr_df,
        hr_offboarding_df=None,
        ad_users_df=ad_users_df,
        aws_users_df=None,
        okta_users_df=None,
        resolved_identities=resolved_df,
        suppression_engine=empty_suppression,
        snapshot_date=SNAPSHOT_DATE,
    )
    assert len(findings) == 1
    assert findings[0].rule == "offboarding_gap"
    assert findings[0].identity_id == "E10001"
    assert findings[0].severity == "high"
    assert "ad" in findings[0].platforms


def test_offboarding_gap_negative(empty_suppression: SuppressionEngine):
    """Active employee with active platform account must NOT be flagged."""
    hr_df = pd.DataFrame([{"employee_id": "E10001", "status": "active", "termination_date": None}])
    ad_users_df = pd.DataFrame([{"account_id": "AD-001", "enabled": True}])
    resolved_df = pd.DataFrame(
        [{"identity_id": "E10001", "identity_kind": "human", "ad_account_id": "AD-001"}]
    )

    findings = detect_offboarding_gap(
        hr_df=hr_df,
        hr_offboarding_df=None,
        ad_users_df=ad_users_df,
        aws_users_df=None,
        okta_users_df=None,
        resolved_identities=resolved_df,
        suppression_engine=empty_suppression,
        snapshot_date=SNAPSHOT_DATE,
    )
    assert len(findings) == 0


def test_offboarding_gap_suppression_approved_exception():
    """Terminated employee with approved active handover exception must be suppressed."""
    hr_df = pd.DataFrame(
        [{"employee_id": "E10001", "status": "terminated", "termination_date": "2026-05-01"}]
    )
    ad_users_df = pd.DataFrame([{"account_id": "AD-001", "enabled": True}])
    resolved_df = pd.DataFrame(
        [{"identity_id": "E10001", "identity_kind": "human", "ad_account_id": "AD-001"}]
    )
    exc_df = pd.DataFrame(
        [
            {
                "exception_id": "EXC-001",
                "employee_id": "E10001",
                "platforms": "ad",
                "privilege": "handover access after exit",
                "start_date": "2026-05-01",
                "end_date": "2026-11-01",
                "status": "active",
                "reason": "handover / legal hold",
            }
        ]
    )
    suppression = SuppressionEngine(snapshot_date=SNAPSHOT_DATE, exceptions_df=exc_df)

    findings = detect_offboarding_gap(
        hr_df=hr_df,
        hr_offboarding_df=None,
        ad_users_df=ad_users_df,
        aws_users_df=None,
        okta_users_df=None,
        resolved_identities=resolved_df,
        suppression_engine=suppression,
        snapshot_date=SNAPSHOT_DATE,
    )
    assert len(findings) == 0


# ==============================================================================
# 2. orphan_account tests
# ==============================================================================


def test_orphan_account_positive():
    """Unresolved account with reason orphan_account must be flagged."""
    unresolved_df = pd.DataFrame(
        [
            {
                "account_id": "AD-00999",
                "platform": "ad",
                "reason": "orphan_account",
                "raw_username": "legacy-adm",
            }
        ]
    )
    findings = detect_orphan_account(unresolved_df)
    assert len(findings) == 1
    assert findings[0].rule == "orphan_account"
    assert findings[0].identity_id == "AD-00999"
    assert findings[0].account_id == "AD-00999"
    assert findings[0].severity == "high"


def test_orphan_account_negative():
    """Unresolved account with reason other than orphan_account must NOT be flagged."""
    unresolved_df = pd.DataFrame(
        [
            {
                "account_id": "AD-00999",
                "platform": "ad",
                "reason": "ambiguous_name",
                "raw_username": "john.smith",
            }
        ]
    )
    findings = detect_orphan_account(unresolved_df)
    assert len(findings) == 0


# ==============================================================================
# 3. dormant_admin tests
# ==============================================================================


def test_dormant_admin_positive(empty_suppression: SuppressionEngine):
    """Privileged admin with no recent audit activity (> 60 days) must be flagged."""
    priv_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "overall_effective_tier": 0,
                "ad_effective_tier": 0,
                "overall_grant_path": "AD: Domain Admins",
            }
        ]
    )
    res_df = pd.DataFrame([{"identity_id": "E10001", "ad_account_id": "AD-001"}])
    audit_df = pd.DataFrame(
        [{"account_id": "AD-001", "timestamp": pd.Timestamp("2026-05-01 00:00:00")}]
    )

    findings = detect_dormant_admin(
        privilege_df=priv_df,
        resolved_identities=res_df,
        audit_events_df=audit_df,
        suppression_engine=empty_suppression,
        snapshot_date=SNAPSHOT_DATE,
        dormant_days=60,
    )
    assert len(findings) == 1
    assert findings[0].rule == "dormant_admin"
    assert findings[0].identity_id == "E10001"
    assert findings[0].severity == "high"


def test_dormant_admin_negative(empty_suppression: SuppressionEngine):
    """Privileged admin with recent audit activity (< 60 days) must NOT be flagged."""
    priv_df = pd.DataFrame(
        [{"identity_id": "E10001", "overall_effective_tier": 0, "ad_effective_tier": 0}]
    )
    res_df = pd.DataFrame([{"identity_id": "E10001", "ad_account_id": "AD-001"}])
    audit_df = pd.DataFrame(
        [{"account_id": "AD-001", "timestamp": pd.Timestamp("2026-10-10 00:00:00")}]
    )

    findings = detect_dormant_admin(
        privilege_df=priv_df,
        resolved_identities=res_df,
        audit_events_df=audit_df,
        suppression_engine=empty_suppression,
        snapshot_date=SNAPSHOT_DATE,
        dormant_days=60,
    )
    assert len(findings) == 0


def test_dormant_admin_suppression_recent_hire():
    """Privileged admin who is a recent hire (within 30 days) must be suppressed."""
    priv_df = pd.DataFrame(
        [{"identity_id": "E10001", "overall_effective_tier": 1, "ad_effective_tier": 1}]
    )
    res_df = pd.DataFrame([{"identity_id": "E10001", "ad_account_id": "AD-001"}])
    audit_df = pd.DataFrame([])  # 0 events
    hr_df = pd.DataFrame([{"employee_id": "E10001", "hire_date": pd.Timestamp("2026-10-01")}])
    suppression = SuppressionEngine(snapshot_date=SNAPSHOT_DATE, hr_df=hr_df, new_hire_days=30)

    findings = detect_dormant_admin(
        privilege_df=priv_df,
        resolved_identities=res_df,
        audit_events_df=audit_df,
        suppression_engine=suppression,
        snapshot_date=SNAPSHOT_DATE,
        dormant_days=60,
    )
    assert len(findings) == 0


# ==============================================================================
# 4. expired_exception_active tests
# ==============================================================================


def test_expired_exception_active_positive():
    """Expired exception whose privileges remain active (tier <= 1) must be flagged."""
    exc_df = pd.DataFrame(
        [
            {
                "exception_id": "EXC-00003",
                "employee_id": "E10001",
                "platforms": "aws",
                "status": "expired",
                "end_date": "2026-06-16",
            }
        ]
    )
    priv_df = pd.DataFrame(
        [{"identity_id": "E10001", "aws_effective_tier": 1, "overall_effective_tier": 1}]
    )

    findings = detect_expired_exception_active(exc_df, priv_df, SNAPSHOT_DATE)
    assert len(findings) == 1
    assert findings[0].rule == "expired_exception_active"
    assert findings[0].identity_id == "E10001"
    assert "aws" in findings[0].platforms


def test_expired_exception_active_negative():
    """Expired exception whose privileges were revoked (tier > 1) must NOT be flagged."""
    exc_df = pd.DataFrame(
        [
            {
                "exception_id": "EXC-00003",
                "employee_id": "E10001",
                "platforms": "aws",
                "status": "expired",
                "end_date": "2026-06-16",
            }
        ]
    )
    priv_df = pd.DataFrame(
        [{"identity_id": "E10001", "aws_effective_tier": 3, "overall_effective_tier": 3}]
    )

    findings = detect_expired_exception_active(exc_df, priv_df, SNAPSHOT_DATE)
    assert len(findings) == 0


# ==============================================================================
# 5. stale_token tests
# ==============================================================================


def test_stale_token_positive():
    """API token not rotated within limit (> 365 days) must be flagged."""
    tokens_df = pd.DataFrame(
        [
            {
                "token_id": "TOK-001",
                "status": "active",
                "platform": "aws",
                "identity_id": "E10001",
                "account_id": "AWS-USR-01",
                "last_rotated_at": pd.Timestamp("2024-01-01"),
                "last_used_at": pd.Timestamp("2026-10-01"),
            }
        ]
    )
    findings = detect_stale_token(tokens_df, SNAPSHOT_DATE, rotation_days=365)
    assert len(findings) == 1
    assert findings[0].rule == "stale_token"
    assert findings[0].identity_id == "E10001"
    assert findings[0].account_id == "AWS-USR-01"
    assert findings[0].severity == "medium"


def test_stale_token_negative():
    """API token rotated recently must NOT be flagged."""
    tokens_df = pd.DataFrame(
        [
            {
                "token_id": "TOK-001",
                "status": "active",
                "platform": "aws",
                "identity_id": "E10001",
                "account_id": "AWS-USR-01",
                "last_rotated_at": pd.Timestamp("2026-09-01"),
                "last_used_at": pd.Timestamp("2026-10-01"),
            }
        ]
    )
    findings = detect_stale_token(tokens_df, SNAPSHOT_DATE, rotation_days=365)
    assert len(findings) == 0


# ==============================================================================
# 6. nested_group_escalation tests
# ==============================================================================


def test_nested_group_escalation_positive(empty_suppression: SuppressionEngine):
    """Hidden escalation from M3 must be flagged."""
    priv_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "hidden_escalation": True,
                "overall_effective_tier": 1,
                "ad_effective_tier": 1,
                "overall_grant_path": "AD: Engineers -> Nested Admins",
            }
        ]
    )
    unres_df = pd.DataFrame([])

    findings = detect_nested_group_escalation(priv_df, unres_df, empty_suppression)
    assert len(findings) == 1
    assert findings[0].rule == "nested_group_escalation"
    assert findings[0].identity_id == "E10001"
    assert findings[0].confidence_caveat is None


def test_nested_group_escalation_negative(empty_suppression: SuppressionEngine):
    """Direct privileges without hidden escalation must NOT be flagged."""
    priv_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "hidden_escalation": False,
                "overall_effective_tier": 1,
                "ad_effective_tier": 1,
            }
        ]
    )
    unres_df = pd.DataFrame([])

    findings = detect_nested_group_escalation(priv_df, unres_df, empty_suppression)
    assert len(findings) == 0


def test_nested_group_escalation_suppression_approved_exception():
    """Hidden escalation covered by approved active exception must be suppressed."""
    priv_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "hidden_escalation": True,
                "overall_effective_tier": 1,
                "ad_effective_tier": 1,
            }
        ]
    )
    exc_df = pd.DataFrame(
        [
            {
                "exception_id": "EXC-002",
                "employee_id": "E10001",
                "platforms": "ad",
                "privilege": "temporary admin",
                "start_date": "2026-09-01",
                "end_date": "2026-11-01",
                "status": "active",
            }
        ]
    )
    suppression = SuppressionEngine(snapshot_date=SNAPSHOT_DATE, exceptions_df=exc_df)

    findings = detect_nested_group_escalation(priv_df, pd.DataFrame([]), suppression)
    assert len(findings) == 0


def test_nested_group_escalation_caveat_unresolved_account(empty_suppression: SuppressionEngine):
    """Hidden escalation with unlinked account in unresolved table must include confidence caveat."""
    priv_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "hidden_escalation": True,
                "overall_effective_tier": 1,
                "ad_effective_tier": 1,
                "ad_account_id": "AD-001",
                "overall_grant_path": "AD: Nested Path",
            }
        ]
    )
    unres_df = pd.DataFrame([{"account_id": "AD-001", "reason": "ambiguous_name"}])

    findings = detect_nested_group_escalation(priv_df, unres_df, empty_suppression)
    assert len(findings) == 1
    assert findings[0].confidence_caveat is not None
    assert "artifact of an unlinked account" in findings[0].confidence_caveat


# ==============================================================================
# 7. cross_platform_admin tests
# ==============================================================================


def test_cross_platform_admin_positive(empty_suppression: SuppressionEngine):
    """Identity holding tier <= 1 on >= 2 platforms must be flagged."""
    priv_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "ad_effective_tier": 0,
                "aws_effective_tier": 1,
                "okta_tier": 3,
            }
        ]
    )
    findings = detect_cross_platform_admin(priv_df, empty_suppression)
    assert len(findings) == 1
    assert findings[0].rule == "cross_platform_admin"
    assert set(findings[0].platforms) == {"ad", "aws"}


def test_cross_platform_admin_negative(empty_suppression: SuppressionEngine):
    """Identity holding tier <= 1 on only 1 platform must NOT be flagged."""
    priv_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "ad_effective_tier": 0,
                "aws_effective_tier": 2,
                "okta_tier": 3,
            }
        ]
    )
    findings = detect_cross_platform_admin(priv_df, empty_suppression)
    assert len(findings) == 0


def test_cross_platform_admin_suppression_oncall():
    """Identity with on-call roster shift covering snapshot date must be suppressed."""
    priv_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "ad_effective_tier": 0,
                "aws_effective_tier": 1,
                "okta_tier": 1,
            }
        ]
    )
    oncall_df = pd.DataFrame(
        [
            {
                "employee_id": "E10001",
                "shift_start": "2026-10-05",
                "shift_end": "2026-10-15",
                "team": "Engineering",
            }
        ]
    )
    suppression = SuppressionEngine(snapshot_date=SNAPSHOT_DATE, oncall_df=oncall_df)

    findings = detect_cross_platform_admin(priv_df, suppression)
    assert len(findings) == 0


# ==============================================================================
# 8. orphaned_service_account tests
# ==============================================================================


def test_orphaned_service_account_positive():
    """Service account whose owner is terminated in HR must be flagged."""
    res_df = pd.DataFrame(
        [
            {
                "identity_id": "svc:ad:AD-SVC01",
                "identity_kind": "service",
                "owner_employee_id": "E10999",
            }
        ]
    )
    hr_df = pd.DataFrame([{"employee_id": "E10999", "status": "terminated"}])

    findings = detect_orphaned_service_account(res_df, hr_df, None, SNAPSHOT_DATE)
    assert len(findings) == 1
    assert findings[0].rule == "orphaned_service_account"
    assert findings[0].identity_id == "svc:ad:AD-SVC01"
    assert findings[0].account_id == "AD-SVC01"


def test_orphaned_service_account_ownerless_not_flagged():
    """Service account with NO owner must NOT be flagged (ownerless is normal in dataset)."""
    res_df = pd.DataFrame(
        [
            {
                "identity_id": "svc:aws:AWS-SVC01",
                "identity_kind": "service",
                "owner_employee_id": None,
            }
        ]
    )
    hr_df = pd.DataFrame([{"employee_id": "E10999", "status": "terminated"}])

    findings = detect_orphaned_service_account(res_df, hr_df, None, SNAPSHOT_DATE)
    assert len(findings) == 0


def test_orphaned_service_account_negative_active_owner():
    """Service account whose owner is an ACTIVE HR employee must NOT be flagged."""
    res_df = pd.DataFrame(
        [
            {
                "identity_id": "svc:okta:OKTA-SVC01",
                "identity_kind": "service",
                "owner_employee_id": "E10001",
            }
        ]
    )
    hr_df = pd.DataFrame([{"employee_id": "E10001", "status": "active"}])

    findings = detect_orphaned_service_account(res_df, hr_df, None, SNAPSHOT_DATE)
    assert len(findings) == 0


# ==============================================================================
# 9. unlinked_account_review tests
# ==============================================================================


def test_unlinked_account_review_positive():
    """Accounts unresolved due to ambiguous_name or signal_conflict must be reported with low severity."""
    unres_df = pd.DataFrame(
        [
            {
                "account_id": "AD-0011",
                "platform": "ad",
                "reason": "ambiguous_name",
                "raw_username": "alex.taylor",
            },
            {
                "account_id": "AWS-0022",
                "platform": "aws",
                "reason": "signal_conflict",
                "raw_username": "sam.jones",
            },
        ]
    )
    findings = detect_unlinked_account_review(unres_df)
    assert len(findings) == 2
    assert all(f.rule == "unlinked_account_review" for f in findings)
    assert all(f.severity == "low" for f in findings)


def test_unlinked_account_review_negative():
    """Accounts unresolved due to orphan_account or low_confidence must NOT be reported under this rule."""
    unres_df = pd.DataFrame(
        [
            {
                "account_id": "AD-0011",
                "platform": "ad",
                "reason": "orphan_account",
                "raw_username": "orphan.user",
            },
            {
                "account_id": "AWS-0022",
                "platform": "aws",
                "reason": "low_confidence",
                "raw_username": "fuzzy.user",
            },
        ]
    )
    findings = detect_unlinked_account_review(unres_df)
    assert len(findings) == 0


# ==============================================================================
# 10. Suppression Order & Rule Isolation tests
# ==============================================================================


def test_suppression_rule_isolation():
    """Suppression of one rule must NEVER hide an unrelated rule for the same identity."""
    # Identity E10001 is on-call (suppresses cross_platform_admin)
    # BUT also holds a stale token. The stale token MUST still be flagged!
    priv_df = pd.DataFrame(
        [
            {
                "identity_id": "E10001",
                "overall_effective_tier": 0,
                "ad_effective_tier": 0,
                "aws_effective_tier": 1,
                "okta_tier": 3,
                "hidden_escalation": False,
            }
        ]
    )
    res_df = pd.DataFrame([{"identity_id": "E10001", "identity_kind": "human"}])
    oncall_df = pd.DataFrame(
        [
            {
                "employee_id": "E10001",
                "shift_start": "2026-10-05",
                "shift_end": "2026-10-15",
                "team": "Engineering",
            }
        ]
    )
    tokens_df = pd.DataFrame(
        [
            {
                "token_id": "TOK-999",
                "status": "active",
                "platform": "aws",
                "identity_id": "E10001",
                "account_id": "AWS-USR-99",
                "last_rotated_at": pd.Timestamp("2024-01-01"),
                "last_used_at": pd.Timestamp("2026-10-01"),
            }
        ]
    )
    hr_df = pd.DataFrame([{"employee_id": "E10001", "status": "active"}])

    all_findings = evaluate_all_rules(
        hr_df=hr_df,
        hr_offboarding_df=None,
        ad_users_df=None,
        aws_users_df=None,
        okta_users_df=None,
        resolved_identities=res_df,
        unresolved_accounts=pd.DataFrame([]),
        privilege_df=priv_df,
        audit_events_df=pd.DataFrame([]),
        oncall_df=oncall_df,
        tokens_df=tokens_df,
        config={"snapshot_date": "2026-10-12"},
    )

    rules_flagged = [f.rule for f in all_findings]
    assert "cross_platform_admin" not in rules_flagged  # Suppressed by on-call
    assert "stale_token" in rules_flagged  # NOT hidden!


def test_scheduled_job_suppression():
    """Registered scheduled job suppresses service account audit/privilege alerts."""
    jobs_df = pd.DataFrame(
        [
            {
                "service_account_id": "SVC-0016",
                "job_name": "nightly-sync",
                "frequency": "daily",
                "window_start": "01:00",
                "window_end": "03:00",
                "owner_employee_id": "E10022",
            }
        ]
    )
    suppression = SuppressionEngine(snapshot_date=SNAPSHOT_DATE, scheduled_jobs_df=jobs_df)
    suppressed, reason = suppression.check_suppression(
        "dormant_admin", "E10022", account_id="SVC-0016"
    )
    assert suppressed is True
    assert "nightly-sync" in reason
