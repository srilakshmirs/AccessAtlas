"""Tests for Milestone 2: Identity Resolution.

Covers:
- Email and name normalization (including contractor .ext handling)
- Matching signals: explicit ID (1.0), email (0.95), fuzzy name/username
- Conflict detection (ID vs Email mismatch, ID vs Name contradiction)
- Orphan account routing (never linked, sent to unresolved)
- Service account representation and owner_status (valid, missing, invalid)
- Integration with fixture data
"""

from __future__ import annotations

import pandas as pd
import pytest

from accessatlas.resolution.matcher import (
    build_hr_index,
    match_account,
    normalize_email,
    normalize_name,
)
from accessatlas.resolution.resolver import resolve_identities


@pytest.fixture
def sample_hr_df() -> pd.DataFrame:
    """Minimal HR records for testing."""
    return pd.DataFrame(
        [
            {
                "employee_id": "E100001",
                "first_name": "Alice",
                "last_name": "Smith",
                "email": "alice.smith@acme-corp.example",
                "worker_type": "employee",
                "status": "active",
            },
            {
                "employee_id": "C100002",
                "first_name": "Bob",
                "last_name": "Jones",
                "email": "bob.jones.ext@acme-corp.example",
                "worker_type": "contractor",
                "status": "active",
            },
            {
                "employee_id": "E100003",
                "first_name": "Carol",
                "last_name": "Venkataraman",
                "email": "carol.venkataraman@acme-corp.example",
                "worker_type": "employee",
                "status": "terminated",
            },
        ]
    )


def test_normalize_email() -> None:
    """Test email normalization and contractor .ext stripping."""
    norm, base = normalize_email("Alice.Smith@ACME-CORP.EXAMPLE")
    assert norm == "alice.smith@acme-corp.example"
    assert base == "alice.smith@acme-corp.example"

    # Contractor .ext
    norm_c, base_c = normalize_email("bob.jones.ext@acme-corp.example ")
    assert norm_c == "bob.jones.ext@acme-corp.example"
    assert base_c == "bob.jones@acme-corp.example"

    # Empty / None
    assert normalize_email(None) == ("", "")
    assert normalize_email("") == ("", "")


def test_normalize_name() -> None:
    """Test display name normalization."""
    assert normalize_name("  Alice   Smith ") == "alice smith"
    assert normalize_name(None) == ""


def test_match_by_explicit_id(sample_hr_df: pd.DataFrame) -> None:
    """Explicit ID matches with confidence 1.0."""
    hr_index = build_hr_index(sample_hr_df)
    res = match_account(
        platform="ad",
        account_id="AD-001",
        account_type="human",
        raw_id="E100001",
        raw_email=None,
        raw_username="asmith",
        raw_display_name="Alice Smith",
        hr_index=hr_index,
    )
    assert res.is_resolved is True
    assert res.employee_id == "E100001"
    assert res.confidence == 1.0
    assert res.signal == "id"


def test_match_by_exact_email_and_contractor_ext(sample_hr_df: pd.DataFrame) -> None:
    """Exact email matches with confidence 0.95, handling .ext variations."""
    hr_index = build_hr_index(sample_hr_df)

    # Standard employee email match
    res_emp = match_account(
        platform="okta",
        account_id="OKTA-001",
        account_type="human",
        raw_id=None,
        raw_email="Alice.Smith@acme-corp.example",
        raw_username="alice.smith",
        raw_display_name="Alice Smith",
        hr_index=hr_index,
    )
    assert res_emp.is_resolved is True
    assert res_emp.employee_id == "E100001"
    assert res_emp.confidence == 0.95
    assert res_emp.signal == "email"

    # Contractor with non-ext email on platform matching contractor in HR
    res_contractor = match_account(
        platform="aws",
        account_id="AWS-001",
        account_type="human",
        raw_id=None,
        raw_email="bob.jones@acme-corp.example",
        raw_username="bjones",
        raw_display_name=None,
        hr_index=hr_index,
    )
    assert res_contractor.is_resolved is True
    assert res_contractor.employee_id == "C100002"
    assert res_contractor.signal == "email"


def test_match_by_fuzzy_name(sample_hr_df: pd.DataFrame) -> None:
    """Fuzzy matching matches on canonical handles (e.g. flast or dot_name)."""
    hr_index = build_hr_index(sample_hr_df)

    # flast username: 'cvenkataraman' -> Carol Venkataraman
    res = match_account(
        platform="aws",
        account_id="AWS-002",
        account_type="human",
        raw_id=None,
        raw_email=None,
        raw_username="cvenkataraman",
        raw_display_name=None,
        hr_index=hr_index,
        fuzzy_threshold=80.0,
    )
    assert res.is_resolved is True
    assert res.employee_id == "E100003"
    assert res.signal == "fuzzy"
    assert res.confidence is not None and res.confidence >= 0.8


def test_fuzzy_below_threshold_unresolved(sample_hr_df: pd.DataFrame) -> None:
    """Scores below fuzzy_threshold are left unresolved with low_confidence."""
    hr_index = build_hr_index(sample_hr_df)
    res = match_account(
        platform="aws",
        account_id="AWS-003",
        account_type="human",
        raw_id=None,
        raw_email=None,
        raw_username="totally_unrelated_handle_123",
        raw_display_name=None,
        hr_index=hr_index,
        fuzzy_threshold=80.0,
    )
    assert res.is_resolved is False
    assert res.unresolved_reason == "low_confidence"


def test_orphan_account_isolated(sample_hr_df: pd.DataFrame) -> None:
    """Orphan accounts must never be linked and must route to unresolved."""
    hr_index = build_hr_index(sample_hr_df)
    res = match_account(
        platform="ad",
        account_id="AD-ORPH-01",
        account_type="orphan",
        raw_id="E100001",  # Even if an ID happens to match, orphan type overrides!
        raw_email="alice.smith@acme-corp.example",
        raw_username="mig-user9",
        raw_display_name="Mig-User9",
        hr_index=hr_index,
    )
    assert res.is_resolved is False
    assert res.unresolved_reason == "orphan_account"


def test_signal_conflict_id_vs_email(sample_hr_df: pd.DataFrame) -> None:
    """Conflicting explicit ID and email must route to unresolved."""
    hr_index = build_hr_index(sample_hr_df)
    # raw_id points to Alice (E100001), raw_email points to Bob (C100002)
    res = match_account(
        platform="ad",
        account_id="AD-CONFLICT-01",
        account_type="human",
        raw_id="E100001",
        raw_email="bob.jones.ext@acme-corp.example",
        raw_username="ajones",
        raw_display_name="Alice Jones",
        hr_index=hr_index,
    )
    assert res.is_resolved is False
    assert res.unresolved_reason == "signal_conflict"
    assert "Explicit ID points to E100001 but email points to C100002" in res.detail


def test_signal_conflict_id_vs_name(sample_hr_df: pd.DataFrame) -> None:
    """Explicit ID with strongly contradictory name points to conflict."""
    hr_index = build_hr_index(sample_hr_df)
    # raw_id points to Alice (E100001), but username is bob.jones (score 100 with Bob, 0 with Alice)
    res = match_account(
        platform="aws",
        account_id="AWS-CONFLICT-02",
        account_type="human",
        raw_id="E100001",
        raw_email=None,
        raw_username="bob.jones",
        raw_display_name=None,
        hr_index=hr_index,
    )
    assert res.is_resolved is False
    assert res.unresolved_reason == "signal_conflict"


def test_resolve_identities_pipeline(sample_hr_df: pd.DataFrame) -> None:
    """Full pipeline test with human, service, orphan, and conflicting accounts."""
    ad_df = pd.DataFrame(
        [
            {
                "account_id": "AD-001",
                "account_type": "human",
                "employee_id": "E100001",
                "mail": "alice.smith@acme-corp.example",
                "sam_account_name": "alice.smith",
                "display_name": "Alice Smith",
                "owner_employee_id": None,
            },
            {
                "account_id": "AD-SVC-01",
                "account_type": "service",
                "employee_id": None,
                "mail": None,
                "sam_account_name": "svc-backup",
                "display_name": "Service Backup",
                "owner_employee_id": "E100001",  # Valid owner
            },
            {
                "account_id": "AD-SVC-02",
                "account_type": "service",
                "employee_id": None,
                "mail": None,
                "sam_account_name": "svc-scanner",
                "display_name": "Service Scanner",
                "owner_employee_id": None,  # Missing owner
            },
            {
                "account_id": "AD-SVC-03",
                "account_type": "service",
                "employee_id": None,
                "mail": None,
                "sam_account_name": "svc-legacy",
                "display_name": "Service Legacy",
                "owner_employee_id": "NON_EXISTENT_ID",  # Invalid owner
            },
            {
                "account_id": "AD-ORPH-01",
                "account_type": "orphan",
                "employee_id": None,
                "mail": None,
                "sam_account_name": "mig-user1",
                "display_name": "Mig-User1",
                "owner_employee_id": None,
            },
        ]
    )

    aws_df = pd.DataFrame(
        [
            {
                "user_id": "AWS-001",
                "account_type": "human",
                "tag_employee_id": "E100001",
                "tag_email": "alice.smith@acme-corp.example",
                "user_name": "asmith",
                "owner_employee_id": None,
            }
        ]
    )

    okta_df = pd.DataFrame(
        [
            {
                "okta_id": "OKTA-001",
                "account_type": "human",
                "employee_number": None,
                "email": "alice.smith@acme-corp.example",
                "login": "alice.smith@acme-corp.example",
                "first_name": "Alice",
                "last_name": "Smith",
                "owner_employee_id": None,
            }
        ]
    )

    result = resolve_identities(sample_hr_df, ad_df, aws_df, okta_df)
    resolved = result.resolved_identities
    unresolved = result.unresolved_accounts

    # Check Alice Smith resolved human identity
    alice = resolved[resolved["identity_id"] == "E100001"].iloc[0]
    assert alice["identity_kind"] == "human"
    assert alice["ad_account_id"] == "AD-001"
    assert alice["aws_user_id"] == "AWS-001"
    assert alice["okta_id"] == "OKTA-001"

    # Check service accounts in resolved table
    svc1 = resolved[resolved["identity_id"] == "svc:ad:AD-SVC-01"].iloc[0]
    assert svc1["identity_kind"] == "service"
    assert svc1["owner_employee_id"] == "E100001"
    assert svc1["owner_status"] == "valid"

    svc2 = resolved[resolved["identity_id"] == "svc:ad:AD-SVC-02"].iloc[0]
    assert svc2["identity_kind"] == "service"
    assert pd.isna(svc2["owner_employee_id"]) or svc2["owner_employee_id"] is None
    assert svc2["owner_status"] == "missing"

    svc3 = resolved[resolved["identity_id"] == "svc:ad:AD-SVC-03"].iloc[0]
    assert svc3["identity_kind"] == "service"
    assert svc3["owner_employee_id"] == "NON_EXISTENT_ID"
    assert svc3["owner_status"] == "invalid"

    # Check orphan in unresolved table
    assert "AD-ORPH-01" in unresolved["account_id"].values
    orph_row = unresolved[unresolved["account_id"] == "AD-ORPH-01"].iloc[0]
    assert orph_row["reason"] == "orphan_account"


def test_fixture_integration() -> None:
    """Run resolution pipeline against test fixtures in tests/fixtures/.

    Includes injected orphan and conflict accounts to verify isolation.
    """
    hr = pd.read_parquet("tests/fixtures/HR_Records.parquet")
    ad = pd.read_parquet("tests/fixtures/AD_Users.parquet")
    aws = pd.read_parquet("tests/fixtures/AWS_Users.parquet")
    okta = pd.read_parquet("tests/fixtures/Okta_Users.parquet")

    # Inject an orphan account into AD fixture
    orphan_row = pd.DataFrame(
        [
            {
                "account_id": "AD-ORPH-FIXTURE",
                "sam_account_name": "mig-user99",
                "user_principal_name": None,
                "display_name": "Mig User99",
                "mail": None,
                "employee_id": None,
                "department": None,
                "title": None,
                "ou": "Disabled",
                "enabled": False,
                "created_at": None,
                "last_logon": None,
                "account_type": "orphan",
                "owner_employee_id": None,
            }
        ]
    )
    ad_with_orphan = pd.concat([ad, orphan_row], ignore_index=True)

    # Inject a conflicting account into AWS fixture (ID points to one employee, email to another)
    first_two_emps = hr["employee_id"].iloc[:2].tolist()
    emp_a, emp_b = first_two_emps[0], first_two_emps[1]
    emp_b_email = hr[hr["employee_id"] == emp_b]["email"].iloc[0]
    conflict_row = pd.DataFrame(
        [
            {
                "user_id": "AWS-CONFLICT-FIXTURE",
                "user_name": "conflict.user",
                "arn": "arn:aws:iam::123:user/conflict.user",
                "tag_employee_id": emp_a,
                "tag_email": emp_b_email,
                "created_at": None,
                "password_last_used": None,
                "console_access": True,
                "mfa_enabled": True,
                "status": "active",
                "account_type": "human",
                "owner_employee_id": None,
            }
        ]
    )
    aws_with_conflict = pd.concat([aws, conflict_row], ignore_index=True)

    result = resolve_identities(hr, ad_with_orphan, aws_with_conflict, okta)
    assert not result.resolved_identities.empty
    assert not result.unresolved_accounts.empty

    # Verify orphan account ended up in unresolved_accounts
    assert "AD-ORPH-FIXTURE" in result.unresolved_accounts["account_id"].values
    orph_record = result.unresolved_accounts[
        result.unresolved_accounts["account_id"] == "AD-ORPH-FIXTURE"
    ].iloc[0]
    assert orph_record["reason"] == "orphan_account"

    # Verify conflicting account ended up in unresolved_accounts
    assert "AWS-CONFLICT-FIXTURE" in result.unresolved_accounts["account_id"].values
    conflict_record = result.unresolved_accounts[
        result.unresolved_accounts["account_id"] == "AWS-CONFLICT-FIXTURE"
    ].iloc[0]
    assert conflict_record["reason"] == "signal_conflict"

    # Verify neither orphan nor conflicting account is in resolved_identities
    resolved_ad = set(result.resolved_identities["ad_account_id"].dropna())
    resolved_aws = set(result.resolved_identities["aws_user_id"].dropna())
    assert "AD-ORPH-FIXTURE" not in resolved_ad
    assert "AWS-CONFLICT-FIXTURE" not in resolved_aws
