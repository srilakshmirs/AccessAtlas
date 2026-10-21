"""Shared test configuration and fixtures.

The FIXTURE_DIR constant points to tests/fixtures/, which is committed to git
so CI can run without the full data/processed/ directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# tests/fixtures/ — committed to git; built once with convert_data.py --fixture
FIXTURE_DIR = Path(__file__).parent / "fixtures"

# All tables that should have a fixture file.
CORE_FIXTURE_TABLES = [
    "HR_Records",
    "HR_RoleChanges",
    "HR_Offboarding",
    "AD_Users",
    "AD_Groups",
    "AD_GroupMembership",
    "AWS_Users",
    "AWS_Groups",
    "AWS_Policies",
    "AWS_UserGroups",
    "AWS_PolicyAttach",
    "Okta_Users",
    "Okta_Groups",
    "Okta_GroupMembership",
    "Okta_AdminRoles",
    "Okta_Apps",
    "Okta_AWS_Federation",
    "Tier_Mapping",
    "API_Tokens",
    "Exceptions",
    "OnCall_Roster",
    "Scheduled_Jobs",
    "Audit_Events",
]


@pytest.fixture(scope="session")
def fixture_dir() -> Path:
    """Return the path to tests/fixtures/. Skip the whole session if absent."""
    if not FIXTURE_DIR.exists():
        pytest.skip("tests/fixtures/ not found. Run: python scripts/convert_data.py --fixture")
    return FIXTURE_DIR
