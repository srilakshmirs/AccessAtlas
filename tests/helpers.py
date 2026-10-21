"""Non-pytest helpers shared across the test suite.

This module contains plain constants and utilities that are imported by test
files directly. It is separate from conftest.py so that:

  - conftest.py stays focused on pytest fixtures and plugin hooks.
  - Any module (including parametrize decorators evaluated at collection time)
    can import from here without triggering pytest fixture machinery.

WHY the split: pytest evaluates @pytest.mark.parametrize arguments at module
import time, before fixtures are available. Keeping CORE_FIXTURE_TABLES in a
plain module avoids an implicit dependency on conftest execution order.
"""

from __future__ import annotations

# Ordered list of every table that must have a corresponding Parquet file in
# tests/fixtures/. Used to parametrise loader and schema tests.
CORE_FIXTURE_TABLES: list[str] = [
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
