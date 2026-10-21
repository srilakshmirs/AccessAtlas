"""Pandera schemas for every ingested table.

IMPORTANT: GT_ sheet schemas live ONLY in accessatlas/evaluation/.
This module must never reference GT_ sheet names. (Enforced by test_gt_isolation.py.)

Each schema uses strict=False so that extra columns in the raw data do not
cause failures — we only assert the columns we care about have the right types.
"""

from __future__ import annotations

import pandera.pandas as pa
from pandera.pandas import Column, DataFrameSchema

# ---------------------------------------------------------------------------
# HR tables
# ---------------------------------------------------------------------------

HR_RECORDS_SCHEMA = DataFrameSchema(
    columns={
        "employee_id": Column(str, nullable=False),
        "first_name": Column(str, nullable=False),
        "last_name": Column(str, nullable=False),
        "email": Column(str, nullable=False),
        "department": Column(str, nullable=False),
        "job_title": Column(str, nullable=False),
        "manager_id": Column(str, nullable=True),  # CEO has no manager
        "worker_type": Column(str, pa.Check.isin(["employee", "contractor"]), nullable=False),
        # 'on_leave' is a real status value in the dataset (employees on leave).
        "status": Column(str, pa.Check.isin(["active", "terminated", "on_leave"]), nullable=False),
        "hire_date": Column("datetime64[ns]", nullable=False),
        "termination_date": Column("datetime64[ns]", nullable=True),
    },
    strict=False,
    name="HR_Records",
)

HR_ROLE_CHANGES_SCHEMA = DataFrameSchema(
    columns={
        "employee_id": Column(str, nullable=False),
        "change_date": Column("datetime64[ns]", nullable=False),
        "old_department": Column(str, nullable=True),
        "new_department": Column(str, nullable=True),
        "old_job_title": Column(str, nullable=True),
        "new_job_title": Column(str, nullable=True),
    },
    strict=False,
    name="HR_RoleChanges",
)

HR_OFFBOARDING_SCHEMA = DataFrameSchema(
    columns={
        "employee_id": Column(str, nullable=False),
        "termination_date": Column("datetime64[ns]", nullable=False),
        "ticket_id": Column(str, nullable=False),
        "ad_disabled_date": Column("datetime64[ns]", nullable=True),
        "okta_deactivated_date": Column("datetime64[ns]", nullable=True),
        "aws_access_removed_date": Column("datetime64[ns]", nullable=True),
        # After cleaning, all_platforms_revoked is a nullable boolean dtype
        "all_platforms_revoked": Column("boolean", nullable=True),
    },
    strict=False,
    name="HR_Offboarding",
)

# ---------------------------------------------------------------------------
# AD tables
# ---------------------------------------------------------------------------

AD_USERS_SCHEMA = DataFrameSchema(
    columns={
        "account_id": Column(str, nullable=False),
        "sam_account_name": Column(str, nullable=False),
        "user_principal_name": Column(str, nullable=False),
        "display_name": Column(str, nullable=False),
        "mail": Column(str, nullable=True),
        "employee_id": Column(str, nullable=True),  # null for orphan/service accounts
        "department": Column(str, nullable=True),
        "title": Column(str, nullable=True),
        "ou": Column(str, nullable=False),
        "enabled": Column("boolean", nullable=False),
        "created_at": Column("datetime64[ns]", nullable=True),
        "last_logon": Column("datetime64[ns]", nullable=True),
        "account_type": Column(str, pa.Check.isin(["human", "service", "orphan"]), nullable=False),
    },
    strict=False,
    name="AD_Users",
)

AD_GROUPS_SCHEMA = DataFrameSchema(
    columns={
        "group_name": Column(str, nullable=False),
        "declared_tier": Column(int, pa.Check.in_range(0, 3), nullable=False),
    },
    strict=False,
    name="AD_Groups",
)

AD_GROUP_MEMBERSHIP_SCHEMA = DataFrameSchema(
    columns={
        "member_type": Column(str, pa.Check.isin(["user", "group"]), nullable=False),
        "member": Column(str, nullable=False),
        "group_name": Column(str, nullable=False),
    },
    strict=False,
    name="AD_GroupMembership",
)

# ---------------------------------------------------------------------------
# AWS tables
# ---------------------------------------------------------------------------

AWS_USERS_SCHEMA = DataFrameSchema(
    columns={
        "user_id": Column(str, nullable=False),
        "user_name": Column(str, nullable=False),
        "arn": Column(str, nullable=False),
        "tag_employee_id": Column(str, nullable=True),
        "tag_email": Column(str, nullable=True),
        "created_at": Column("datetime64[ns]", nullable=True),
        "password_last_used": Column("datetime64[ns]", nullable=True),
        "console_access": Column("boolean", nullable=True),
        "mfa_enabled": Column("boolean", nullable=True),
        "status": Column(str, nullable=False),
        "account_type": Column(str, pa.Check.isin(["human", "service", "orphan"]), nullable=False),
    },
    strict=False,
    name="AWS_Users",
)

AWS_GROUPS_SCHEMA = DataFrameSchema(
    columns={
        "group_name": Column(str, nullable=False),
        "attached_policies": Column(str, nullable=True),
    },
    strict=False,
    name="AWS_Groups",
)

AWS_POLICIES_SCHEMA = DataFrameSchema(
    columns={
        "policy_name": Column(str, nullable=False),
        "declared_tier": Column(int, pa.Check.in_range(0, 3), nullable=False),
    },
    strict=False,
    name="AWS_Policies",
)

AWS_USER_GROUPS_SCHEMA = DataFrameSchema(
    columns={
        "user_id": Column(str, nullable=False),
        "group_name": Column(str, nullable=False),
    },
    strict=False,
    name="AWS_UserGroups",
)

AWS_POLICY_ATTACH_SCHEMA = DataFrameSchema(
    columns={
        "principal_type": Column(str, pa.Check.isin(["user", "group"]), nullable=False),
        "principal_id": Column(str, nullable=False),
        "policy_name": Column(str, nullable=False),
    },
    strict=False,
    name="AWS_PolicyAttach",
)

# ---------------------------------------------------------------------------
# Okta tables
# ---------------------------------------------------------------------------

OKTA_USERS_SCHEMA = DataFrameSchema(
    columns={
        "okta_id": Column(str, nullable=False),
        "login": Column(str, nullable=False),
        # ~80 service/orphan Okta accounts have no email address.
        "email": Column(str, nullable=True),
        "first_name": Column(str, nullable=True),
        "last_name": Column(str, nullable=True),
        "employee_number": Column(str, nullable=True),
        "status": Column(str, nullable=False),
        "created_at": Column("datetime64[ns]", nullable=True),
        "last_login": Column("datetime64[ns]", nullable=True),
        "account_type": Column(str, pa.Check.isin(["human", "service", "orphan"]), nullable=False),
    },
    strict=False,
    name="Okta_Users",
)

OKTA_GROUPS_SCHEMA = DataFrameSchema(
    columns={
        "group_name": Column(str, nullable=False),
    },
    strict=False,
    name="Okta_Groups",
)

OKTA_GROUP_MEMBERSHIP_SCHEMA = DataFrameSchema(
    columns={
        "okta_id": Column(str, nullable=False),
        "group_name": Column(str, nullable=False),
    },
    strict=False,
    name="Okta_GroupMembership",
)

OKTA_ADMIN_ROLES_SCHEMA = DataFrameSchema(
    columns={
        "okta_id": Column(str, nullable=False),
        "admin_role": Column(str, nullable=False),
        "assigned_at": Column("datetime64[ns]", nullable=True),
    },
    strict=False,
    name="Okta_AdminRoles",
)

OKTA_APPS_SCHEMA = DataFrameSchema(
    columns={
        "okta_id": Column(str, nullable=False),
        "app_name": Column(str, nullable=False),
    },
    strict=False,
    name="Okta_Apps",
)

OKTA_AWS_FEDERATION_SCHEMA = DataFrameSchema(
    columns={
        "okta_group": Column(str, nullable=False),
        "aws_role": Column(str, nullable=False),
        "aws_declared_tier": Column(int, pa.Check.in_range(0, 3), nullable=False),
    },
    strict=False,
    name="Okta_AWS_Federation",
)

# ---------------------------------------------------------------------------
# Context / supporting tables
# ---------------------------------------------------------------------------

TIER_MAPPING_SCHEMA = DataFrameSchema(
    columns={
        "platform": Column(str, nullable=False),
        "role_or_group": Column(str, nullable=False),
        "common_tier": Column(int, pa.Check.in_range(0, 3), nullable=False),
    },
    strict=False,
    name="Tier_Mapping",
)

API_TOKENS_SCHEMA = DataFrameSchema(
    columns={
        "token_id": Column(str, nullable=False),
        "platform": Column(str, nullable=False),
        "account_id": Column(str, nullable=False),
        "created_at": Column("datetime64[ns]", nullable=True),
        "last_rotated_at": Column("datetime64[ns]", nullable=True),
        "last_used_at": Column("datetime64[ns]", nullable=True),
        "scope_tier": Column(int, pa.Check.in_range(0, 3), nullable=True),
        "status": Column(str, nullable=False),
    },
    strict=False,
    name="API_Tokens",
)

EXCEPTIONS_SCHEMA = DataFrameSchema(
    columns={
        "exception_id": Column(str, nullable=False),
        "employee_id": Column(str, nullable=False),
        "ticket_id": Column(str, nullable=False),
        "start_date": Column("datetime64[ns]", nullable=True),
        "end_date": Column("datetime64[ns]", nullable=True),
        "status": Column(str, pa.Check.isin(["active", "expired", "revoked"]), nullable=False),
        "revocation_confirmed": Column("boolean", nullable=True),
    },
    strict=False,
    name="Exceptions",
)

ON_CALL_ROSTER_SCHEMA = DataFrameSchema(
    columns={
        "employee_id": Column(str, nullable=False),
        "shift_start": Column("datetime64[ns]", nullable=False),
        "shift_end": Column("datetime64[ns]", nullable=False),
        "team": Column(str, nullable=False),
    },
    strict=False,
    name="OnCall_Roster",
)

SCHEDULED_JOBS_SCHEMA = DataFrameSchema(
    columns={
        "service_account_id": Column(str, nullable=False),
        "job_name": Column(str, nullable=False),
        "frequency": Column(str, nullable=False),
        "owner_employee_id": Column(str, nullable=True),
    },
    strict=False,
    name="Scheduled_Jobs",
)

# ---------------------------------------------------------------------------
# Audit Events (same schema for both Parts)
# ---------------------------------------------------------------------------

AUDIT_EVENTS_SCHEMA = DataFrameSchema(
    columns={
        "event_id": Column(str, nullable=False),
        "timestamp": Column("datetime64[ns]", nullable=False),
        "platform": Column(str, pa.Check.isin(["ad", "aws", "okta"]), nullable=False),
        "account_id": Column(str, nullable=False),
        "username": Column(str, nullable=False),
        "event_type": Column(str, nullable=False),
        "category": Column(str, nullable=False),
        "resource": Column(str, nullable=True),
        "result": Column(str, pa.Check.isin(["success", "failure"]), nullable=False),
        "source_ip": Column(str, nullable=True),
        "privileged_action": Column("boolean", nullable=True),
        "mfa_used": Column("boolean", nullable=True),  # NaN for AD (not tracked)
    },
    strict=False,
    name="Audit_Events",
)

# ---------------------------------------------------------------------------
# Registry — maps sheet/table name → schema for easy lookup
# ---------------------------------------------------------------------------

SCHEMAS: dict[str, pa.DataFrameSchema] = {
    "HR_Records": HR_RECORDS_SCHEMA,
    "HR_RoleChanges": HR_ROLE_CHANGES_SCHEMA,
    "HR_Offboarding": HR_OFFBOARDING_SCHEMA,
    "AD_Users": AD_USERS_SCHEMA,
    "AD_Groups": AD_GROUPS_SCHEMA,
    "AD_GroupMembership": AD_GROUP_MEMBERSHIP_SCHEMA,
    "AWS_Users": AWS_USERS_SCHEMA,
    "AWS_Groups": AWS_GROUPS_SCHEMA,
    "AWS_Policies": AWS_POLICIES_SCHEMA,
    "AWS_UserGroups": AWS_USER_GROUPS_SCHEMA,
    "AWS_PolicyAttach": AWS_POLICY_ATTACH_SCHEMA,
    "Okta_Users": OKTA_USERS_SCHEMA,
    "Okta_Groups": OKTA_GROUPS_SCHEMA,
    "Okta_GroupMembership": OKTA_GROUP_MEMBERSHIP_SCHEMA,
    "Okta_AdminRoles": OKTA_ADMIN_ROLES_SCHEMA,
    "Okta_Apps": OKTA_APPS_SCHEMA,
    "Okta_AWS_Federation": OKTA_AWS_FEDERATION_SCHEMA,
    "Tier_Mapping": TIER_MAPPING_SCHEMA,
    "API_Tokens": API_TOKENS_SCHEMA,
    "Exceptions": EXCEPTIONS_SCHEMA,
    "OnCall_Roster": ON_CALL_ROSTER_SCHEMA,
    "Scheduled_Jobs": SCHEDULED_JOBS_SCHEMA,
    "Audit_Events": AUDIT_EVENTS_SCHEMA,
}
