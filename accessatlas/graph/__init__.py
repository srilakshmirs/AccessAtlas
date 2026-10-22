"""Privilege graph construction and effective entitlement analysis."""

from __future__ import annotations

from accessatlas.graph.builder import build_privilege_graph
from accessatlas.graph.privilege import (
    AccountPrivilege,
    compute_ad_account_privilege,
    compute_aws_account_privilege,
    compute_federation_privilege,
    compute_identity_privileges,
    compute_okta_account_privilege,
)

__all__ = [
    "AccountPrivilege",
    "build_privilege_graph",
    "compute_ad_account_privilege",
    "compute_aws_account_privilege",
    "compute_federation_privilege",
    "compute_identity_privileges",
    "compute_okta_account_privilege",
]
