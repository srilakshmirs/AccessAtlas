"""Unit and integration tests for Milestone 3: Privilege Graph and Effective Privilege.

Covers:
- Direct assignment on AD, AWS, and Okta
- Multi-hop nesting across group hierarchies
- Group cycles terminating cleanly without infinite recursion
- Okta-to-AWS federation crediting to aws_effective_tier
- Accounts with no access (tier 9: disabled, inactive, deprovisioned)
- End-to-end integration test on committed fixture data
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pandas as pd

from accessatlas.graph.builder import build_privilege_graph
from accessatlas.graph.privilege import (
    compute_ad_account_privilege,
    compute_aws_account_privilege,
    compute_federation_privilege,
    compute_identity_privileges,
    compute_okta_account_privilege,
)
from accessatlas.resolution.resolver import resolve_identities

# =============================================================================
# Unit Tests
# =============================================================================


def test_direct_assignment() -> None:
    """Direct assignment on AD, AWS, and Okta yields expected direct and effective tiers."""
    ad_groups = pd.DataFrame(
        [
            {"group_name": "Prod-Deployers", "declared_tier": 2},
            {"group_name": "GRP-All-Staff", "declared_tier": 3},
        ]
    )
    ad_membership = pd.DataFrame(
        [
            {"member_type": "user", "member": "AD-001", "group_name": "Prod-Deployers"},
            {"member_type": "user", "member": "AD-001", "group_name": "GRP-All-Staff"},
        ]
    )
    ad_users = pd.DataFrame([{"account_id": "AD-001", "enabled": True}])

    aws_policies = pd.DataFrame([{"policy_name": "AmazonS3FullAccess", "declared_tier": 2}])
    aws_groups = pd.DataFrame(
        [{"group_name": "s3-admins", "attached_policies": "AmazonS3FullAccess"}]
    )
    aws_user_groups = pd.DataFrame([{"user_id": "AWS-001", "group_name": "s3-admins"}])
    aws_policy_attach = pd.DataFrame(columns=["principal_type", "principal_id", "policy_name"])
    aws_users = pd.DataFrame([{"user_id": "AWS-001", "status": "active"}])

    okta_admin_roles = pd.DataFrame([{"okta_id": "OKTA-001", "admin_role": "APP_ADMIN"}])
    okta_group_membership = pd.DataFrame(columns=["okta_id", "group_name"])
    okta_aws_federation = pd.DataFrame(columns=["okta_group", "aws_role", "aws_declared_tier"])
    okta_users = pd.DataFrame([{"okta_id": "OKTA-001", "status": "ACTIVE"}])

    graph = build_privilege_graph(
        ad_groups_df=ad_groups,
        ad_membership_df=ad_membership,
        aws_groups_df=aws_groups,
        aws_policies_df=aws_policies,
        aws_user_groups_df=aws_user_groups,
        aws_policy_attach_df=aws_policy_attach,
        okta_admin_roles_df=okta_admin_roles,
        okta_group_membership_df=okta_group_membership,
        okta_aws_federation_df=okta_aws_federation,
        ad_users_df=ad_users,
        aws_users_df=aws_users,
        okta_users_df=okta_users,
    )

    # AD check: minimum tier of direct groups is 2
    ad_d, ad_eff, ad_path = compute_ad_account_privilege(graph, "AD-001")
    assert ad_d == 2
    assert ad_eff == 2
    assert ad_path == "AD: Prod-Deployers"

    # AWS check: direct group attached policy gives tier 2
    aws_d, aws_path = compute_aws_account_privilege(graph, "AWS-001")
    assert aws_d == 2
    assert aws_path == "AWS: direct/group policy"

    # Okta check: APP_ADMIN is tier 2
    okta_t, okta_path = compute_okta_account_privilege(graph, "OKTA-001")
    assert okta_t == 2
    assert okta_path == "Okta: admin role"


def test_aws_policy_attached_to_group() -> None:
    """AWS policies attached to groups via AWS_PolicyAttach (principal_type='group') are inherited."""
    empty_df = pd.DataFrame()
    aws_policies = pd.DataFrame([{"policy_name": "SecurityAudit", "declared_tier": 3}])
    aws_groups = pd.DataFrame([{"group_name": "sec-analysts", "attached_policies": ""}])
    aws_user_groups = pd.DataFrame([{"user_id": "AWS-GRP-ATTACH", "group_name": "sec-analysts"}])
    # Policy attached to group, not to user directly
    aws_policy_attach = pd.DataFrame(
        [
            {
                "principal_type": "group",
                "principal_id": "sec-analysts",
                "policy_name": "SecurityAudit",
            }
        ]
    )
    aws_users = pd.DataFrame([{"user_id": "AWS-GRP-ATTACH", "status": "active"}])

    graph = build_privilege_graph(
        ad_groups_df=empty_df,
        ad_membership_df=empty_df,
        aws_groups_df=aws_groups,
        aws_policies_df=aws_policies,
        aws_user_groups_df=aws_user_groups,
        aws_policy_attach_df=aws_policy_attach,
        okta_admin_roles_df=empty_df,
        okta_group_membership_df=empty_df,
        okta_aws_federation_df=empty_df,
        aws_users_df=aws_users,
    )

    aws_d, aws_path = compute_aws_account_privilege(graph, "AWS-GRP-ATTACH")
    assert aws_d == 3
    assert aws_path == "AWS: direct/group policy"


def test_multihop_nesting() -> None:
    """Multi-hop AD nesting resolves to highest privilege (tier 0) and formats grant path."""
    ad_groups = pd.DataFrame(
        [
            {"group_name": "Tier3-Support", "declared_tier": 3},
            {"group_name": "Middle-Tier", "declared_tier": 3},
            {"group_name": "Domain Admins", "declared_tier": 0},
        ]
    )
    ad_membership = pd.DataFrame(
        [
            {"member_type": "user", "member": "AD-NESTED", "group_name": "Tier3-Support"},
            {"member_type": "group", "member": "Tier3-Support", "group_name": "Middle-Tier"},
            {"member_type": "group", "member": "Middle-Tier", "group_name": "Domain Admins"},
        ]
    )
    ad_users = pd.DataFrame([{"account_id": "AD-NESTED", "enabled": True}])

    empty_df = pd.DataFrame()
    graph = build_privilege_graph(
        ad_groups_df=ad_groups,
        ad_membership_df=ad_membership,
        aws_groups_df=empty_df,
        aws_policies_df=empty_df,
        aws_user_groups_df=empty_df,
        aws_policy_attach_df=empty_df,
        okta_admin_roles_df=empty_df,
        okta_group_membership_df=empty_df,
        okta_aws_federation_df=empty_df,
        ad_users_df=ad_users,
    )

    ad_d, ad_eff, ad_path = compute_ad_account_privilege(graph, "AD-NESTED")
    assert ad_d == 3
    assert ad_eff == 0
    assert ad_path == "AD: Tier3-Support -> Middle-Tier -> Domain Admins"

    # Verify identity rollup correctly flags hidden escalation
    resolved_id = pd.DataFrame(
        [
            {
                "identity_id": "E-NESTED",
                "identity_kind": "human",
                "ad_account_id": "AD-NESTED",
                "aws_user_id": None,
                "okta_id": None,
            }
        ]
    )
    priv_df = compute_identity_privileges(graph, resolved_id)
    assert priv_df.loc[0, "ad_direct_tier"] == 3
    assert priv_df.loc[0, "ad_effective_tier"] == 0
    assert priv_df.loc[0, "overall_effective_tier"] == 0
    assert priv_df.loc[0, "hidden_escalation"] == 1
    assert priv_df.loc[0, "grant_path"] == "AD: Tier3-Support -> Middle-Tier -> Domain Admins"


def test_group_cycle_terminates() -> None:
    """Group cycles (A -> B -> A) terminate safely and select the shortest acyclic path."""
    ad_groups = pd.DataFrame(
        [
            {"group_name": "CycleGroupA", "declared_tier": 3},
            {"group_name": "CycleGroupB", "declared_tier": 3},
            {"group_name": "TargetServerAdmin", "declared_tier": 1},
        ]
    )
    # A -> B -> A cycle, with B also granting TargetServerAdmin
    ad_membership = pd.DataFrame(
        [
            {"member_type": "user", "member": "AD-CYCLIC", "group_name": "CycleGroupA"},
            {"member_type": "group", "member": "CycleGroupA", "group_name": "CycleGroupB"},
            {"member_type": "group", "member": "CycleGroupB", "group_name": "CycleGroupA"},
            {"member_type": "group", "member": "CycleGroupB", "group_name": "TargetServerAdmin"},
        ]
    )
    ad_users = pd.DataFrame([{"account_id": "AD-CYCLIC", "enabled": True}])

    empty_df = pd.DataFrame()
    graph = build_privilege_graph(
        ad_groups_df=ad_groups,
        ad_membership_df=ad_membership,
        aws_groups_df=empty_df,
        aws_policies_df=empty_df,
        aws_user_groups_df=empty_df,
        aws_policy_attach_df=empty_df,
        okta_admin_roles_df=empty_df,
        okta_group_membership_df=empty_df,
        okta_aws_federation_df=empty_df,
        ad_users_df=ad_users,
    )

    ad_d, ad_eff, ad_path = compute_ad_account_privilege(graph, "AD-CYCLIC")
    assert ad_d == 3
    assert ad_eff == 1
    # Shortest path without revisiting cycle nodes
    assert ad_path == "AD: CycleGroupA -> CycleGroupB -> TargetServerAdmin"


def test_federation_case() -> None:
    """Okta-to-AWS federation credits to aws_effective_tier while keeping okta_tier intact."""
    okta_users = pd.DataFrame([{"okta_id": "00u-FED", "status": "ACTIVE"}])
    okta_admin_roles = pd.DataFrame(columns=["okta_id", "admin_role"])
    okta_group_membership = pd.DataFrame([{"okta_id": "00u-FED", "group_name": "okta-aws-admins"}])
    okta_aws_federation = pd.DataFrame(
        [
            {
                "okta_group": "okta-aws-admins",
                "aws_role": "AdministratorAccess",
                "aws_declared_tier": 0,
            }
        ]
    )

    empty_df = pd.DataFrame()
    graph = build_privilege_graph(
        ad_groups_df=empty_df,
        ad_membership_df=empty_df,
        aws_groups_df=empty_df,
        aws_policies_df=empty_df,
        aws_user_groups_df=empty_df,
        aws_policy_attach_df=empty_df,
        okta_admin_roles_df=okta_admin_roles,
        okta_group_membership_df=okta_group_membership,
        okta_aws_federation_df=okta_aws_federation,
        okta_users_df=okta_users,
    )

    # Okta user has base tier 3 on Okta platform
    okta_t, _ = compute_okta_account_privilege(graph, "00u-FED")
    assert okta_t == 3

    # Federation gives tier 0 on AWS
    fed_t, fed_path = compute_federation_privilege(graph, "00u-FED")
    assert fed_t == 0
    assert fed_path == "Okta group okta-aws-admins -> AWS role AdministratorAccess (federation)"

    # Identity has NO native AWS account, but receives aws_effective_tier = 0
    resolved_id = pd.DataFrame(
        [
            {
                "identity_id": "E-FEDERATED",
                "identity_kind": "human",
                "ad_account_id": None,
                "aws_user_id": None,
                "okta_id": "00u-FED",
            }
        ]
    )
    priv_df = compute_identity_privileges(graph, resolved_id)
    assert priv_df.loc[0, "aws_direct_tier"] == 9
    assert priv_df.loc[0, "aws_effective_tier"] == 0
    assert priv_df.loc[0, "okta_tier"] == 3
    assert priv_df.loc[0, "overall_effective_tier"] == 0
    assert priv_df.loc[0, "hidden_escalation"] == 1
    assert (
        priv_df.loc[0, "grant_path"]
        == "Okta group okta-aws-admins -> AWS role AdministratorAccess (federation)"
    )


def test_no_access_account_tier_9() -> None:
    """Accounts with no access (disabled, inactive, deprovisioned, unlinked) score tier 9."""
    ad_users = pd.DataFrame([{"account_id": "AD-DISABLED", "enabled": False}])
    ad_groups = pd.DataFrame([{"group_name": "Domain Admins", "declared_tier": 0}])
    ad_membership = pd.DataFrame(
        [{"member_type": "user", "member": "AD-DISABLED", "group_name": "Domain Admins"}]
    )

    aws_users = pd.DataFrame([{"user_id": "AWS-INACTIVE", "status": "inactive"}])
    aws_policies = pd.DataFrame([{"policy_name": "AdministratorAccess", "declared_tier": 0}])
    aws_policy_attach = pd.DataFrame(
        [
            {
                "principal_type": "user",
                "principal_id": "AWS-INACTIVE",
                "policy_name": "AdministratorAccess",
            }
        ]
    )

    okta_users = pd.DataFrame([{"okta_id": "OKTA-DEPROV", "status": "DEPROVISIONED"}])
    okta_admin_roles = pd.DataFrame([{"okta_id": "OKTA-DEPROV", "admin_role": "SUPER_ADMIN"}])

    empty_df = pd.DataFrame()
    graph = build_privilege_graph(
        ad_groups_df=ad_groups,
        ad_membership_df=ad_membership,
        aws_groups_df=empty_df,
        aws_policies_df=aws_policies,
        aws_user_groups_df=empty_df,
        aws_policy_attach_df=aws_policy_attach,
        okta_admin_roles_df=okta_admin_roles,
        okta_group_membership_df=empty_df,
        okta_aws_federation_df=empty_df,
        ad_users_df=ad_users,
        aws_users_df=aws_users,
        okta_users_df=okta_users,
    )

    # Disabled AD account -> 9
    ad_d, ad_eff, ad_path = compute_ad_account_privilege(graph, "AD-DISABLED")
    assert ad_d == 9
    assert ad_eff == 9
    assert ad_path is None

    # Inactive AWS account -> 9
    aws_d, aws_path = compute_aws_account_privilege(graph, "AWS-INACTIVE")
    assert aws_d == 9
    assert aws_path is None

    # Deprovisioned Okta account -> 9
    okta_t, okta_path = compute_okta_account_privilege(graph, "OKTA-DEPROV")
    assert okta_t == 9
    assert okta_path is None

    # Overall rollup for identity with no active access -> 9 and default grant path
    resolved_id = pd.DataFrame(
        [
            {
                "identity_id": "E-NOACCESS",
                "identity_kind": "human",
                "ad_account_id": "AD-DISABLED",
                "aws_user_id": "AWS-INACTIVE",
                "okta_id": "OKTA-DEPROV",
            }
        ]
    )
    priv_df = compute_identity_privileges(graph, resolved_id)
    assert priv_df.loc[0, "ad_effective_tier"] == 9
    assert priv_df.loc[0, "aws_effective_tier"] == 9
    assert priv_df.loc[0, "okta_tier"] == 9
    assert priv_df.loc[0, "overall_effective_tier"] == 9
    assert priv_df.loc[0, "hidden_escalation"] == 0
    assert priv_df.loc[0, "grant_path"] == "AWS: direct/group policy"


# =============================================================================
# Integration Test with Committed Fixtures
# =============================================================================


def test_graph_fixtures_integration(fixture_dir: Path) -> None:
    """Test full privilege graph pipeline on committed tests/fixtures/ data."""
    hr_df = pd.read_parquet(fixture_dir / "HR_Records.parquet")
    ad_users_df = pd.read_parquet(fixture_dir / "AD_Users.parquet")
    aws_users_df = pd.read_parquet(fixture_dir / "AWS_Users.parquet")
    okta_users_df = pd.read_parquet(fixture_dir / "Okta_Users.parquet")

    ad_groups_df = pd.read_parquet(fixture_dir / "AD_Groups.parquet")
    ad_membership_df = pd.read_parquet(fixture_dir / "AD_GroupMembership.parquet")
    aws_groups_df = pd.read_parquet(fixture_dir / "AWS_Groups.parquet")
    aws_policies_df = pd.read_parquet(fixture_dir / "AWS_Policies.parquet")
    aws_user_groups_df = pd.read_parquet(fixture_dir / "AWS_UserGroups.parquet")
    aws_policy_attach_df = pd.read_parquet(fixture_dir / "AWS_PolicyAttach.parquet")
    okta_admin_roles_df = pd.read_parquet(fixture_dir / "Okta_AdminRoles.parquet")
    okta_group_membership_df = pd.read_parquet(fixture_dir / "Okta_GroupMembership.parquet")
    okta_aws_federation_df = pd.read_parquet(fixture_dir / "Okta_AWS_Federation.parquet")
    tier_mapping_df = pd.read_parquet(fixture_dir / "Tier_Mapping.parquet")

    # 1. Build privilege graph
    graph = build_privilege_graph(
        ad_groups_df=ad_groups_df,
        ad_membership_df=ad_membership_df,
        aws_groups_df=aws_groups_df,
        aws_policies_df=aws_policies_df,
        aws_user_groups_df=aws_user_groups_df,
        aws_policy_attach_df=aws_policy_attach_df,
        okta_admin_roles_df=okta_admin_roles_df,
        okta_group_membership_df=okta_group_membership_df,
        okta_aws_federation_df=okta_aws_federation_df,
        tier_mapping_df=tier_mapping_df,
        ad_users_df=ad_users_df,
        aws_users_df=aws_users_df,
        okta_users_df=okta_users_df,
    )
    assert isinstance(graph, nx.DiGraph)
    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0

    # 2. Run M2 identity resolution on fixtures
    res = resolve_identities(
        hr_df=hr_df,
        ad_df=ad_users_df,
        aws_df=aws_users_df,
        okta_df=okta_users_df,
    )
    assert not res.resolved_identities.empty

    # 3. Compute privileges for all resolved identities and unresolved accounts
    priv_df = compute_identity_privileges(
        graph=graph,
        resolved_identities=res.resolved_identities,
        unresolved_accounts=res.unresolved_accounts,
    )

    # Validate output schema
    expected_cols = [
        "identity_id",
        "identity_kind",
        "ad_direct_tier",
        "ad_effective_tier",
        "aws_direct_tier",
        "aws_effective_tier",
        "okta_tier",
        "overall_effective_tier",
        "hidden_escalation",
        "platforms_with_tier_le1",
        "grant_path",
    ]
    assert list(priv_df.columns) == expected_cols
    assert len(priv_df) == len(res.resolved_identities) + len(res.unresolved_accounts)

    # Validate tier ranges
    valid_tiers = {0, 1, 2, 3, 9}
    for col in [
        "ad_direct_tier",
        "ad_effective_tier",
        "aws_direct_tier",
        "aws_effective_tier",
        "okta_tier",
        "overall_effective_tier",
    ]:
        assert priv_df[col].isin(valid_tiers).all(), f"Invalid tiers in {col}"

    assert priv_df["hidden_escalation"].isin({0, 1}).all()
    assert priv_df["platforms_with_tier_le1"].between(0, 3).all()
    assert priv_df["grant_path"].notna().all()
