"""Privilege graph construction across Active Directory, AWS IAM, and Okta.

This module constructs a unified NetworkX DiGraph linking platform accounts,
groups, nested groups, policies, roles, and cross-platform federation edges.

WHY:
- Direct assignment alone obscures indirect privilege (nested AD groups or
  federated AWS access through Okta).
- A unified directed graph allows exact shortest-path traversal to compute
  effective privilege tiers and determine whether privileged access was granted
  via hidden escalation.
- Modeling platform entities as typed nodes and relationships as directed edges
  makes graph traversal cycle-safe and independent of dataset scale.
"""

from __future__ import annotations

import networkx as nx
import pandas as pd


def build_privilege_graph(
    ad_groups_df: pd.DataFrame,
    ad_membership_df: pd.DataFrame,
    aws_groups_df: pd.DataFrame,
    aws_policies_df: pd.DataFrame,
    aws_user_groups_df: pd.DataFrame,
    aws_policy_attach_df: pd.DataFrame,
    okta_admin_roles_df: pd.DataFrame,
    okta_group_membership_df: pd.DataFrame,
    okta_aws_federation_df: pd.DataFrame,
    tier_mapping_df: pd.DataFrame | None = None,
    ad_users_df: pd.DataFrame | None = None,
    aws_users_df: pd.DataFrame | None = None,
    okta_users_df: pd.DataFrame | None = None,
) -> nx.DiGraph:
    """Build a unified directed privilege graph across AD, AWS, and Okta.

    Parameters
    ----------
    ad_groups_df : pd.DataFrame
        Active Directory groups with declared_tier.
    ad_membership_df : pd.DataFrame
        AD group memberships (user-to-group and group-to-group nesting).
    aws_groups_df : pd.DataFrame
        AWS IAM groups with attached_policies.
    aws_policies_df : pd.DataFrame
        AWS IAM policies with declared_tier.
    aws_user_groups_df : pd.DataFrame
        AWS IAM user group memberships.
    aws_policy_attach_df : pd.DataFrame
        AWS IAM policy attachments directly to users or groups.
    okta_admin_roles_df : pd.DataFrame
        Okta admin role assignments.
    okta_group_membership_df : pd.DataFrame
        Okta group memberships.
    okta_aws_federation_df : pd.DataFrame
        Okta-to-AWS federation mappings (okta_group -> aws_role, aws_declared_tier).
    tier_mapping_df : pd.DataFrame | None, optional
        Standard common tier mappings across platforms.
    ad_users_df : pd.DataFrame | None, optional
        AD users table containing account_id and enabled flag.
    aws_users_df : pd.DataFrame | None, optional
        AWS users table containing user_id and status flag.
    okta_users_df : pd.DataFrame | None, optional
        Okta users table containing okta_id and status flag.

    Returns
    -------
    nx.DiGraph
        Directed graph with typed nodes and directed permission inheritance edges.
    """
    graph = nx.DiGraph()

    # -------------------------------------------------------------------------
    # 1. Active Directory (AD) Subgraph
    # -------------------------------------------------------------------------
    # Group nodes with declared tiers
    ad_tiers: dict[str, int] = {}
    if "declared_tier" in ad_groups_df.columns:
        ad_tiers.update(dict(zip(ad_groups_df["group_name"], ad_groups_df["declared_tier"])))

    if tier_mapping_df is not None and not tier_mapping_df.empty:
        ad_tm = tier_mapping_df[tier_mapping_df["platform"] == "ad"]
        for _, r in ad_tm.iterrows():
            grp = r["role_or_group"]
            if grp not in ad_tiers:
                ad_tiers[grp] = int(r["common_tier"])

    for _, row in ad_groups_df.iterrows():
        gname = str(row["group_name"])
        tier = ad_tiers.get(gname)
        graph.add_node(
            f"ad:group:{gname}",
            kind="group",
            platform="ad",
            name=gname,
            tier=int(tier) if tier is not None and pd.notna(tier) else None,
        )

    # User nodes
    sam_to_acc: dict[str, str] = {}
    if ad_users_df is not None and not ad_users_df.empty:
        for _, row in ad_users_df.iterrows():
            acc_id = str(row["account_id"])
            sam = str(row.get("sam_account_name", ""))
            if sam:
                sam_to_acc[sam] = acc_id
            enabled_val = row.get("enabled", True)
            is_enabled = bool(enabled_val) and not pd.isna(enabled_val)
            graph.add_node(
                f"ad:user:{acc_id}",
                kind="user",
                platform="ad",
                account_id=acc_id,
                enabled=is_enabled,
            )

    # Memberships (user -> group, child_group -> parent_group)
    for _, row in ad_membership_df.iterrows():
        m_type = str(row["member_type"])
        raw_member = str(row["member"])
        gname = str(row["group_name"])
        parent_node = f"ad:group:{gname}"

        if not graph.has_node(parent_node):
            tier = ad_tiers.get(gname)
            graph.add_node(
                parent_node,
                kind="group",
                platform="ad",
                name=gname,
                tier=int(tier) if tier is not None and pd.notna(tier) else None,
            )

        if m_type == "user":
            # Map sam_account_name to account_id if applicable, otherwise use raw_member
            acc_id = sam_to_acc.get(raw_member, raw_member)
            u_node = f"ad:user:{acc_id}"
            if not graph.has_node(u_node):
                graph.add_node(
                    u_node,
                    kind="user",
                    platform="ad",
                    account_id=acc_id,
                    enabled=True,
                )
            graph.add_edge(u_node, parent_node, rel="member_of")
        else:
            # Group nesting: member is child group
            child_node = f"ad:group:{raw_member}"
            if not graph.has_node(child_node):
                tier = ad_tiers.get(raw_member)
                graph.add_node(
                    child_node,
                    kind="group",
                    platform="ad",
                    name=raw_member,
                    tier=int(tier) if tier is not None and pd.notna(tier) else None,
                )
            graph.add_edge(child_node, parent_node, rel="member_of")

    # -------------------------------------------------------------------------
    # 2. AWS IAM Subgraph
    # -------------------------------------------------------------------------
    aws_tiers: dict[str, int] = {}
    if "declared_tier" in aws_policies_df.columns:
        aws_tiers.update(
            dict(zip(aws_policies_df["policy_name"], aws_policies_df["declared_tier"]))
        )

    if tier_mapping_df is not None and not tier_mapping_df.empty:
        aws_tm = tier_mapping_df[tier_mapping_df["platform"] == "aws"]
        for _, r in aws_tm.iterrows():
            pol = r["role_or_group"]
            if pol not in aws_tiers:
                aws_tiers[pol] = int(r["common_tier"])

    for pol, t in aws_tiers.items():
        graph.add_node(
            f"aws:policy:{pol}",
            kind="policy",
            platform="aws",
            name=pol,
            tier=int(t),
        )

    # AWS Users
    if aws_users_df is not None and not aws_users_df.empty:
        for _, row in aws_users_df.iterrows():
            uid = str(row["user_id"])
            status = str(row.get("status", "active"))
            graph.add_node(
                f"aws:user:{uid}",
                kind="user",
                platform="aws",
                user_id=uid,
                status=status,
            )

    # AWS Groups and attached policies
    for _, row in aws_groups_df.iterrows():
        gname = str(row["group_name"])
        g_node = f"aws:group:{gname}"
        graph.add_node(g_node, kind="group", platform="aws", name=gname)
        pols = str(row.get("attached_policies", "")).split("|")
        for pol in pols:
            pol = pol.strip()
            if pol:
                p_node = f"aws:policy:{pol}"
                if not graph.has_node(p_node):
                    t = aws_tiers.get(pol, 3)
                    graph.add_node(p_node, kind="policy", platform="aws", name=pol, tier=int(t))
                graph.add_edge(g_node, p_node, rel="attached_policy")

    # AWS User Groups
    for _, row in aws_user_groups_df.iterrows():
        uid = str(row["user_id"])
        gname = str(row["group_name"])
        u_node = f"aws:user:{uid}"
        g_node = f"aws:group:{gname}"
        if not graph.has_node(u_node):
            graph.add_node(u_node, kind="user", platform="aws", user_id=uid, status="active")
        if not graph.has_node(g_node):
            graph.add_node(g_node, kind="group", platform="aws", name=gname)
        graph.add_edge(u_node, g_node, rel="member_of")

    # AWS Direct Policy Attachments
    for _, row in aws_policy_attach_df.iterrows():
        p_type = str(row.get("principal_type", "user")).lower()
        p_id = str(row["principal_id"])
        pol = str(row["policy_name"])
        p_node = f"aws:policy:{pol}"
        if not graph.has_node(p_node):
            t = aws_tiers.get(pol, 3)
            graph.add_node(p_node, kind="policy", platform="aws", name=pol, tier=int(t))

        target_node = f"aws:{p_type}:{p_id}"
        if not graph.has_node(target_node):
            graph.add_node(target_node, kind=p_type, platform="aws", status="active")
        graph.add_edge(target_node, p_node, rel="attached_policy")

    # -------------------------------------------------------------------------
    # 3. Okta Subgraph & AWS Federation
    # -------------------------------------------------------------------------
    okta_role_tiers: dict[str, int] = {}
    if tier_mapping_df is not None and not tier_mapping_df.empty:
        okta_tm = tier_mapping_df[tier_mapping_df["platform"] == "okta"]
        for _, r in okta_tm.iterrows():
            role_name = str(r["role_or_group"])
            okta_role_tiers[role_name] = int(r["common_tier"])
    else:
        try:
            from accessatlas.utils import load_config

            cfg = load_config()
            cfg_roles = cfg.get("privilege", {}).get("okta_roles", {})
            okta_role_tiers = {str(k): int(v) for k, v in cfg_roles.items()}
        except Exception:
            okta_role_tiers = {}

    for rname, t in okta_role_tiers.items():
        graph.add_node(
            f"okta:role:{rname}",
            kind="role",
            platform="okta",
            name=rname,
            tier=int(t),
        )

    # Okta Users
    if okta_users_df is not None and not okta_users_df.empty:
        for _, row in okta_users_df.iterrows():
            oid = str(row["okta_id"])
            status = str(row.get("status", "ACTIVE"))
            graph.add_node(
                f"okta:user:{oid}",
                kind="user",
                platform="okta",
                okta_id=oid,
                status=status,
            )

    # Okta Admin Roles
    for _, row in okta_admin_roles_df.iterrows():
        oid = str(row["okta_id"])
        role_type = str(row["admin_role"])
        u_node = f"okta:user:{oid}"
        r_node = f"okta:role:{role_type}"
        if not graph.has_node(u_node):
            graph.add_node(u_node, kind="user", platform="okta", okta_id=oid, status="ACTIVE")
        if not graph.has_node(r_node):
            t = okta_role_tiers.get(role_type, 3)
            graph.add_node(r_node, kind="role", platform="okta", name=role_type, tier=int(t))
        graph.add_edge(u_node, r_node, rel="admin_role")

    # Okta Group Membership
    for _, row in okta_group_membership_df.iterrows():
        oid = str(row["okta_id"])
        gname = str(row["group_name"])
        u_node = f"okta:user:{oid}"
        g_node = f"okta:group:{gname}"
        if not graph.has_node(u_node):
            graph.add_node(u_node, kind="user", platform="okta", okta_id=oid, status="ACTIVE")
        if not graph.has_node(g_node):
            graph.add_node(g_node, kind="group", platform="okta", name=gname)
        graph.add_edge(u_node, g_node, rel="member_of")

    # Okta-to-AWS Federation
    for _, row in okta_aws_federation_df.iterrows():
        og = str(row["okta_group"])
        ar = str(row["aws_role"])
        fed_tier = int(row["aws_declared_tier"])
        og_node = f"okta:group:{og}"
        ar_node = f"aws:role:{ar}"
        if not graph.has_node(og_node):
            graph.add_node(og_node, kind="group", platform="okta", name=og)
        graph.add_node(
            ar_node,
            kind="role",
            platform="aws",
            name=ar,
            tier=fed_tier,
        )
        graph.add_edge(og_node, ar_node, rel="federates_to", tier=fed_tier)

    return graph
