"""Effective privilege tier and grant path computation.

This module computes platform-level direct and effective privilege tiers,
shortest grant paths, and cross-platform identity rollups with hidden escalation
detection.

WHY:
- Direct assignment is insufficient to evaluate blast radius: nesting and
  federation expand effective permissions beyond what platform administrators
  directly assign.
- Hidden escalation occurs when an identity's effective privilege reaches a
  privileged tier (tier <= 2) that is strictly higher than their direct
  entitlements via indirect paths (nested AD groups or Okta-to-AWS federation).
- BFS shortest-path traversal guarantees safe termination on cyclic group
  structures and produces deterministic, audit-traceable grant paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx
import pandas as pd


@dataclass(frozen=True)
class AccountPrivilege:
    """Privilege summary for a single platform account."""

    platform: str
    account_id: str
    direct_tier: int
    effective_tier: int
    grant_path: str | None


def compute_ad_account_privilege(graph: nx.DiGraph, account_id: str) -> tuple[int, int, str | None]:
    """Compute direct tier, effective tier, and shortest grant path for an AD account.

    Parameters
    ----------
    graph : nx.DiGraph
        Privilege graph containing AD user and group nodes.
    account_id : str
        Active Directory account identifier (e.g. "AD-000001").

    Returns
    -------
    tuple[int, int, str | None]
        (ad_direct_tier, ad_effective_tier, ad_grant_path)
    """
    u_node = f"ad:user:{account_id}"
    if not graph.has_node(u_node):
        return 9, 9, None

    # Disabled AD accounts carry no active privilege
    if not bool(graph.nodes[u_node].get("enabled", False)):
        return 9, 9, None

    # Direct tier: minimum declared tier among direct parent groups
    direct_groups = list(graph.successors(u_node))
    direct_tiers = [
        graph.nodes[g]["tier"] for g in direct_groups if graph.nodes[g].get("tier") is not None
    ]
    ad_direct_tier = min(direct_tiers) if direct_tiers else 9

    # Effective tier: minimum declared tier across all reachable groups
    lengths = nx.single_source_shortest_path_length(graph, u_node)
    paths = nx.single_source_shortest_path(graph, u_node)

    cand_groups = [
        n for n in lengths if n.startswith("ad:group:") and graph.nodes[n].get("tier") is not None
    ]
    if not cand_groups:
        return ad_direct_tier, 9, None

    min_tier = min(graph.nodes[n]["tier"] for n in cand_groups)
    ad_effective_tier = min_tier

    best_candidates = [n for n in cand_groups if graph.nodes[n]["tier"] == min_tier]
    # Deterministic tie-breaker: shortest distance first, then alphabetical by group name
    best_candidates.sort(key=lambda n: (lengths[n], graph.nodes[n].get("name", n)))
    best_target = best_candidates[0]
    best_path = paths[best_target]

    group_names = [graph.nodes[n].get("name", n.split(":")[-1]) for n in best_path if n != u_node]
    if len(group_names) == 1:
        ad_grant_path = f"AD: {group_names[0]}"
    else:
        ad_grant_path = f"AD: {' -> '.join(group_names)}"

    return ad_direct_tier, ad_effective_tier, ad_grant_path


def compute_aws_account_privilege(graph: nx.DiGraph, user_id: str) -> tuple[int, str | None]:
    """Compute direct tier and grant path for a native AWS IAM account.

    Parameters
    ----------
    graph : nx.DiGraph
        Privilege graph containing AWS user, group, and policy nodes.
    user_id : str
        AWS IAM user identifier (e.g. "AWS-USR-000001").

    Returns
    -------
    tuple[int, str | None]
        (aws_direct_tier, aws_direct_path)
    """
    u_node = f"aws:user:{user_id}"
    if not graph.has_node(u_node):
        return 9, None

    status = str(graph.nodes[u_node].get("status", "active")).lower()
    if status != "active":
        return 9, None

    lengths = nx.single_source_shortest_path_length(graph, u_node)
    cand_pols = [
        n for n in lengths if n.startswith("aws:policy:") and graph.nodes[n].get("tier") is not None
    ]
    if not cand_pols:
        return 9, None

    aws_direct_tier = min(graph.nodes[n]["tier"] for n in cand_pols)
    return aws_direct_tier, "AWS: direct/group policy"


def compute_okta_account_privilege(graph: nx.DiGraph, okta_id: str) -> tuple[int, str | None]:
    """Compute native platform tier and grant path for an Okta account.

    Parameters
    ----------
    graph : nx.DiGraph
        Privilege graph containing Okta user and role nodes.
    okta_id : str
        Okta user internal identifier.

    Returns
    -------
    tuple[int, str | None]
        (okta_tier, okta_path)
    """
    u_node = f"okta:user:{okta_id}"
    if not graph.has_node(u_node):
        return 9, None

    status = str(graph.nodes[u_node].get("status", "ACTIVE")).upper()
    if status == "DEPROVISIONED":
        return 9, None

    roles = [n for n in graph.successors(u_node) if n.startswith("okta:role:")]
    role_tiers = [graph.nodes[r]["tier"] for r in roles if graph.nodes[r].get("tier") is not None]
    if role_tiers:
        return min(role_tiers), "Okta: admin role"

    # Active or suspended Okta users without an admin role have standard tier 3 access
    return 3, "Okta: admin role"


def compute_federation_privilege(graph: nx.DiGraph, okta_id: str) -> tuple[int, str | None]:
    """Compute AWS tier and grant path gained via Okta-to-AWS SAML federation.

    Parameters
    ----------
    graph : nx.DiGraph
        Privilege graph containing Okta group and AWS role federation edges.
    okta_id : str
        Okta user identifier.

    Returns
    -------
    tuple[int, str | None]
        (federation_aws_tier, federation_grant_path)
    """
    u_node = f"okta:user:{okta_id}"
    if not graph.has_node(u_node):
        return 9, None

    status = str(graph.nodes[u_node].get("status", "ACTIVE")).upper()
    if status == "DEPROVISIONED":
        return 9, None

    lengths = nx.single_source_shortest_path_length(graph, u_node)
    paths = nx.single_source_shortest_path(graph, u_node)

    cand_roles = [
        n for n in lengths if n.startswith("aws:role:") and graph.nodes[n].get("tier") is not None
    ]
    if not cand_roles:
        return 9, None

    min_fed_tier = min(graph.nodes[n]["tier"] for n in cand_roles)
    best_candidates = [n for n in cand_roles if graph.nodes[n]["tier"] == min_fed_tier]
    best_candidates.sort(key=lambda n: (lengths[n], graph.nodes[n].get("name", n)))
    best_path = paths[best_candidates[0]]

    # Path structure: okta:user -> okta:group -> aws:role
    og_node = best_path[1]
    ar_node = best_path[2]
    og_name = graph.nodes[og_node].get("name", og_node.split(":")[-1])
    ar_name = graph.nodes[ar_node].get("name", ar_node.split(":")[-1])

    fed_path = f"Okta group {og_name} -> AWS role {ar_name} (federation)"
    return min_fed_tier, fed_path


def compute_identity_privileges(
    graph: nx.DiGraph,
    resolved_identities: pd.DataFrame,
    unresolved_accounts: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """Compute effective privilege tiers and grant paths for canonical identities.

    Rolls up account entitlements across AD, AWS, and Okta into an identity-level
    privilege record, crediting cross-platform federation to aws_effective_tier,
    evaluating hidden escalation, and counting privileged platforms (tier <= 1).

    Parameters
    ----------
    graph : nx.DiGraph
        Constructed multi-platform privilege graph.
    resolved_identities : pd.DataFrame
        Resolved identity records with platform account links.
    unresolved_accounts : pd.DataFrame | None, optional
        Unresolved accounts (e.g., orphan accounts) to include in privilege scoring.

    Returns
    -------
    pd.DataFrame
        Privilege table with columns:
        - identity_id
        - identity_kind
        - ad_direct_tier
        - ad_effective_tier
        - aws_direct_tier
        - aws_effective_tier
        - okta_tier
        - overall_effective_tier
        - hidden_escalation
        - platforms_with_tier_le1
        - grant_path
    """
    rows: list[dict[str, Any]] = []

    # 1. Process resolved identities (human and service)
    for _, row in resolved_identities.iterrows():
        ident_id = str(row["identity_id"])
        ident_kind = str(row.get("identity_kind", "human"))
        ad_acc = row.get("ad_account_id")
        aws_acc = row.get("aws_user_id")
        okta_acc = row.get("okta_id")

        ad_d, ad_eff, ad_path = (
            compute_ad_account_privilege(graph, str(ad_acc)) if pd.notna(ad_acc) else (9, 9, None)
        )
        aws_d, aws_d_path = (
            compute_aws_account_privilege(graph, str(aws_acc)) if pd.notna(aws_acc) else (9, None)
        )
        okta_t, okta_path = (
            compute_okta_account_privilege(graph, str(okta_acc))
            if pd.notna(okta_acc)
            else (9, None)
        )
        fed_t, fed_path = (
            compute_federation_privilege(graph, str(okta_acc)) if pd.notna(okta_acc) else (9, None)
        )

        # Federation credits to aws_effective_tier
        aws_eff = min(aws_d, fed_t)
        if fed_t <= aws_d and fed_t < 9:
            aws_eff_path = fed_path
        elif aws_d < 9:
            aws_eff_path = "AWS: direct/group policy"
        else:
            aws_eff_path = None

        overall_eff = min(ad_eff, aws_eff, okta_t)
        overall_direct = min(ad_d, aws_d, okta_t)

        platforms_le1 = int(ad_eff <= 1) + int(aws_eff <= 1) + int(okta_t <= 1)

        # Winning grant path selection (tie-breaker order: AD > AWS > Okta)
        if overall_eff == 9:
            winning_path = "AWS: direct/group policy"
        elif ad_eff == overall_eff:
            winning_path = ad_path or "AD: direct"
        elif aws_eff == overall_eff:
            winning_path = aws_eff_path or "AWS: direct/group policy"
        else:
            winning_path = okta_path or "Okta: admin role"

        # Hidden escalation definition:
        # Reached tier <= 2, strictly lower than overall direct tier, via nesting or federation
        is_escalation = int(
            (overall_eff <= 2)
            and (overall_eff < overall_direct)
            and ((" -> " in winning_path) or ("(federation)" in winning_path))
        )

        rows.append(
            {
                "identity_id": ident_id,
                "identity_kind": ident_kind,
                "ad_direct_tier": ad_d,
                "ad_effective_tier": ad_eff,
                "aws_direct_tier": aws_d,
                "aws_effective_tier": aws_eff,
                "okta_tier": okta_t,
                "overall_effective_tier": overall_eff,
                "hidden_escalation": is_escalation,
                "platforms_with_tier_le1": platforms_le1,
                "grant_path": winning_path,
            }
        )

    # 2. Process unresolved accounts (e.g. orphan accounts) if provided
    if unresolved_accounts is not None and not unresolved_accounts.empty:
        for _, row in unresolved_accounts.iterrows():
            acc_id = str(row["account_id"])
            plat = str(row["platform"]).lower()
            acc_type = str(row.get("account_type", "orphan"))

            ad_d, ad_eff, ad_path = (
                compute_ad_account_privilege(graph, acc_id) if plat == "ad" else (9, 9, None)
            )
            aws_d, aws_d_path = (
                compute_aws_account_privilege(graph, acc_id) if plat == "aws" else (9, None)
            )
            okta_t, okta_path = (
                compute_okta_account_privilege(graph, acc_id) if plat == "okta" else (9, None)
            )
            fed_t, fed_path = (
                compute_federation_privilege(graph, acc_id) if plat == "okta" else (9, None)
            )

            aws_eff = min(aws_d, fed_t)
            if fed_t <= aws_d and fed_t < 9:
                aws_eff_path = fed_path
            elif aws_d < 9:
                aws_eff_path = "AWS: direct/group policy"
            else:
                aws_eff_path = None

            overall_eff = min(ad_eff, aws_eff, okta_t)
            overall_direct = min(ad_d, aws_d, okta_t)
            platforms_le1 = int(ad_eff <= 1) + int(aws_eff <= 1) + int(okta_t <= 1)

            if overall_eff == 9:
                winning_path = "AWS: direct/group policy"
            elif ad_eff == overall_eff:
                winning_path = ad_path or "AD: direct"
            elif aws_eff == overall_eff:
                winning_path = aws_eff_path or "AWS: direct/group policy"
            else:
                winning_path = okta_path or "Okta: admin role"

            is_escalation = int(
                (overall_eff <= 2)
                and (overall_eff < overall_direct)
                and ((" -> " in winning_path) or ("(federation)" in winning_path))
            )

            rows.append(
                {
                    "identity_id": acc_id,
                    "identity_kind": acc_type,
                    "ad_direct_tier": ad_d,
                    "ad_effective_tier": ad_eff,
                    "aws_direct_tier": aws_d,
                    "aws_effective_tier": aws_eff,
                    "okta_tier": okta_t,
                    "overall_effective_tier": overall_eff,
                    "hidden_escalation": is_escalation,
                    "platforms_with_tier_le1": platforms_le1,
                    "grant_path": winning_path,
                }
            )

    return pd.DataFrame(rows)
