"""Identity resolution subpackage.

Links Active Directory, AWS, and Okta accounts to HR identities.
"""

from accessatlas.resolution.matcher import (
    AccountMatch,
    AccountResolution,
    build_hr_index,
    match_account,
    normalize_email,
    normalize_name,
)
from accessatlas.resolution.resolver import ResolutionResult, resolve_identities

__all__ = [
    "AccountMatch",
    "AccountResolution",
    "ResolutionResult",
    "build_hr_index",
    "match_account",
    "normalize_email",
    "normalize_name",
    "resolve_identities",
]
