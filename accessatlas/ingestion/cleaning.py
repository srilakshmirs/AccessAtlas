"""Data cleaning helpers used by the converter and loader.

Each function documents WHY the cleaning rule exists, not just what it does.
These rules are also reflected in docs/data_dictionary.md.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Generic cleaners
# ---------------------------------------------------------------------------

_NA_STRINGS = {"n/a", "na", "n.a.", "none", "null", "-", ""}


def coerce_date(series: pd.Series) -> pd.Series:
    """Parse a date/datetime column, treating common 'missing' strings as NaT.

    WHY: HR_Offboarding stores 'n/a' in aws_access_removed_date when access
    was removed via another channel (e.g., Okta SSO deletion). pandas reads
    those cells as the string "n/a" rather than NaN, breaking datetime coercion.
    """
    # Replace known NA strings (case-insensitive) with actual NaN first.
    cleaned = series.where(
        ~series.astype(str).str.strip().str.lower().isin(_NA_STRINGS),
        other=np.nan,
    )
    return pd.to_datetime(cleaned, errors="coerce", utc=False)


def coerce_bool(series: pd.Series) -> pd.Series:
    """Normalise boolean-like values to Python bool (nullable).

    WHY: Spreadsheet tools sometimes store boolean columns as the strings
    'true'/'false' or 'TRUE'/'FALSE', or as integers 0/1. We convert all of
    these so downstream code can use `==` comparisons safely.
    """
    if series.dtype == bool or str(series.dtype) == "bool":
        # Always upcast Python bool to pandas nullable BooleanDtype so pandera
        # schema checks against Column("boolean") pass consistently.
        return series.astype("boolean")
    if pd.api.types.is_float_dtype(series) or pd.api.types.is_integer_dtype(series):
        # 0.0 → False, 1.0 → True, NaN → pd.NA
        return series.map(
            lambda v: pd.NA if pd.isna(v) else bool(int(v)),
        ).astype("boolean")

    str_map = {
        "true": True,
        "false": False,
        "1": True,
        "0": False,
        "yes": True,
        "no": False,
    }
    return (
        series.astype(str)
        .str.strip()
        .str.lower()
        .map(lambda v: str_map.get(v, pd.NA))
        .astype("boolean")
    )


# ---------------------------------------------------------------------------
# Per-sheet cleaning functions
# ---------------------------------------------------------------------------


def clean_hr_records(df: pd.DataFrame) -> pd.DataFrame:
    """Clean HR_Records.

    - termination_date: stored as NaT for active employees, 'n/a' for some.
    - hire_date: should always be a date; coerce just in case.
    """
    df = df.copy()
    df["hire_date"] = coerce_date(df["hire_date"])
    df["termination_date"] = coerce_date(df["termination_date"])
    return df


def clean_hr_offboarding(df: pd.DataFrame) -> pd.DataFrame:
    """Clean HR_Offboarding.

    - *_date columns: some platforms show 'n/a' when deactivation was done
      out-of-band; treat as null so date arithmetic doesn't crash.
    - all_platforms_revoked: stored as True/False object; cast to nullable bool.
    """
    df = df.copy()
    date_cols = [
        "termination_date",
        "ad_disabled_date",
        "okta_deactivated_date",
        "aws_access_removed_date",
    ]
    for col in date_cols:
        if col in df.columns:
            df[col] = coerce_date(df[col])
    if "all_platforms_revoked" in df.columns:
        df["all_platforms_revoked"] = coerce_bool(df["all_platforms_revoked"])
    return df


def clean_hr_role_changes(df: pd.DataFrame) -> pd.DataFrame:
    """Clean HR_RoleChanges — date column only."""
    df = df.copy()
    df["change_date"] = coerce_date(df["change_date"])
    return df


def clean_ad_users(df: pd.DataFrame) -> pd.DataFrame:
    """Clean AD_Users.

    - enabled: already bool from openpyxl, cast to nullable bool for consistency.
    - created_at / last_logon: coerce to datetime.
    """
    df = df.copy()
    for col in ("created_at", "last_logon"):
        if col in df.columns:
            df[col] = coerce_date(df[col])
    if "enabled" in df.columns:
        df["enabled"] = coerce_bool(df["enabled"])
    return df


def clean_aws_users(df: pd.DataFrame) -> pd.DataFrame:
    """Clean AWS_Users.

    - console_access / mfa_enabled: already bool; normalise to nullable bool.
    - created_at / password_last_used: coerce to datetime.
    """
    df = df.copy()
    for col in ("created_at", "password_last_used"):
        if col in df.columns:
            df[col] = coerce_date(df[col])
    for col in ("console_access", "mfa_enabled"):
        if col in df.columns:
            df[col] = coerce_bool(df[col])
    return df


def clean_okta_users(df: pd.DataFrame) -> pd.DataFrame:
    """Clean Okta_Users.

    - created_at / last_login: coerce to datetime.
    """
    df = df.copy()
    for col in ("created_at", "last_login"):
        if col in df.columns:
            df[col] = coerce_date(df[col])
    return df


def clean_okta_admin_roles(df: pd.DataFrame) -> pd.DataFrame:
    """Clean Okta_AdminRoles — assigned_at date."""
    df = df.copy()
    df["assigned_at"] = coerce_date(df["assigned_at"])
    return df


def clean_exceptions(df: pd.DataFrame) -> pd.DataFrame:
    """Clean Exceptions.

    - start_date / end_date: coerce to datetime.
    - revocation_confirmed: bool-like.
    """
    df = df.copy()
    for col in ("start_date", "end_date"):
        if col in df.columns:
            df[col] = coerce_date(df[col])
    if "revocation_confirmed" in df.columns:
        df["revocation_confirmed"] = coerce_bool(df["revocation_confirmed"])
    return df


def clean_on_call_roster(df: pd.DataFrame) -> pd.DataFrame:
    """Clean OnCall_Roster — shift dates."""
    df = df.copy()
    df["shift_start"] = coerce_date(df["shift_start"])
    df["shift_end"] = coerce_date(df["shift_end"])
    return df


def clean_api_tokens(df: pd.DataFrame) -> pd.DataFrame:
    """Clean API_Tokens — all *_at columns."""
    df = df.copy()
    for col in ("created_at", "last_rotated_at", "last_used_at"):
        if col in df.columns:
            df[col] = coerce_date(df[col])
    return df


def clean_audit_events(df: pd.DataFrame) -> pd.DataFrame:
    """Clean Audit_Events.

    - timestamp: coerce to datetime.
    - privileged_action / mfa_used: stored as 0/1 integers or NaN; cast to
      nullable bool. mfa_used is NaN for AD events where MFA is not tracked.
    """
    df = df.copy()
    df["timestamp"] = coerce_date(df["timestamp"])
    for col in ("privileged_action", "mfa_used"):
        if col in df.columns:
            df[col] = coerce_bool(df[col])
    return df


# ---------------------------------------------------------------------------
# Dispatch table — maps sheet name → cleaning function
# ---------------------------------------------------------------------------

CLEANERS: dict[str, callable] = {
    "HR_Records": clean_hr_records,
    "HR_RoleChanges": clean_hr_role_changes,
    "HR_Offboarding": clean_hr_offboarding,
    "AD_Users": clean_ad_users,
    "AWS_Users": clean_aws_users,
    "Okta_Users": clean_okta_users,
    "Okta_AdminRoles": clean_okta_admin_roles,
    "Exceptions": clean_exceptions,
    "OnCall_Roster": clean_on_call_roster,
    "API_Tokens": clean_api_tokens,
    "Audit_Events": clean_audit_events,
}
