"""Identity matching signals and conflict detection.

This module provides the matching signals (explicit ID, email, fuzzy name/username)
used to link platform accounts to HR employee records, along with conflict
detection logic.

WHY: Identity resolution must be explainable and deterministic:
1. Explicit IDs provide the strongest signal (confidence 1.0) because employee IDs
   are primary keys assigned by HR.
2. Email provides the next strongest signal (confidence 0.95) because enterprise
   mailboxes are usually unique, but contractor addresses may have domain or .ext variations.
3. Fuzzy matching via RapidFuzz provides a fallback for accounts with abbreviations,
   transpositions, or missing tags.
4. When signals point to conflicting HR employees, we never guess: the account is
   flagged as conflicting and sent to the unresolved list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import pandas as pd
from rapidfuzz import fuzz


@dataclass(frozen=True)
class AccountMatch:
    """Represents a candidate match of an account to an HR employee."""

    employee_id: str
    confidence: float
    signal: str  # "id", "email", or "fuzzy"
    detail: str


@dataclass(frozen=True)
class AccountResolution:
    """The outcome of resolving a single platform account."""

    is_resolved: bool
    platform: str
    account_id: str
    account_type: str
    employee_id: str | None = None
    confidence: float | None = None
    signal: str | None = None
    unresolved_reason: str | None = (
        None  # "orphan_account", "signal_conflict", "low_confidence", "invalid_id"
    )
    detail: str = ""


def normalize_email(email: str | None) -> tuple[str, str]:
    """Normalize an email address for matching.

    Returns a tuple of (normalized_email, base_email):
    - normalized_email: lowercased, stripped.
    - base_email: lowercased, stripped, with '.ext' contractor suffix removed from the local part.

    WHY: Contractors in HR or Okta/AD often use 'first.last.ext@domain' while another platform
    might record 'first.last@domain'. Normalizing both enables exact matching across worker types.
    """
    if not email or pd.isna(email):
        return "", ""
    clean = str(email).strip().lower()
    if "@" not in clean:
        return clean, clean
    local, domain = clean.split("@", 1)
    base_local = re.sub(r"\.ext$", "", local)
    return clean, f"{base_local}@{domain}"


def normalize_name(name: str | None) -> str:
    """Normalize a display name or full name for comparison."""
    if not name or pd.isna(name):
        return ""
    # Strip extra whitespace and lower case
    return " ".join(str(name).strip().lower().split())


def build_hr_index(hr_df: pd.DataFrame) -> dict[str, Any]:
    """Build fast lookup indexes from the HR_Records table.

    Indexes created:
    - id_to_emp: employee_id -> row dict
    - email_to_id: normalized_email -> employee_id
    - base_email_to_id: base_email_without_ext -> employee_id
    - name_profiles: list of precomputed name handles per employee for fuzzy matching
    """
    id_to_emp: dict[str, dict[str, Any]] = {}
    email_to_id: dict[str, str] = {}
    base_email_to_id: dict[str, str] = {}
    name_profiles: list[dict[str, Any]] = []

    for _, row in hr_df.iterrows():
        emp_id = str(row["employee_id"]).strip()
        first = str(row.get("first_name", "")).strip()
        last = str(row.get("last_name", "")).strip()
        email = row.get("email")

        emp_dict = {
            "employee_id": emp_id,
            "first_name": first,
            "last_name": last,
            "full_name": f"{first} {last}".strip(),
            "email": email,
            "worker_type": row.get("worker_type"),
            "status": row.get("status"),
        }
        id_to_emp[emp_id] = emp_dict

        if pd.notna(email):
            norm_email, base_email = normalize_email(email)
            if norm_email:
                email_to_id[norm_email] = emp_id
            if base_email and base_email not in base_email_to_id:
                base_email_to_id[base_email] = emp_id

        # Precompute canonical handles for fuzzy matching
        first_clean = first.lower()
        last_clean = last.lower()
        full_clean = f"{first_clean} {last_clean}".strip()
        flast = f"{first_clean[0]}{last_clean}" if first_clean else last_clean
        dot_name = f"{first_clean}.{last_clean}"
        hyphen_name = f"{first_clean}-{last_clean}"
        underscore_name = f"{first_clean}_{last_clean}"

        name_profiles.append(
            {
                "employee_id": emp_id,
                "full_name": full_clean,
                "handles": {flast, dot_name, hyphen_name, underscore_name},
            }
        )

    return {
        "id_to_emp": id_to_emp,
        "email_to_id": email_to_id,
        "base_email_to_id": base_email_to_id,
        "name_profiles": name_profiles,
    }


def compute_name_similarity(query: str, profile: dict[str, Any]) -> float:
    """Compute highest similarity score between an account handle/name and an HR profile.

    Scores against canonical handles (flast, first.last) and full name using RapidFuzz.
    """
    clean_query = query.strip().lower()
    if not clean_query:
        return 0.0

    # 1. Exact match with any canonical handle or full name gets 100.0
    if clean_query in profile["handles"] or clean_query == profile["full_name"]:
        return 100.0

    # 2. RapidFuzz ratio against canonical handles
    best_score = 0.0
    for handle in profile["handles"]:
        score = fuzz.ratio(clean_query, handle)
        if score > best_score:
            best_score = score

    # 3. Token sort ratio against full name (handles 'Last, First' or reordered tokens)
    token_score = fuzz.token_sort_ratio(clean_query, profile["full_name"])
    if token_score > best_score:
        best_score = token_score

    return float(best_score)


def match_account(
    platform: str,
    account_id: str,
    account_type: str,
    raw_id: str | None,
    raw_email: str | None,
    raw_username: str | None,
    raw_display_name: str | None,
    hr_index: dict[str, Any],
    fuzzy_threshold: float = 85.0,
) -> AccountResolution:
    """Match a single platform account to an HR record using tiered signals.

    Rules:
    1. Orphan accounts -> immediately unresolved (reason='orphan_account').
    2. Explicit ID checked against HR_Records (Signal: 'id', Confidence: 1.0).
    3. Email checked against HR_Records (Signal: 'email', Confidence: 0.95).
    4. Conflict check: if ID and Email point to different employees, or if ID/Email
       strongly contradicts a high-confidence name match, route to unresolved
       (reason='signal_conflict').
    5. Fallback: Fuzzy name/username matching if score >= fuzzy_threshold
       (Signal: 'fuzzy', Confidence: score / 100.0).
    6. If below threshold -> unresolved (reason='low_confidence').
    """
    # Rule 1: Orphan accounts are never forced into a link
    if account_type == "orphan":
        return AccountResolution(
            is_resolved=False,
            platform=platform,
            account_id=account_id,
            account_type=account_type,
            unresolved_reason="orphan_account",
            detail="Account is tagged as orphan; no HR record exists",
        )

    id_to_emp = hr_index["id_to_emp"]
    email_to_id = hr_index["email_to_id"]
    base_email_to_id = hr_index["base_email_to_id"]

    id_candidate: str | None = None
    email_candidate: str | None = None

    # Rule 2: Explicit ID
    if raw_id and pd.notna(raw_id):
        clean_id = str(raw_id).strip()
        if clean_id in id_to_emp:
            id_candidate = clean_id
        else:
            # An ID was provided but does not exist in HR
            # If no other signal exists, this is an invalid ID
            pass

    # Rule 3: Exact Email
    if raw_email and pd.notna(raw_email):
        norm_email, base_email = normalize_email(raw_email)
        if norm_email in email_to_id:
            email_candidate = email_to_id[norm_email]
        elif base_email in base_email_to_id:
            email_candidate = base_email_to_id[base_email]

    # Rule 4: Conflict detection between explicit ID and Email
    if id_candidate and email_candidate and id_candidate != email_candidate:
        return AccountResolution(
            is_resolved=False,
            platform=platform,
            account_id=account_id,
            account_type=account_type,
            unresolved_reason="signal_conflict",
            detail=f"Explicit ID points to {id_candidate} but email points to {email_candidate}",
        )

    # Name-based contradiction check when ID or Email is present:
    # If ID or email pointed to emp_A, verify that username/display_name does not strongly
    # match a different employee emp_B (>= 90%) while failing to match emp_A (< 50%).
    active_candidate = id_candidate or email_candidate
    name_query = raw_username or raw_display_name or ""
    clean_name_query = str(name_query).strip()

    if active_candidate and clean_name_query:
        # Check similarity to the matched employee
        profile_matched = next(
            (p for p in hr_index["name_profiles"] if p["employee_id"] == active_candidate),
            None,
        )
        score_matched = (
            compute_name_similarity(clean_name_query, profile_matched) if profile_matched else 0.0
        )

        # If name matches the candidate poorly, check if it matches someone else strongly
        if score_matched < 50.0:
            for p in hr_index["name_profiles"]:
                if p["employee_id"] != active_candidate:
                    other_score = compute_name_similarity(clean_name_query, p)
                    if other_score >= 90.0:
                        return AccountResolution(
                            is_resolved=False,
                            platform=platform,
                            account_id=account_id,
                            account_type=account_type,
                            unresolved_reason="signal_conflict",
                            detail=(
                                f"Account signal points to {active_candidate} (score {score_matched:.1f}), "
                                f"but name '{clean_name_query}' strongly points to {p['employee_id']} "
                                f"(score {other_score:.1f})"
                            ),
                        )

    # If ID matched without conflict:
    if id_candidate:
        return AccountResolution(
            is_resolved=True,
            platform=platform,
            account_id=account_id,
            account_type=account_type,
            employee_id=id_candidate,
            confidence=1.0,
            signal="id",
            detail=f"Matched by explicit ID {raw_id}",
        )

    # If Email matched without conflict:
    if email_candidate:
        return AccountResolution(
            is_resolved=True,
            platform=platform,
            account_id=account_id,
            account_type=account_type,
            employee_id=email_candidate,
            confidence=0.95,
            signal="email",
            detail=f"Matched by exact email {raw_email}",
        )

    # Rule 5: Fuzzy name / username matching fallback
    if clean_name_query:
        candidates_at_best: list[str] = []
        best_score = 0.0
        second_best_score = 0.0
        best_emp: str | None = None

        for profile in hr_index["name_profiles"]:
            score = compute_name_similarity(clean_name_query, profile)
            if score > best_score:
                second_best_score = best_score
                best_score = score
                best_emp = profile["employee_id"]
                candidates_at_best = [profile["employee_id"]]
            elif score == best_score and best_score > 0.0:
                candidates_at_best.append(profile["employee_id"])
            elif score > second_best_score:
                second_best_score = score

        if best_emp and best_score >= fuzzy_threshold:
            # Check for ambiguous match: multiple employees share the top score
            # or the top score is not clearly separated from the runner-up (< 3.0 points).
            if len(candidates_at_best) > 1 or (best_score - second_best_score < 3.0):
                return AccountResolution(
                    is_resolved=False,
                    platform=platform,
                    account_id=account_id,
                    account_type=account_type,
                    unresolved_reason="ambiguous_name",
                    detail=(
                        f"Ambiguous name match: {len(candidates_at_best)} employees share top score "
                        f"{best_score:.1f} (second best: {second_best_score:.1f})"
                    ),
                )

            return AccountResolution(
                is_resolved=True,
                platform=platform,
                account_id=account_id,
                account_type=account_type,
                employee_id=best_emp,
                confidence=round(best_score / 100.0, 4),
                signal="fuzzy",
                detail=f"Matched by fuzzy name comparison (score={best_score:.1f})",
            )

    # Rule 6: Low confidence / No match
    return AccountResolution(
        is_resolved=False,
        platform=platform,
        account_id=account_id,
        account_type=account_type,
        unresolved_reason="low_confidence",
        detail="No signal matched an HR employee above the required confidence threshold",
    )
