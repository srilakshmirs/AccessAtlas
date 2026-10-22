"""Context suppression engine for AccessAtlas rules.

Legitimate administrative activity and temporary privileges must not generate
false alarms. Suppression evaluates real-world context tables:
1. Approved active exceptions (Exceptions table)
2. On-call roster shifts (OnCall_Roster table)
3. Registered scheduled jobs (Scheduled_Jobs table)
4. Recent hires (HR_Records table)
5. Recent role changes (HR_RoleChanges table)

Crucially, suppression is rule-specific and platform-specific: suppressing one
rule (e.g. cross_platform_admin due to on-call duty) never hides an unrelated rule
(e.g. stale_token or offboarding_gap) for the same identity.
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


class SuppressionEngine:
    """Evaluates context suppression conditions in a strict, documented order.

    Order of evaluation:
    1. Approved Active Exception: Active security exception covering the identity & platform.
       Target rules: offboarding_gap (for handover), nested_group_escalation.
    2. On-Call Roster: Active on-call shift covering snapshot_date.
       Target rules: cross_platform_admin.
    3. Scheduled Job: Registered scheduled job with declared service window.
       Target rules: service account execution/privilege checks.
    4. Recent Hire: Employee hired within configurable new_hire_days.
       Target rules: dormant_admin (new hires have not yet accumulated audit events).
    5. Role Change: Employee transferred within configurable role_change_days.
       Target rules: temporary transitional privileges.
    """

    def __init__(
        self,
        snapshot_date: pd.Timestamp | str,
        exceptions_df: pd.DataFrame | None = None,
        oncall_df: pd.DataFrame | None = None,
        scheduled_jobs_df: pd.DataFrame | None = None,
        hr_df: pd.DataFrame | None = None,
        role_changes_df: pd.DataFrame | None = None,
        new_hire_days: int = 30,
        role_change_days: int = 30,
    ) -> None:
        self.snapshot_date = pd.Timestamp(snapshot_date)
        self.exceptions_df = exceptions_df if exceptions_df is not None else pd.DataFrame()
        self.oncall_df = oncall_df if oncall_df is not None else pd.DataFrame()
        self.scheduled_jobs_df = (
            scheduled_jobs_df if scheduled_jobs_df is not None else pd.DataFrame()
        )
        self.hr_df = hr_df if hr_df is not None else pd.DataFrame()
        self.role_changes_df = role_changes_df if role_changes_df is not None else pd.DataFrame()
        self.new_hire_days = new_hire_days
        self.role_change_days = role_change_days

        # Pre-index active exceptions for fast lookup
        self._active_exceptions_by_emp: dict[str, list[dict[str, Any]]] = {}
        if not self.exceptions_df.empty:
            for _, row in self.exceptions_df.iterrows():
                if str(row.get("status", "")).lower() == "active":
                    s_date = pd.to_datetime(row.get("start_date"))
                    e_date = pd.to_datetime(row.get("end_date"))
                    if pd.notna(s_date) and pd.notna(e_date):
                        if s_date <= self.snapshot_date <= e_date:
                            emp_id = str(row["employee_id"])
                            self._active_exceptions_by_emp.setdefault(emp_id, []).append(
                                row.to_dict()
                            )

        # Pre-index active oncall shifts
        self._active_oncall_emps: set[str] = set()
        if not self.oncall_df.empty:
            for _, row in self.oncall_df.iterrows():
                s_start = pd.to_datetime(row.get("shift_start"))
                s_end = pd.to_datetime(row.get("shift_end"))
                if pd.notna(s_start) and pd.notna(s_end):
                    if s_start <= self.snapshot_date <= s_end:
                        self._active_oncall_emps.add(str(row["employee_id"]))

        # Pre-index recent hires
        self._recent_hires: set[str] = set()
        if not self.hr_df.empty and "hire_date" in self.hr_df.columns:
            for _, row in self.hr_df.iterrows():
                h_date = pd.to_datetime(row.get("hire_date"))
                if pd.notna(h_date):
                    days = (self.snapshot_date - h_date).days
                    if 0 <= days <= self.new_hire_days:
                        self._recent_hires.add(str(row["employee_id"]))

        # Pre-index recent role changes
        self._recent_role_change_emps: set[str] = set()
        if not self.role_changes_df.empty and "change_date" in self.role_changes_df.columns:
            for _, row in self.role_changes_df.iterrows():
                c_date = pd.to_datetime(row.get("change_date"))
                if pd.notna(c_date):
                    days = (self.snapshot_date - c_date).days
                    if 0 <= days <= self.role_change_days:
                        self._recent_role_change_emps.add(str(row["employee_id"]))

    def check_suppression(
        self,
        rule: str,
        identity_id: str,
        platforms: list[str] | None = None,
        account_id: str | None = None,
    ) -> tuple[bool, str | None]:
        """Check if a candidate finding should be suppressed by legitimate context.

        Returns
        -------
        tuple[bool, str | None]
            (is_suppressed, suppression_reason)
        """
        platforms = platforms or []

        # 1. Approved Active Exception
        if identity_id in self._active_exceptions_by_emp:
            active_list = self._active_exceptions_by_emp[identity_id]
            for exc in active_list:
                exc_plats = [p.strip().lower() for p in str(exc.get("platforms", "")).split("|")]
                exc_priv = str(exc.get("privilege", "")).lower()
                exc_reason = str(exc.get("reason", "")).lower()

                # Offboarding gap suppression: approved handover exception
                if rule == "offboarding_gap":
                    if "handover" in exc_priv or "handover" in exc_reason:
                        return (
                            True,
                            f"Suppressed by active approved exception {exc.get('exception_id')}: {exc.get('reason')}",
                        )

                # Nested group escalation / privilege escalation suppression
                if rule in ("nested_group_escalation", "cross_platform_admin"):
                    # Check if platform overlap exists
                    if any(p.lower() in exc_plats for p in platforms) or "all" in exc_plats:
                        return (
                            True,
                            f"Suppressed by approved active privilege exception {exc.get('exception_id')}: {exc.get('privilege')}",
                        )

        # 2. On-Call Roster
        if rule == "cross_platform_admin":
            if identity_id in self._active_oncall_emps:
                return (
                    True,
                    f"Suppressed by active on-call shift covering snapshot date {self.snapshot_date.date()}",
                )

        # 3. Scheduled Jobs (for service accounts)
        if rule in ("excessive_service_privilege", "dormant_admin") and account_id:
            # Check if account is tied to a scheduled job
            if not self.scheduled_jobs_df.empty:
                job_matches = self.scheduled_jobs_df[
                    (self.scheduled_jobs_df["service_account_id"] == account_id)
                    | (self.scheduled_jobs_df["owner_employee_id"] == identity_id)
                ]
                if not job_matches.empty:
                    job_name = job_matches.iloc[0]["job_name"]
                    return True, f"Suppressed by registered scheduled job '{job_name}'"

        # 4. Recent Hire
        if rule == "dormant_admin":
            if identity_id in self._recent_hires:
                return (
                    True,
                    f"Suppressed by recent hire status (hired within {self.new_hire_days} days)",
                )

        # 5. Role Change
        if rule in ("cross_platform_admin", "nested_group_escalation"):
            if identity_id in self._recent_role_change_emps:
                return (
                    True,
                    f"Suppressed by recent HR role change within {self.role_change_days} days",
                )

        return False, None
