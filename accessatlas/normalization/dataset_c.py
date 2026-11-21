"""Dataset C loader, normalizer, and validator.

Reads native CSV/XLSX/JSON exports from data/external/dataset_c/ and converts them
into canonical Parquet tables validated against pandera schemas.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from accessatlas.ingestion.schemas import SCHEMAS
from accessatlas.normalization.common import (
    DeterministicIdGenerator,
    deduplicate_rows,
    load_normalization_config,
    normalize_boolean,
    normalize_categorical,
    normalize_datetime,
    normalize_email,
    normalize_missing,
    normalize_name,
    normalize_tier,
    normalize_whitespace,
    parse_time_window,
)
from accessatlas.normalization.reporter import QualityReporter

logger = logging.getLogger(__name__)


def normalize_dataset_c(
    raw_dir: Path | str,
    output_dir: Path | str,
    config: dict[str, Any] | None = None,
) -> QualityReporter:
    """Normalize raw Dataset C exports into standard canonical tables.

    Parameters
    ----------
    raw_dir : Path or str
        Directory containing raw dataset C files (e.g. data/external/dataset_c).
    output_dir : Path or str
        Target directory for Parquet tables, id_map.csv, and quality reports.
    config : dict, optional
        Loaded configuration dictionary. If None, loads config/normalization.yaml.

    Returns
    -------
    QualityReporter
        Populated quality report collector with statistics for each table.
    """
    raw_path = Path(raw_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    cfg = config or load_normalization_config()
    common_cfg = cfg.get("common", {})
    status_map = common_cfg.get("status_mapping", {})
    worker_map = common_cfg.get("worker_type_mapping", {})
    platform_map = common_cfg.get("platform_mapping", {})
    result_map = common_cfg.get("result_mapping", {})
    token_scope_map = common_cfg.get("token_scope_mapping", {})
    aws_group_pol_map = common_cfg.get("aws_group_policy_mapping", {})

    reporter = QualityReporter(dataset_name="dataset_c")
    id_gen = DeterministicIdGenerator()

    # Track username/login -> canonical account_id mappings for Audit_Events lookup
    account_lookup: dict[tuple[str, str], str] = {}

    # -------------------------------------------------------------------------
    # 0. Service Account Inventory (reference for account_type and linking)
    # -------------------------------------------------------------------------
    svc_inv_file = raw_path / "service_account_inventory.csv"
    svc_df = pd.read_csv(svc_inv_file) if svc_inv_file.is_file() else pd.DataFrame()

    ad_svc_names: set[str] = set()
    aws_svc_names: set[str] = set()
    okta_svc_names: set[str] = set()
    svc_info: dict[str, dict[str, Any]] = {}
    job_to_svc_id: dict[str, str] = {}

    if not svc_df.empty:
        for _, row in svc_df.iterrows():
            s_id = str(row["service_account_id"]).strip()
            name = str(row["account_name"]).strip()
            sys_val = str(row["system"]).strip().upper()
            owner = str(row["owner_employee_id"]).strip() if pd.notna(row.get("owner_employee_id")) else None

            svc_info[s_id] = {
                "system": sys_val.lower(),
                "name": name,
                "owner_employee_id": owner,
            }
            if sys_val == "AD":
                ad_svc_names.add(name.lower())
            elif sys_val == "AWS":
                aws_svc_names.add(name.lower())
            elif sys_val == "OKTA":
                okta_svc_names.add(name.lower())

            # Scheduled job links: job name 'svc-batch-001-job' strips to 'svc-batch-001'
            job_to_svc_id[name.lower()] = s_id

    # -------------------------------------------------------------------------
    # 1. HR Workbook: Employees, Role History, Offboarding Tickets
    # -------------------------------------------------------------------------
    hr_file = raw_path / "hr_system.xlsx"
    hr_lookup: dict[str, dict[str, Any]] = {}

    # 1.1 HR_Records
    t_hr = reporter.get_or_create_table("HR_Records")
    if hr_file.is_file():
        raw_hr = pd.read_excel(hr_file, sheet_name="Employees")
        t_hr.rows_read = len(raw_hr)

        df_hr = raw_hr.copy()
        df_hr, fix_cnt = normalize_missing(df_hr)
        t_hr.record_fix("missing_markers_cleared", fix_cnt)

        # Rename work_email -> email
        if "work_email" in df_hr.columns:
            df_hr = df_hr.rename(columns={"work_email": "email"})
            t_hr.record_fix("column_renamed_work_email", len(df_hr))

        df_hr["email"], fix_cnt = normalize_email(df_hr["email"])
        t_hr.record_fix("email_normalized", fix_cnt)

        df_hr["first_name"], fix_cnt = normalize_name(df_hr["first_name"])
        t_hr.record_fix("name_normalized", fix_cnt)
        df_hr["last_name"], fix_cnt = normalize_name(df_hr["last_name"])
        t_hr.record_fix("name_normalized", fix_cnt)

        df_hr["worker_type"], fix_cnt = normalize_categorical(df_hr["worker_type"], worker_map, default="employee")
        t_hr.record_fix("worker_type_mapped", fix_cnt)

        df_hr["status"], fix_cnt = normalize_categorical(df_hr["status"], status_map, default="active")
        t_hr.record_fix("status_mapped", fix_cnt)

        df_hr["hire_date"], fix_cnt = normalize_datetime(df_hr["hire_date"], ["%d-%b-%Y"])
        t_hr.record_fix("hire_date_parsed", fix_cnt)

        df_hr["termination_date"], fix_cnt = normalize_datetime(df_hr["termination_date"], ["%d-%b-%Y"])
        t_hr.record_fix("termination_date_parsed", fix_cnt)

        df_hr, dedup_cnt = deduplicate_rows(df_hr, subset=["employee_id"])
        t_hr.duplicates_removed = dedup_cnt
        t_hr.rows_output = len(df_hr)

        # Store HR lookup for AD enrichment
        for _, r in df_hr.iterrows():
            eid = str(r["employee_id"]).strip()
            hr_lookup[eid] = {
                "display_name": f"{r['first_name']} {r['last_name']}".strip(),
                "department": r.get("department"),
                "job_title": r.get("job_title"),
            }

        SCHEMAS["HR_Records"].validate(df_hr, lazy=True)
        df_hr.to_parquet(out_path / "HR_Records.parquet", index=False)
    else:
        reporter.mark_unavailable("HR_Records")

    # 1.2 HR_RoleChanges
    t_rc = reporter.get_or_create_table("HR_RoleChanges")
    if hr_file.is_file():
        raw_rc = pd.read_excel(hr_file, sheet_name="Role History")
        t_rc.rows_read = len(raw_rc)

        df_rc = raw_rc.copy()
        df_rc, fix_cnt = normalize_missing(df_rc)
        t_rc.record_fix("missing_markers_cleared", fix_cnt)

        df_rc = df_rc.rename(
            columns={
                "effective_date": "change_date",
                "old_title": "old_job_title",
                "new_title": "new_job_title",
            }
        )
        df_rc["change_date"], fix_cnt = normalize_datetime(df_rc["change_date"], ["%d-%b-%Y"])
        t_rc.record_fix("change_date_parsed", fix_cnt)

        df_rc, dedup_cnt = deduplicate_rows(df_rc)
        t_rc.duplicates_removed = dedup_cnt
        t_rc.rows_output = len(df_rc)

        SCHEMAS["HR_RoleChanges"].validate(df_rc, lazy=True)
        df_rc.to_parquet(out_path / "HR_RoleChanges.parquet", index=False)
    else:
        reporter.mark_unavailable("HR_RoleChanges")

    # 1.3 HR_Offboarding
    t_off = reporter.get_or_create_table("HR_Offboarding")
    if hr_file.is_file():
        raw_off = pd.read_excel(hr_file, sheet_name="Offboarding Tickets")
        t_off.rows_read = len(raw_off)

        df_off = raw_off.copy()
        df_off, fix_cnt = normalize_missing(df_off)
        t_off.record_fix("missing_markers_cleared", fix_cnt)

        df_off = df_off.rename(
            columns={
                "ad_revoked_on": "ad_disabled_date",
                "okta_revoked_on": "okta_deactivated_date",
                "aws_revoked_on": "aws_access_removed_date",
            }
        )

        for col in ["termination_date", "ad_disabled_date", "okta_deactivated_date", "aws_access_removed_date"]:
            df_off[col], fix_cnt = normalize_datetime(df_off[col], ["%d-%b-%Y"])
            t_off.record_fix(f"{col}_parsed", fix_cnt)

        # all_platforms_revoked is intentionally absent in source; set to nullable boolean pd.NA
        df_off["all_platforms_revoked"] = pd.Series(pd.NA, index=df_off.index, dtype="boolean")
        t_off.columns_unavailable.append("all_platforms_revoked")

        df_off, dedup_cnt = deduplicate_rows(df_off)
        t_off.duplicates_removed = dedup_cnt
        t_off.rows_output = len(df_off)

        SCHEMAS["HR_Offboarding"].validate(df_off, lazy=True)
        df_off.to_parquet(out_path / "HR_Offboarding.parquet", index=False)
    else:
        reporter.mark_unavailable("HR_Offboarding")

    # -------------------------------------------------------------------------
    # 2. Active Directory
    # -------------------------------------------------------------------------
    # 2.1 AD_Users
    t_ad_u = reporter.get_or_create_table("AD_Users")
    ad_users_file = raw_path / "ad_users.csv"
    if ad_users_file.is_file():
        raw_ad = pd.read_csv(ad_users_file)
        t_ad_u.rows_read = len(raw_ad)

        df_ad = raw_ad.copy()
        df_ad, fix_cnt = normalize_missing(df_ad)
        t_ad_u.record_fix("missing_markers_cleared", fix_cnt)

        # Exact duplicate removal
        df_ad, dedup_cnt = deduplicate_rows(df_ad)
        t_ad_u.duplicates_removed = dedup_cnt

        sam_series = df_ad["sAMAccountName"].astype(str).str.strip()
        df_ad["sam_account_name"] = sam_series
        df_ad["user_principal_name"] = df_ad["userPrincipalName"].astype(str).str.strip()

        df_ad["mail"], fix_cnt = normalize_email(df_ad["mail"])
        t_ad_u.record_fix("email_normalized", fix_cnt)

        df_ad["employee_id"] = (
            df_ad["employeeID"].astype(str).str.strip().replace(list(common_cfg.get("missing_markers", [])), pd.NA)
        )

        # Datetime coercion
        df_ad["created_at"], fix_cnt = normalize_datetime(df_ad["whenCreated"], ["%m/%d/%Y %H:%M:%S"])
        t_ad_u.record_fix("created_at_parsed", fix_cnt)

        df_ad["last_logon"], fix_cnt = normalize_datetime(df_ad["lastLogonTimestamp"], ["%m/%d/%Y %H:%M:%S"])
        t_ad_u.record_fix("last_logon_parsed", fix_cnt)

        # Boolean enabled from userAccountControl
        uac_str = df_ad["userAccountControl"].astype(str).str.strip().str.upper()
        df_ad["enabled"] = (uac_str == "NORMAL_ACCOUNT").astype("boolean")
        t_ad_u.record_fix("uac_to_enabled_coerced", len(df_ad))

        # Generate unique, deterministic canonical account_id
        ad_ids = []
        for sam, eid, mail in zip(sam_series, df_ad["employee_id"], df_ad["mail"]):
            raw_key = f"{sam}|{eid if pd.notna(eid) else ''}|{mail if pd.notna(mail) else ''}"
            acc_id = id_gen.get_or_generate_id("ad", raw_key)
            ad_ids.append(acc_id)
            account_lookup[("ad", sam.lower())] = acc_id
            if pd.notna(mail):
                account_lookup[("ad", str(mail).lower())] = acc_id

        df_ad["account_id"] = ad_ids
        t_ad_u.record_fix("account_id_generated", len(df_ad))

        # account_type: "service" if in inventory, else "human". NEVER "orphan"
        acc_types = []
        owner_ids = []
        for sam in sam_series:
            sam_lower = sam.lower()
            if sam_lower in ad_svc_names:
                acc_types.append("service")
                owner_ids.append(svc_info.get(sam_lower, {}).get("owner_employee_id"))
            else:
                acc_types.append("human")
                owner_ids.append(None)
        df_ad["account_type"] = acc_types
        df_ad["owner_employee_id"] = owner_ids

        # Standard non-null OU
        df_ad["ou"] = "OU=Users"
        t_ad_u.columns_unavailable.append("ou (defaulted to 'OU=Users')")

        # display_name enriched from HR lookup or fallback to sam_account_name
        disp_names = []
        departments = []
        titles = []
        for sam, eid in zip(sam_series, df_ad["employee_id"]):
            hr_rec = hr_lookup.get(str(eid)) if pd.notna(eid) else None
            if hr_rec:
                disp_names.append(hr_rec["display_name"])
                departments.append(hr_rec.get("department"))
                titles.append(hr_rec.get("job_title"))
            else:
                disp_names.append(sam)
                departments.append(None)
                titles.append(None)

        df_ad["display_name"] = disp_names
        df_ad["department"] = departments
        df_ad["title"] = titles
        t_ad_u.columns_unavailable.extend(["department", "title"])
        t_ad_u.rows_output = len(df_ad)

        SCHEMAS["AD_Users"].validate(df_ad, lazy=True)
        df_ad.to_parquet(out_path / "AD_Users.parquet", index=False)
    else:
        reporter.mark_unavailable("AD_Users")

    # 2.2 AD_Groups
    t_ad_g = reporter.get_or_create_table("AD_Groups")
    ad_groups_file = raw_path / "ad_groups.csv"
    if ad_groups_file.is_file():
        raw_ad_g = pd.read_csv(ad_groups_file)
        t_ad_g.rows_read = len(raw_ad_g)

        df_ad_g = raw_ad_g.copy()
        df_ad_g["group_name"] = df_ad_g["group_name"].astype(str).str.strip()
        df_ad_g["declared_tier"], fix_cnt = normalize_tier(df_ad_g["privilege_tier"])
        t_ad_g.record_fix("declared_tier_normalized", fix_cnt)
        df_ad_g["declared_tier"] = df_ad_g["declared_tier"].astype(int)

        df_ad_g, dedup_cnt = deduplicate_rows(df_ad_g, subset=["group_name"])
        t_ad_g.duplicates_removed = dedup_cnt
        t_ad_g.rows_output = len(df_ad_g)

        SCHEMAS["AD_Groups"].validate(df_ad_g, lazy=True)
        df_ad_g.to_parquet(out_path / "AD_Groups.parquet", index=False)
    else:
        reporter.mark_unavailable("AD_Groups")

    # 2.3 AD_GroupMembership
    t_ad_m = reporter.get_or_create_table("AD_GroupMembership")
    ad_m_file = raw_path / "ad_group_membership.csv"
    if ad_m_file.is_file():
        raw_ad_m = pd.read_csv(ad_m_file)
        t_ad_m.rows_read = len(raw_ad_m)

        df_ad_m = raw_ad_m.copy()
        df_ad_m["group_name"] = df_ad_m["parent_group"].astype(str).str.strip()
        df_ad_m["member_type"] = df_ad_m["member_type"].astype(str).str.strip().str.lower()
        df_ad_m["member"] = df_ad_m["member"].astype(str).str.strip()

        df_ad_m, dedup_cnt = deduplicate_rows(df_ad_m)
        t_ad_m.duplicates_removed = dedup_cnt
        t_ad_m.rows_output = len(df_ad_m)

        SCHEMAS["AD_GroupMembership"].validate(df_ad_m, lazy=True)
        df_ad_m.to_parquet(out_path / "AD_GroupMembership.parquet", index=False)
    else:
        reporter.mark_unavailable("AD_GroupMembership")

    # -------------------------------------------------------------------------
    # 3. AWS IAM
    # -------------------------------------------------------------------------
    # 3.1 AWS_Users
    t_aws_u = reporter.get_or_create_table("AWS_Users")
    aws_users_file = raw_path / "aws_credential_report.csv"
    if aws_users_file.is_file():
        raw_aws = pd.read_csv(aws_users_file)
        t_aws_u.rows_read = len(raw_aws)

        df_aws = raw_aws.copy()
        df_aws, fix_cnt = normalize_missing(df_aws)
        t_aws_u.record_fix("missing_markers_cleared", fix_cnt)

        # Exact duplicate removal
        df_aws, dedup_cnt = deduplicate_rows(df_aws)
        t_aws_u.duplicates_removed = dedup_cnt

        u_names = df_aws["user"].astype(str).str.strip()
        df_aws["user_name"] = u_names
        df_aws["arn"] = df_aws["arn"].astype(str).str.strip()

        df_aws["tag_employee_id"] = (
            df_aws["tag_employee_id"].astype(str).str.strip().replace(list(common_cfg.get("missing_markers", [])), pd.NA)
        )
        df_aws["tag_email"], fix_cnt = normalize_email(df_aws["tag_email"])
        t_aws_u.record_fix("tag_email_normalized", fix_cnt)

        # Generate unique, deterministic user_id
        aws_uids = []
        user_to_primary_uid = {}
        for u, eid, em in zip(u_names, df_aws["tag_employee_id"], df_aws["tag_email"]):
            raw_key = f"{u}|{eid if pd.notna(eid) else ''}|{em if pd.notna(em) else ''}"
            uid = id_gen.get_or_generate_id("aws", raw_key)
            aws_uids.append(uid)
            if u.lower() not in user_to_primary_uid:
                user_to_primary_uid[u.lower()] = uid
            account_lookup[("aws", u.lower())] = uid
            if pd.notna(em):
                account_lookup[("aws", str(em).lower())] = uid

        df_aws["user_id"] = aws_uids
        t_aws_u.record_fix("user_id_generated", len(df_aws))

        df_aws["password_last_used"], fix_cnt = normalize_datetime(df_aws["password_last_used"])
        t_aws_u.record_fix("password_last_used_parsed", fix_cnt)

        df_aws["console_access"], fix_cnt = normalize_boolean(df_aws["password_enabled"])
        t_aws_u.record_fix("console_access_coerced", fix_cnt)

        df_aws["mfa_enabled"], fix_cnt = normalize_boolean(df_aws["mfa_active"])
        t_aws_u.record_fix("mfa_enabled_coerced", fix_cnt)

        df_aws["created_at"] = pd.Series(pd.NaT, index=df_aws.index, dtype="datetime64[ns]")
        t_aws_u.columns_unavailable.append("created_at")

        df_aws["status"] = "active"

        acc_types = []
        owner_ids = []
        for u in u_names:
            u_lower = u.lower()
            if u_lower in aws_svc_names:
                acc_types.append("service")
                owner_ids.append(svc_info.get(u_lower, {}).get("owner_employee_id"))
            else:
                acc_types.append("human")
                owner_ids.append(None)
        df_aws["account_type"] = acc_types
        df_aws["owner_employee_id"] = owner_ids
        t_aws_u.rows_output = len(df_aws)

        SCHEMAS["AWS_Users"].validate(df_aws, lazy=True)
        df_aws.to_parquet(out_path / "AWS_Users.parquet", index=False)
    else:
        reporter.mark_unavailable("AWS_Users")

    # 3.2 AWS_Policies
    t_aws_p = reporter.get_or_create_table("AWS_Policies")
    aws_pol_file = raw_path / "aws_policies.csv"
    if aws_pol_file.is_file():
        raw_pol = pd.read_csv(aws_pol_file)
        t_aws_p.rows_read = len(raw_pol)

        df_pol = raw_pol.copy()
        df_pol["policy_name"] = df_pol["policy_name"].astype(str).str.strip()
        df_pol["declared_tier"], fix_cnt = normalize_tier(df_pol["tier"])
        t_aws_p.record_fix("declared_tier_normalized", fix_cnt)
        df_pol["declared_tier"] = df_pol["declared_tier"].astype(int)

        df_pol, dedup_cnt = deduplicate_rows(df_pol, subset=["policy_name"])
        t_aws_p.duplicates_removed = dedup_cnt
        t_aws_p.rows_output = len(df_pol)

        SCHEMAS["AWS_Policies"].validate(df_pol, lazy=True)
        df_pol.to_parquet(out_path / "AWS_Policies.parquet", index=False)
    else:
        reporter.mark_unavailable("AWS_Policies")

    # 3.3 AWS_Groups (resolve nested group to inherit policies without duplicate rows)
    t_aws_g = reporter.get_or_create_table("AWS_Groups")
    aws_grp_file = raw_path / "aws_groups.csv"
    if aws_grp_file.is_file():
        raw_grp = pd.read_csv(aws_grp_file)
        t_aws_g.rows_read = len(raw_grp)

        df_grp = raw_grp.copy()
        df_grp["group_name"] = df_grp["group_name"].astype(str).str.strip()

        # Map attached policies directly or via nested group inheritance
        # Nested-Platform-Ops -> Administrators (AdministratorAccess)
        attached_list = []
        for g in df_grp["group_name"]:
            if g in aws_group_pol_map:
                attached_list.append(aws_group_pol_map[g])
            elif g == "Nested-Platform-Ops":
                # Inherits AdministratorAccess from Administrators
                attached_list.append("AdministratorAccess")
            else:
                attached_list.append(None)

        df_grp["attached_policies"] = attached_list
        df_grp, dedup_cnt = deduplicate_rows(df_grp, subset=["group_name"])
        t_aws_g.duplicates_removed = dedup_cnt
        t_aws_g.rows_output = len(df_grp)

        SCHEMAS["AWS_Groups"].validate(df_grp, lazy=True)
        df_grp.to_parquet(out_path / "AWS_Groups.parquet", index=False)
    else:
        reporter.mark_unavailable("AWS_Groups")

    # 3.4 AWS_UserGroups
    t_aws_ug = reporter.get_or_create_table("AWS_UserGroups")
    aws_ug_file = raw_path / "aws_user_group_links.csv"
    if aws_ug_file.is_file():
        raw_ug = pd.read_csv(aws_ug_file)
        t_aws_ug.rows_read = len(raw_ug)

        df_ug = raw_ug.copy()
        df_ug, dedup_cnt = deduplicate_rows(df_ug)
        t_aws_ug.duplicates_removed = dedup_cnt

        df_ug["group_name"] = df_ug["group_name"].astype(str).str.strip()
        # Map user_name -> deterministic user_id
        df_ug["user_id"] = [
            user_to_primary_uid.get(u.strip().lower(), id_gen.get_or_generate_id("aws", u.strip()))
            for u in df_ug["user_name"]
        ]
        t_aws_ug.rows_output = len(df_ug)

        SCHEMAS["AWS_UserGroups"].validate(df_ug, lazy=True)
        df_ug.to_parquet(out_path / "AWS_UserGroups.parquet", index=False)
    else:
        reporter.mark_unavailable("AWS_UserGroups")

    # 3.5 AWS_PolicyAttach
    t_aws_pa = reporter.get_or_create_table("AWS_PolicyAttach")
    aws_pa_file = raw_path / "aws_direct_policy_attachments.csv"
    if aws_pa_file.is_file():
        raw_pa = pd.read_csv(aws_pa_file)
        t_aws_pa.rows_read = len(raw_pa)

        df_pa = raw_pa.copy()
        df_pa, dedup_cnt = deduplicate_rows(df_pa)
        t_aws_pa.duplicates_removed = dedup_cnt

        df_pa["principal_type"] = "user"
        df_pa["principal_id"] = [
            user_to_primary_uid.get(u.strip().lower(), id_gen.get_or_generate_id("aws", u.strip()))
            for u in df_pa["user_name"]
        ]
        df_pa["policy_name"] = df_pa["policy_name"].astype(str).str.strip()
        t_aws_pa.rows_output = len(df_pa)

        SCHEMAS["AWS_PolicyAttach"].validate(df_pa, lazy=True)
        df_pa.to_parquet(out_path / "AWS_PolicyAttach.parquet", index=False)
    else:
        reporter.mark_unavailable("AWS_PolicyAttach")

    # -------------------------------------------------------------------------
    # 4. Okta JSON Export
    # -------------------------------------------------------------------------
    okta_file = raw_path / "okta_export.json"
    okta_data: dict[str, Any] = {}
    if okta_file.is_file():
        with open(okta_file, encoding="utf-8") as f:
            okta_data = json.load(f)

    # 4.1 Okta_Users
    t_okta_u = reporter.get_or_create_table("Okta_Users")
    if "users" in okta_data:
        raw_okta_users = okta_data["users"]
        t_okta_u.rows_read = len(raw_okta_users)

        u_records = []
        for u in raw_okta_users:
            p = u.get("profile", {})
            oid = str(u.get("id", "")).strip()
            login = str(p.get("login", "")).strip()
            email = str(p.get("email", "")).strip() or None
            fn = str(p.get("firstName", "")).strip() or None
            ln = str(p.get("lastName", "")).strip() or None
            emp_num = str(p.get("employeeNumber", "")).strip() or None

            # Check service account inventory
            is_svc = (login.lower() in okta_svc_names) or (oid.lower() in okta_svc_names)
            acc_type = "service" if is_svc else "human"
            owner = svc_info.get(login.lower(), {}).get("owner_employee_id") if is_svc else None

            u_records.append(
                {
                    "okta_id": oid,
                    "login": login,
                    "email": email,
                    "first_name": fn,
                    "last_name": ln,
                    "employee_number": emp_num,
                    "status": str(u.get("status", "ACTIVE")).strip(),
                    "created_at": pd.NaT,
                    "last_login": pd.NaT,
                    "account_type": acc_type,
                    "owner_employee_id": owner,
                }
            )
            # Lookup for events
            account_lookup[("okta", oid.lower())] = oid
            account_lookup[("okta", login.lower())] = oid
            if email:
                account_lookup[("okta", email.lower())] = oid

        df_okta_u = pd.DataFrame(u_records)
        df_okta_u, fix_cnt = normalize_missing(df_okta_u)
        t_okta_u.record_fix("missing_markers_cleared", fix_cnt)

        df_okta_u["email"], fix_cnt = normalize_email(df_okta_u["email"])
        t_okta_u.record_fix("email_normalized", fix_cnt)

        df_okta_u["created_at"] = pd.to_datetime(df_okta_u["created_at"], utc=True).dt.tz_localize(None)
        df_okta_u["last_login"] = pd.to_datetime(df_okta_u["last_login"], utc=True).dt.tz_localize(None)
        t_okta_u.columns_unavailable.extend(["created_at", "last_login"])

        df_okta_u, dedup_cnt = deduplicate_rows(df_okta_u, subset=["okta_id"])
        t_okta_u.duplicates_removed = dedup_cnt
        t_okta_u.rows_output = len(df_okta_u)

        SCHEMAS["Okta_Users"].validate(df_okta_u, lazy=True)
        df_okta_u.to_parquet(out_path / "Okta_Users.parquet", index=False)
    else:
        reporter.mark_unavailable("Okta_Users")

    # 4.2 Okta_Groups
    t_okta_g = reporter.get_or_create_table("Okta_Groups")
    okta_grp_id_to_name: dict[str, str] = {}
    if "groups" in okta_data:
        raw_okta_grp = okta_data["groups"]
        t_okta_g.rows_read = len(raw_okta_grp)

        grp_records = []
        for g in raw_okta_grp:
            gid = str(g.get("id", "")).strip()
            gname = str(g.get("name", "")).strip()
            okta_grp_id_to_name[gid] = gname
            grp_records.append({"group_name": gname})

        df_okta_g = pd.DataFrame(grp_records)
        df_okta_g, dedup_cnt = deduplicate_rows(df_okta_g, subset=["group_name"])
        t_okta_g.duplicates_removed = dedup_cnt
        t_okta_g.rows_output = len(df_okta_g)

        SCHEMAS["Okta_Groups"].validate(df_okta_g, lazy=True)
        df_okta_g.to_parquet(out_path / "Okta_Groups.parquet", index=False)
    else:
        reporter.mark_unavailable("Okta_Groups")

    # 4.3 Okta_GroupMembership (maps group ID to group name)
    t_okta_gm = reporter.get_or_create_table("Okta_GroupMembership")
    if "group_memberships" in okta_data:
        raw_okta_gm = okta_data["group_memberships"]
        t_okta_gm.rows_read = len(raw_okta_gm)

        gm_records = []
        for gm in raw_okta_gm:
            gid = str(gm.get("group", "")).strip()
            gname = okta_grp_id_to_name.get(gid, gid)
            gm_records.append(
                {
                    "okta_id": str(gm.get("userId", "")).strip(),
                    "group_name": gname,
                }
            )

        df_okta_gm = pd.DataFrame(gm_records)
        t_okta_gm.record_fix("group_id_resolved_to_name", len(df_okta_gm))

        df_okta_gm, dedup_cnt = deduplicate_rows(df_okta_gm, subset=["okta_id", "group_name"])
        t_okta_gm.duplicates_removed = dedup_cnt
        t_okta_gm.rows_output = len(df_okta_gm)

        SCHEMAS["Okta_GroupMembership"].validate(df_okta_gm, lazy=True)
        df_okta_gm.to_parquet(out_path / "Okta_GroupMembership.parquet", index=False)
    else:
        reporter.mark_unavailable("Okta_GroupMembership")

    # 4.4 Okta_AdminRoles
    t_okta_ar = reporter.get_or_create_table("Okta_AdminRoles")
    if "admin_role_assignments" in okta_data:
        raw_ar = okta_data["admin_role_assignments"]
        t_okta_ar.rows_read = len(raw_ar)

        ar_records = []
        for ar in raw_ar:
            ar_records.append(
                {
                    "okta_id": str(ar.get("userId", "")).strip(),
                    "admin_role": str(ar.get("role", "")).strip(),
                    "assigned_at": pd.NaT,
                }
            )
        df_okta_ar = pd.DataFrame(ar_records)
        df_okta_ar["assigned_at"] = pd.to_datetime(df_okta_ar["assigned_at"], utc=True).dt.tz_localize(None)
        t_okta_ar.columns_unavailable.append("assigned_at")

        df_okta_ar, dedup_cnt = deduplicate_rows(df_okta_ar, subset=["okta_id", "admin_role"])
        t_okta_ar.duplicates_removed = dedup_cnt
        t_okta_ar.rows_output = len(df_okta_ar)

        SCHEMAS["Okta_AdminRoles"].validate(df_okta_ar, lazy=True)
        df_okta_ar.to_parquet(out_path / "Okta_AdminRoles.parquet", index=False)
    else:
        reporter.mark_unavailable("Okta_AdminRoles")

    # 4.5 Okta_Apps
    t_okta_app = reporter.get_or_create_table("Okta_Apps")
    if "app_assignments" in okta_data:
        raw_apps = okta_data["app_assignments"]
        t_okta_app.rows_read = len(raw_apps)

        app_records = []
        for app in raw_apps:
            app_records.append(
                {
                    "okta_id": str(app.get("userId", "")).strip(),
                    "app_name": str(app.get("app", "")).strip(),
                }
            )
        df_okta_app = pd.DataFrame(app_records)
        df_okta_app, dedup_cnt = deduplicate_rows(df_okta_app, subset=["okta_id", "app_name"])
        t_okta_app.duplicates_removed = dedup_cnt
        t_okta_app.rows_output = len(df_okta_app)

        SCHEMAS["Okta_Apps"].validate(df_okta_app, lazy=True)
        df_okta_app.to_parquet(out_path / "Okta_Apps.parquet", index=False)
    else:
        reporter.mark_unavailable("Okta_Apps")

    # 4.6 Okta_AWS_Federation
    t_okta_fed = reporter.get_or_create_table("Okta_AWS_Federation")
    if "group_aws_role_mapping" in okta_data:
        raw_fed = okta_data["group_aws_role_mapping"]
        t_okta_fed.rows_read = len(raw_fed)

        fed_records = []
        for fed in raw_fed:
            fed_records.append(
                {
                    "okta_group": str(fed.get("okta_group", "")).strip(),
                    "aws_role": str(fed.get("aws_role", "")).strip(),
                    "aws_declared_tier": int(fed.get("tier", 3)),
                }
            )
        df_okta_fed = pd.DataFrame(fed_records)
        df_okta_fed, dedup_cnt = deduplicate_rows(df_okta_fed, subset=["okta_group", "aws_role"])
        t_okta_fed.duplicates_removed = dedup_cnt
        t_okta_fed.rows_output = len(df_okta_fed)

        SCHEMAS["Okta_AWS_Federation"].validate(df_okta_fed, lazy=True)
        df_okta_fed.to_parquet(out_path / "Okta_AWS_Federation.parquet", index=False)
    else:
        reporter.mark_unavailable("Okta_AWS_Federation")

    # -------------------------------------------------------------------------
    # 5. Supporting Tables
    # -------------------------------------------------------------------------
    # 5.1 Tier_Mapping
    t_tm = reporter.get_or_create_table("Tier_Mapping")
    tm_file = raw_path / "tier_mapping.csv"
    if tm_file.is_file():
        raw_tm = pd.read_csv(tm_file)
        t_tm.rows_read = len(raw_tm)

        df_tm = raw_tm.copy()
        df_tm["platform"], fix_cnt = normalize_categorical(df_tm["system"], platform_map)
        t_tm.record_fix("platform_mapped", fix_cnt)

        df_tm["role_or_group"] = df_tm["source_tier"].astype(str).str.strip()
        df_tm["common_tier"] = df_tm["common_tier"].astype(int)

        df_tm, dedup_cnt = deduplicate_rows(df_tm, subset=["platform", "role_or_group"])
        t_tm.duplicates_removed = dedup_cnt
        t_tm.rows_output = len(df_tm)

        SCHEMAS["Tier_Mapping"].validate(df_tm, lazy=True)
        df_tm.to_parquet(out_path / "Tier_Mapping.parquet", index=False)
    else:
        reporter.mark_unavailable("Tier_Mapping")

    # 5.2 API_Tokens
    t_tok = reporter.get_or_create_table("API_Tokens")
    tok_file = raw_path / "api_tokens.csv"
    if tok_file.is_file():
        raw_tok = pd.read_csv(tok_file)
        t_tok.rows_read = len(raw_tok)

        df_tok = raw_tok.copy()
        df_tok, fix_cnt = normalize_missing(df_tok)
        t_tok.record_fix("missing_markers_cleared", fix_cnt)

        df_tok["token_id"] = df_tok["token_id"].astype(str).str.strip()
        df_tok["account_id"] = df_tok["service_account_id"].astype(str).str.strip()

        # Platform joined from service_account_inventory
        platforms = []
        identity_ids = []
        for s_id in df_tok["account_id"]:
            s_data = svc_info.get(s_id, {})
            platforms.append(s_data.get("system", "aws"))
            identity_ids.append(s_data.get("owner_employee_id", "unknown"))

        df_tok["platform"] = platforms
        df_tok["identity_id"] = identity_ids

        for d_col in ["created", "last_rotated", "last_used"]:
            norm_col = f"{d_col}_at"
            df_tok[norm_col], fix_cnt = normalize_datetime(df_tok[d_col])
            t_tok.record_fix(f"{norm_col}_parsed", fix_cnt)

        # scope_tier mapping
        scope_tiers = []
        for s in df_tok["scope"]:
            s_clean = str(s).strip().lower()
            scope_tiers.append(token_scope_map.get(s_clean, pd.NA))
        df_tok["scope_tier"] = pd.Series(scope_tiers, dtype="Int64")
        t_tok.record_fix("scope_tier_mapped", int(df_tok["scope_tier"].notna().sum()))

        df_tok["status"] = df_tok["status"].astype(str).str.strip().str.lower()

        df_tok, dedup_cnt = deduplicate_rows(df_tok, subset=["token_id"])
        t_tok.duplicates_removed = dedup_cnt
        t_tok.rows_output = len(df_tok)

        SCHEMAS["API_Tokens"].validate(df_tok, lazy=True)
        df_tok.to_parquet(out_path / "API_Tokens.parquet", index=False)
    else:
        reporter.mark_unavailable("API_Tokens")

    # 5.3 Exceptions
    t_exc = reporter.get_or_create_table("Exceptions")
    exc_file = raw_path / "access_exceptions.csv"
    if exc_file.is_file():
        raw_exc = pd.read_csv(exc_file)
        t_exc.rows_read = len(raw_exc)

        df_exc = raw_exc.copy()
        df_exc, fix_cnt = normalize_missing(df_exc)
        t_exc.record_fix("missing_markers_cleared", fix_cnt)

        df_exc["employee_id"] = df_exc["employee_id"].astype(str).str.strip()
        df_exc["ticket_id"] = df_exc["ticket"].astype(str).str.strip()

        # Generate deterministic exception_id
        df_exc["exception_id"] = [f"EXC-{i:06d}" for i in range(1, len(df_exc) + 1)]

        df_exc["start_date"], fix_cnt = normalize_datetime(df_exc["start_date"])
        t_exc.record_fix("start_date_parsed", fix_cnt)

        df_exc["end_date"], fix_cnt = normalize_datetime(df_exc["end_date"])
        t_exc.record_fix("end_date_parsed", fix_cnt)

        # Status mapping (APPROVED -> active, EXPIRED_REVOKED -> revoked)
        df_exc["status"], fix_cnt = normalize_categorical(df_exc["status"], status_map, default="active")
        t_exc.record_fix("status_mapped", fix_cnt)

        # Platforms column preserved for rules evaluation
        df_exc["platforms"] = df_exc["platform"].astype(str).str.strip().str.lower()

        df_exc["revocation_confirmed"] = pd.Series(pd.NA, index=df_exc.index, dtype="boolean")
        t_exc.columns_unavailable.append("revocation_confirmed")

        df_exc, dedup_cnt = deduplicate_rows(df_exc, subset=["exception_id"])
        t_exc.duplicates_removed = dedup_cnt
        t_exc.rows_output = len(df_exc)

        SCHEMAS["Exceptions"].validate(df_exc, lazy=True)
        df_exc.to_parquet(out_path / "Exceptions.parquet", index=False)
    else:
        reporter.mark_unavailable("Exceptions")

    # 5.4 OnCall_Roster
    t_oncall = reporter.get_or_create_table("OnCall_Roster")
    oncall_file = raw_path / "on_call_roster.csv"
    if oncall_file.is_file():
        raw_oncall = pd.read_csv(oncall_file)
        t_oncall.rows_read = len(raw_oncall)

        df_oncall = raw_oncall.copy()
        df_oncall["employee_id"] = df_oncall["employee_id"].astype(str).str.strip()
        df_oncall["shift_start"], fix_cnt = normalize_datetime(df_oncall["shift_start"])
        t_oncall.record_fix("shift_start_parsed", fix_cnt)
        df_oncall["shift_end"], fix_cnt = normalize_datetime(df_oncall["shift_end"])
        t_oncall.record_fix("shift_end_parsed", fix_cnt)
        df_oncall["team"] = df_oncall["team"].astype(str).str.strip()

        df_oncall, dedup_cnt = deduplicate_rows(df_oncall)
        t_oncall.duplicates_removed = dedup_cnt
        t_oncall.rows_output = len(df_oncall)

        SCHEMAS["OnCall_Roster"].validate(df_oncall, lazy=True)
        df_oncall.to_parquet(out_path / "OnCall_Roster.parquet", index=False)
    else:
        reporter.mark_unavailable("OnCall_Roster")

    # 5.5 Scheduled_Jobs
    t_job = reporter.get_or_create_table("Scheduled_Jobs")
    job_file = raw_path / "scheduled_jobs.csv"
    if job_file.is_file():
        raw_job = pd.read_csv(job_file)
        t_job.rows_read = len(raw_job)

        df_job = raw_job.copy()
        df_job, fix_cnt = normalize_missing(df_job)
        t_job.record_fix("missing_markers_cleared", fix_cnt)

        df_job["job_name"] = df_job["job_name"].astype(str).str.strip()
        df_job["frequency"] = df_job["frequency"].astype(str).str.strip()
        df_job["owner_employee_id"] = df_job["owner"].astype(str).str.strip()

        # Parse time windows into window_start and window_end
        if "time_window" in df_job.columns:
            w_start, w_end, fix_cnt = parse_time_window(df_job["time_window"])
            df_job["window_start"] = w_start
            df_job["window_end"] = w_end
            t_job.record_fix("time_windows_parsed", fix_cnt)

        if "expected_source_ip" in df_job.columns:
            df_job["expected_source_ip"] = df_job["expected_source_ip"].astype(str).str.strip()

        # Link scheduled job to service_account_id by stripping -job suffix
        strip_sfx = cfg.get("datasets", {}).get("dataset_c", {}).get("scheduled_job_link", {}).get("strip_suffix", "-job")
        svc_ids = []
        for jname in df_job["job_name"]:
            key = jname
            if key.endswith(strip_sfx):
                key = key[: -len(strip_sfx)]
            matched_id = job_to_svc_id.get(key.lower(), jname)
            svc_ids.append(matched_id)

        df_job["service_account_id"] = svc_ids
        t_job.record_fix("job_linked_to_service_account", len(df_job))

        df_job, dedup_cnt = deduplicate_rows(df_job, subset=["job_name"])
        t_job.duplicates_removed = dedup_cnt
        t_job.rows_output = len(df_job)

        SCHEMAS["Scheduled_Jobs"].validate(df_job, lazy=True)
        df_job.to_parquet(out_path / "Scheduled_Jobs.parquet", index=False)
    else:
        reporter.mark_unavailable("Scheduled_Jobs")

    # -------------------------------------------------------------------------
    # 6. Audit Events (with fallback ID guardrail)
    # -------------------------------------------------------------------------
    t_evt = reporter.get_or_create_table("Audit_Events")
    evt_file = raw_path / "activity_events.csv"
    if evt_file.is_file():
        raw_evt = pd.read_csv(evt_file)
        t_evt.rows_read = len(raw_evt)

        df_evt = raw_evt.copy()
        df_evt, fix_cnt = normalize_missing(df_evt)
        t_evt.record_fix("missing_markers_cleared", fix_cnt)

        df_evt["event_id"] = df_evt["event_id"].astype(str).str.strip()
        df_evt["timestamp"], fix_cnt = normalize_datetime(df_evt["timestamp_utc"])
        t_evt.record_fix("timestamp_parsed", fix_cnt)

        df_evt["platform"], fix_cnt = normalize_categorical(df_evt["system"], platform_map)
        t_evt.record_fix("platform_mapped", fix_cnt)

        # In Dataset C, the account_id column holds the login/username
        raw_usernames = df_evt["account_id"].astype(str).str.strip()
        df_evt["username"] = raw_usernames

        # Map to canonical account_id via account_lookup; fallback if unknown/deleted
        canonical_accs = []
        fallback_cnt = 0
        for plat, uname in zip(df_evt["platform"], raw_usernames):
            plat_str = str(plat).lower()
            uname_clean = str(uname).lower()
            lookup_key = (plat_str, uname_clean)

            if lookup_key in account_lookup:
                canonical_accs.append(account_lookup[lookup_key])
            else:
                # Deterministic fallback ID
                digest = hashlib.md5(f"{plat_str}:{uname_clean}".encode()).hexdigest()[:6]
                fallback_id = f"{plat_str.upper()}-UNK-{digest}"
                canonical_accs.append(fallback_id)
                fallback_cnt += 1

        df_evt["account_id"] = canonical_accs
        if fallback_cnt > 0:
            t_evt.record_fix("unknown_account_fallback_id", fallback_cnt)

        df_evt["event_type"] = df_evt["event_type"].astype(str).str.strip()
        df_evt["category"] = df_evt["category"].astype(str).str.strip()
        df_evt["resource"] = df_evt["resource"].astype(str).str.strip()
        df_evt["result"], fix_cnt = normalize_categorical(df_evt["result"], result_map, default="failure")
        t_evt.record_fix("result_mapped", fix_cnt)

        if "source_ip" in df_evt.columns:
            df_evt["source_ip"] = df_evt["source_ip"].astype(str).str.strip()

        df_evt["privileged_action"], fix_cnt = normalize_boolean(df_evt["privileged_action"])
        t_evt.record_fix("privileged_action_coerced", fix_cnt)

        df_evt["mfa_used"], fix_cnt = normalize_boolean(df_evt["mfa_used"])
        t_evt.record_fix("mfa_used_coerced", fix_cnt)

        df_evt, dedup_cnt = deduplicate_rows(df_evt, subset=["event_id"])
        t_evt.duplicates_removed = dedup_cnt
        t_evt.rows_output = len(df_evt)

        SCHEMAS["Audit_Events"].validate(df_evt, lazy=True)
        df_evt.to_parquet(out_path / "Audit_Events.parquet", index=False)
    else:
        reporter.mark_unavailable("Audit_Events")

    # -------------------------------------------------------------------------
    # 7. Export ID Map and Quality Reports
    # -------------------------------------------------------------------------
    id_gen.export_id_map(out_path / "id_map.csv")
    reporter.write_reports(out_path)
    logger.info("Normalization complete for %s. Quality report written to %s", reporter.dataset_name, out_path)

    return reporter
