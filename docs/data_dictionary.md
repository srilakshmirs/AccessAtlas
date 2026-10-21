# Data Dictionary — AccessAtlas

Auto-generated from the synthetic dataset (2026-10-21).
All column types shown are the **post-cleaning** types stored in Parquet.

> **Cleaning rules** are applied by `accessatlas/ingestion/cleaning.py` before
> Parquet is written. Each rule is noted inline.

---

## Core dataset (`data/raw/AccessAtlas_Dataset_Core.xlsx`)

### HR_Records — 5,000 rows

Source of truth for all employees and contractors.

| Column | Type | Nullable | Notes / Cleaning rule |
|--------|------|----------|-----------------------|
| employee_id | str | No | Primary key. Format: `E######` (employee) or `C######` (contractor). |
| first_name | str | No | |
| last_name | str | No | |
| email | str | No | Corporate email. Contractors use `.ext@` domain. |
| department | str | No | |
| job_title | str | No | |
| manager_id | str | Yes | Null for the CEO (top of hierarchy). |
| worker_type | str | No | `"employee"` or `"contractor"`. |
| status | str | No | `"active"`, `"terminated"`, or `"on_leave"`. |
| hire_date | datetime | No | **Cleaned:** coerced from raw date to `datetime64[ns]`. |
| termination_date | datetime | Yes | Null for active employees. **Cleaned:** coerced; `'n/a'` → NaT. |

---

### HR_RoleChanges

Records every department or title change.

| Column | Type | Nullable | Notes / Cleaning rule |
|--------|------|----------|-----------------------|
| employee_id | str | No | FK → HR_Records.employee_id |
| change_date | datetime | No | **Cleaned:** coerced to datetime. |
| old_department | str | Yes | |
| new_department | str | Yes | |
| old_job_title | str | Yes | |
| new_job_title | str | Yes | |

---

### HR_Offboarding — 535 rows

Tracks the decommissioning timeline for terminated employees.

| Column | Type | Nullable | Notes / Cleaning rule |
|--------|------|----------|-----------------------|
| employee_id | str | No | FK → HR_Records.employee_id |
| termination_date | datetime | No | **Cleaned:** coerced to datetime. |
| ticket_id | str | No | Offboarding ticket reference. |
| ad_disabled_date | datetime | Yes | **Cleaned:** `'n/a'` → NaT. Null when AD access removed via group policy, not per-account. |
| okta_deactivated_date | datetime | Yes | **Cleaned:** `'n/a'` → NaT. |
| aws_access_removed_date | datetime | Yes | **Cleaned:** `'n/a'` → NaT. Null when access removed via Okta federation. |
| all_platforms_revoked | boolean | Yes | **Cleaned:** Python `True`/`False` → pandas nullable `boolean` dtype. |
| notes | str | Yes | Free text. |

---

### AD_Users — 5,004 rows

Active Directory accounts. Includes human, service and orphan accounts.

| Column | Type | Nullable | Notes / Cleaning rule |
|--------|------|----------|-----------------------|
| account_id | str | No | AD primary key. Format: `AD-######`. |
| sam_account_name | str | No | Windows login name. |
| user_principal_name | str | No | UPN (email format). |
| display_name | str | No | |
| mail | str | Yes | Exchange email. May differ from UPN for service accounts. |
| employee_id | str | Yes | Null for service and orphan accounts. |
| department | str | Yes | |
| title | str | Yes | |
| ou | str | No | Organisational Unit path. |
| enabled | boolean | No | **Cleaned:** Python `bool` → pandas nullable `boolean`. |
| created_at | datetime | Yes | **Cleaned:** coerced to datetime. |
| last_logon | datetime | Yes | **Cleaned:** coerced to datetime. Null if account never logged on. |
| account_type | str | No | `"human"`, `"service"`, or `"orphan"`. |
| owner_employee_id | str | Yes | Employee who owns a service/orphan account. |

---

### AD_Groups — 29 rows

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| group_name | str | No | |
| declared_tier | int | No | 0 (most privileged) – 3. |
| description | str | Yes | |

---

### AD_GroupMembership

Members can be users (`sam_account_name`) or other groups — enabling **nested group** escalation.

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| member_type | str | No | `"user"` or `"group"`. |
| member | str | No | sam_account_name (user) or group_name (group). |
| group_name | str | No | The group this member belongs to. |

---

### AWS_Users — 1,315 rows

IAM users. Many lack a tag_employee_id (service/orphan accounts), making identity resolution non-trivial.

| Column | Type | Nullable | Notes / Cleaning rule |
|--------|------|----------|-----------------------|
| user_id | str | No | Format: `AWS-USR-######`. |
| user_name | str | No | IAM username (often abbreviated). |
| arn | str | No | Full IAM ARN. |
| tag_employee_id | str | Yes | Employee ID tag set during provisioning. Missing for many service accounts. |
| tag_email | str | Yes | |
| created_at | datetime | Yes | **Cleaned:** coerced to datetime. |
| password_last_used | datetime | Yes | **Cleaned:** coerced to datetime. |
| console_access | boolean | Yes | **Cleaned:** bool → nullable boolean. |
| mfa_enabled | boolean | Yes | **Cleaned:** bool → nullable boolean. |
| status | str | No | |
| account_type | str | No | `"human"`, `"service"`, or `"orphan"`. |
| owner_employee_id | str | Yes | |

---

### AWS_Groups / AWS_Policies / AWS_UserGroups / AWS_PolicyAttach

Standard IAM group/policy model. See `accessatlas/ingestion/schemas.py` for column details.

---

### Okta_Users — 4,935 rows

Okta identity store.

| Column | Type | Nullable | Notes / Cleaning rule |
|--------|------|----------|-----------------------|
| okta_id | str | No | Okta internal ID. |
| login | str | No | Login email. |
| email | str | Yes | ~80 service/orphan accounts have no email. |
| first_name | str | Yes | |
| last_name | str | Yes | |
| employee_number | str | Yes | Maps to HR employee_id. Missing for service accounts. |
| status | str | No | `"ACTIVE"`, `"DEPROVISIONED"`, etc. |
| created_at | datetime | Yes | **Cleaned:** coerced to datetime. |
| last_login | datetime | Yes | **Cleaned:** coerced to datetime. |
| account_type | str | No | `"human"`, `"service"`, or `"orphan"`. |
| owner_employee_id | str | Yes | |

---

### Okta_AWS_Federation — 3 rows

Maps Okta groups to AWS IAM roles for SAML-based federation.

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| okta_group | str | No | |
| aws_role | str | No | |
| aws_declared_tier | int | No | 0–3. |

---

### Tier_Mapping — 23 rows

Common privilege tier mapping for all platforms. Tier 0 = most privileged.

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| platform | str | No | `"ad"`, `"aws"`, or `"okta"`. |
| role_or_group | str | No | |
| common_tier | int | No | 0–3. |
| notes | str | Yes | |

---

### Exceptions — 194 rows

Approved temporary privilege exceptions (e.g. on-call admins, project escalations).

| Column | Type | Nullable | Notes / Cleaning rule |
|--------|------|----------|-----------------------|
| exception_id | str | No | |
| employee_id | str | No | |
| platforms | str | No | Pipe-separated: `"ad\|aws\|okta"`. |
| privilege | str | No | |
| ticket_id | str | No | |
| approved_by | str | No | |
| start_date | datetime | Yes | **Cleaned:** coerced to datetime. |
| end_date | datetime | Yes | **Cleaned:** coerced to datetime. |
| status | str | No | `"active"`, `"expired"`, or `"revoked"`. |
| reason | str | Yes | |
| revocation_confirmed | boolean | Yes | **Cleaned:** bool → nullable boolean. |

---

### OnCall_Roster — 118 rows

Shift schedule. Used to suppress alerts for engineers performing legitimate privileged operations during on-call.

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| employee_id | str | No | |
| shift_start | datetime | No | **Cleaned:** coerced to datetime. |
| shift_end | datetime | No | **Cleaned:** coerced to datetime. |
| team | str | No | |

---

### Scheduled_Jobs — 147 rows

Service accounts with known nightly/scheduled activity. Used to suppress alerts for expected behaviour.

| Column | Type | Nullable | Notes |
|--------|------|----------|-------|
| service_account_id | str | No | |
| job_name | str | No | |
| frequency | str | No | |
| window_start | str | No | Time string (e.g. `"01:00"`). |
| window_end | str | No | |
| expected_source_ip | str | No | |
| owner_employee_id | str | Yes | |

---

### API_Tokens — 1,281 rows

Long-lived API tokens across all platforms. Stale tokens are a detection target in M4.

| Column | Type | Nullable | Notes / Cleaning rule |
|--------|------|----------|-----------------------|
| token_id | str | No | |
| token_type | str | No | |
| platform | str | No | |
| account_id | str | No | |
| identity_id | str | No | |
| created_at | datetime | Yes | **Cleaned:** coerced to datetime. |
| last_rotated_at | datetime | Yes | **Cleaned:** coerced to datetime. |
| last_used_at | datetime | Yes | **Cleaned:** coerced to datetime. |
| last_used_ip | str | Yes | |
| scope_tier | int | Yes | 0–3. |
| status | str | No | |

---

## Ground-truth sheets (evaluation-only)

The four GT_ sheets (`GT_Labels`, `GT_EffectivePrivilege`, `GT_IdentityLinks`,
`GT_InjectedEvents`) are stored in `data/processed/gt/`. They may **only** be
loaded by `accessatlas/evaluation/`. See `tests/test_gt_isolation.py`.

`GT_Labels` has a `split` column: `train` / `test` / `holdout`.
- Rules and thresholds are tuned on **train** only.
- Accuracy is reported on **test** during development.
- **Holdout** is never inspected until final evaluation.

---

## Events dataset (`data/raw/AccessAtlas_Dataset_Events_Part*.xlsx`)

Combined into a single `data/processed/events/Audit_Events.parquet` — **372,556 rows**.

| Column | Type | Nullable | Notes / Cleaning rule |
|--------|------|----------|-----------------------|
| event_id | str | No | Format: `EVT-########`. |
| timestamp | datetime | No | UTC. **Cleaned:** coerced to datetime. |
| platform | str | No | `"ad"`, `"aws"`, or `"okta"`. |
| account_id | str | No | Platform-native account identifier. |
| username | str | No | Human-readable login name (may differ per platform). |
| event_type | str | No | |
| category | str | No | |
| resource | str | Yes | |
| result | str | No | `"success"` or `"failure"`. |
| source_ip | str | Yes | |
| geo_country | str | Yes | |
| user_agent | str | Yes | |
| bytes_transferred | int | Yes | |
| privileged_action | boolean | Yes | **Cleaned:** `0`/`1` → nullable boolean. |
| mfa_used | boolean | Yes | **Cleaned:** `0`/`1` → nullable boolean. NaN for AD events (MFA not tracked). |
