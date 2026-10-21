# ADR-001 — Store data as Parquet, not XLSX at runtime

**Date:** 2026-10-21  
**Status:** Accepted  
**Milestone:** M1

## Context

The dataset consists of ~30 sheets from a core XLSX (~3 MB) and two events XLSX
files (~32 MB combined, 372,556 rows). Every time the API starts or a test runs,
it would need to read these files.

## Decision

Convert XLSX → Parquet once with `scripts/convert_data.py`. All runtime code
reads Parquet files only.

## Measured load times (on this machine)

| File | Format | Rows | Load time |
|------|--------|------|-----------|
| Audit_Events (both parts) | XLSX (openpyxl) | 372,556 | ~76 s (measured during conversion) |
| Audit_Events (both parts) | Parquet (pyarrow) | 372,556 | **1.036 s** |
| Audit_Events fixture | Parquet (pyarrow) | 11,575 | **0.005 s** |

> Times measured on the development machine running this project.
> Results will vary by hardware and disk speed.

## Consequences

- **Positive:** Runtime is fast; tests using the small fixture run in <1 s.
- **Positive:** Parquet stores dtypes (datetime, bool, int) so no re-coercion at load time.
- **Negative:** Requires a one-time setup step (`python scripts/convert_data.py`).
- **Negative:** Two copies of the data exist during development (XLSX + Parquet). Both are gitignored.

## Alternatives considered

- **Read XLSX at runtime:** Too slow (~76 s for events alone); unacceptable for API startup.
- **SQLite:** Would work for relational queries but adds a new dependency and an ETL step. Parquet integrates directly with pandas without a query layer.
- **CSV:** Human-readable but larger on disk and loses datetime dtype information.
