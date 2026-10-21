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

## Measured load times

Measured on: **Intel Core 7 150U, 15 GB RAM, Windows 10, Python 3.11.9**  
Method: 3 consecutive runs, median reported.

| Operation | Format | Rows | Run 1 | Run 2 | Run 3 | **Median** |
|-----------|--------|------|-------|-------|-------|------------|
| Both events files | XLSX (openpyxl) | 372,556 | 90.058 s | 80.367 s | 80.007 s | **80.367 s** |
| Full Audit_Events | Parquet (pyarrow) | 372,556 | 1.055 s | 0.070 s | 0.059 s | **0.070 s** |
| Fixture Audit_Events | Parquet (pyarrow) | 11,575 | 0.025 s | 0.006 s | 0.005 s | **0.006 s** |

**Note on the Parquet first-run spike (1.055 s):** The first read of a cold
file goes to disk; the OS then caches the pages. Runs 2 and 3 read from the
OS page cache (warm reads). The median of 0.070 s represents the typical
warm-read cost during normal operation. XLSX shows no such cache benefit
because openpyxl parses the XML cell-by-cell every time regardless.

## Consequences

- **Positive:** Warm Parquet read is ~1,150× faster than XLSX (80.367 s ÷ 0.070 s).
- **Positive:** Parquet stores dtypes (datetime, bool, int) so no re-coercion at load time.
- **Positive:** Fixture read at 0.006 s means the full test suite runs in under 2 seconds.
- **Negative:** Requires a one-time setup step (`python scripts/convert_data.py`).
- **Negative:** Two copies of the data exist during development (XLSX + Parquet). Both are gitignored.

## Alternatives considered

- **Read XLSX at runtime:** Too slow (~80 s per API startup for events alone).
- **SQLite:** Would work for relational queries but adds a new dependency and an
  ETL step. Parquet integrates directly with pandas without a query layer.
- **CSV:** Human-readable but larger on disk and loses datetime dtype information.
