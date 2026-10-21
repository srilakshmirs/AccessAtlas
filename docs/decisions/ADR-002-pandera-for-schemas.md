# ADR-002 — pandera over Pydantic for schema validation

**Date:** 2026-10-21  
**Status:** Accepted  
**Milestone:** M1

## Context

We need to validate that every table has the expected columns, correct dtypes,
and no unexpected null values in required fields.

## Decision

Use **pandera** (`DataFrameSchema`) to declare and enforce schemas.

## Reasoning

| Concern | pandera | Pydantic |
|---------|---------|---------|
| Operates on DataFrames natively | ✅ Yes | ❌ Requires row-by-row conversion |
| Performance on large tables | ✅ Vectorised | ❌ O(n) model instantiation |
| `lazy=True` collects all errors before raising | ✅ Yes | ❌ Raises on first error |
| Already in the pandas ecosystem | ✅ Yes | ➖ General-purpose |

## Consequences

- Schema definitions live in `accessatlas/ingestion/schemas.py` as Python classes.
- Each schema uses `strict=False` so extra columns (e.g. undocumented fields added to future XLSX versions) do not break validation.
- The API layer (M4) will use Pydantic for request/response models — Pydantic and pandera are complementary, not competing.

## Alternatives considered

- **Pydantic only:** Would require converting each row to a Pydantic model instance, which is slow for 372 k rows.
- **Great Expectations:** Very powerful but heavyweight; adds significant setup overhead for a student project.
- **Manual dtype assertions:** Error-prone and verbose; pandera gives free error messages, nullable logic and value checks.
