# Architecture — AccessAtlas

## System overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Data Layer (M1)                         │
│  data/raw/ (XLSX) ──► scripts/convert_data.py ──► data/processed/ (Parquet) │
│                              ▲                                   │
│                    accessatlas/ingestion/                        │
│                    loader.py · schemas.py · cleaning.py          │
└────────────────────────────────────┬────────────────────────────┘
                                     │ DataFrames
┌────────────────────────────────────▼────────────────────────────┐
│                    Resolution Layer (M2)                        │
│            accessatlas/resolution/                              │
│   Links AD / AWS / Okta accounts → HR employee_id              │
│   Output: identity_links.parquet + confidence scores           │
└────────────────────────────────────┬────────────────────────────┘
                                     │ Resolved identities
┌────────────────────────────────────▼────────────────────────────┐
│                      Graph Layer (M3)                           │
│               accessatlas/graph/                                │
│   NetworkX directed graph: identity → groups → policies → tier │
│   Computes effective tier, handles cycles, stores grant path   │
└────────────────────────────────────┬────────────────────────────┘
                                     │ Privilege data
┌────────────────────────────────────▼────────────────────────────┐
│                    Rules + API Layer (M4)                       │
│     accessatlas/rules/   accessatlas/api/                      │
│   Rule-based detections → Findings with evidence + remediation │
│   FastAPI endpoints: /health /identities /findings /evaluation │
└────────────────────────────────────┬────────────────────────────┘
                                     │ JSON (CORS enabled)
┌────────────────────────────────────▼────────────────────────────┐
│                      Frontend (M4)                              │
│         frontend/ (React + Vite)                                │
│   Findings table · Identity detail · Privilege graph (ReactFlow)│
│   Evaluation charts (Recharts)                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Evaluation module (separate from all layers above)

```
accessatlas/evaluation/
```

The evaluation module is the **only** place that may read GT_ ground-truth
sheets. It loads GT_Labels, GT_EffectivePrivilege, GT_IdentityLinks and
GT_InjectedEvents from `data/processed/gt/` and reports per-scenario
precision, recall, and F1 by split (train / test / holdout).

CI enforces the isolation: `tests/test_gt_isolation.py` fails if any source
file outside `evaluation/` references a GT_ sheet name.

## Data flow — M1 detail

```
XLSX (read-only, openpyxl)
  └─► pandas.read_excel()
        └─► cleaning.py  (coerce dates, normalise booleans, null 'n/a')
              └─► schemas.py (pandera validation, lazy=True for full error list)
                    └─► pyarrow Parquet (columnar, fast to read at runtime)
```

## Ground-truth split policy

GT_Labels has a `split` column with three values:
- **train** — used to tune rule thresholds and suppression logic
- **test** — used to report final accuracy during development
- **holdout** — never looked at during development; reported separately at submission

This prevents overfitting the rules to the test labels.
