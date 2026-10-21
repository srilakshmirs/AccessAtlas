# Tech Stack — AccessAtlas

This document covers every library used in the project, why it was chosen,
which module uses it, and a one-sentence explanation for a guide/examiner.

---

## Backend

### Runtime dependencies

| Library | Version | Why chosen over alternatives | Module(s) that use it | Examiner one-liner |
|---------|---------|------------------------------|----------------------|-------------------|
| **Python 3.11** | 3.11 | Latest stable with improved error messages and `tomllib` built in; required by the spec. | All | Python 3.11 is the current LTS release with faster startup and better tracebacks than 3.10. |
| **pandas** | ≥2.1 | Industry standard for tabular data; direct `.read_parquet()` / `.to_parquet()` support; familiar to the team. Alternatives: polars (faster but less mature ecosystem), dask (overkill for our scale). | `ingestion/`, `resolution/`, `graph/`, `rules/`, `evaluation/` | pandas is the standard Python library for reading, transforming and analysing tabular data in DataFrames. |
| **pyarrow** | ≥14.0 | Parquet engine for pandas; columnar storage retains dtypes (datetime, bool) and is columnar-memory-mapped for fast reads. Alternatives: fastparquet (slower, less maintained). | `ingestion/` (via pandas) | pyarrow is the engine that converts our spreadsheet data to and from Parquet, a column-oriented file format that is much faster to read than XLSX. |
| **openpyxl** | ≥3.1 | Required by `pandas.read_excel()` to open `.xlsx` files; read-only mode reduces memory use during the one-time conversion. | `scripts/convert_data.py` | openpyxl is the library that reads Microsoft Excel files; we use it only once to convert the source data to Parquet. |
| **pandera** | ≥0.18 | Declarative DataFrame schema classes; validates dtypes, nullability and value ranges; `lazy=True` collects all errors before raising; operates on DataFrames natively without row-by-row conversion. Alternatives: Great Expectations (too heavyweight), Pydantic (designed for single objects, not tables). | `ingestion/schemas.py` | pandera lets us declare what each table's columns, types and value ranges should look like, and raises a descriptive error if the data doesn't match. |
| **tqdm** | ≥4.66 | Progress bar for the one-time XLSX conversion; makes it clear that the ~2-minute events conversion is still running. | `scripts/convert_data.py` | tqdm adds a progress bar to loops so the user can see how far along the data conversion is. |
| **PyYAML** | ≥6.0 | Reads `config.yaml`; avoids hard-coded paths in source files. Alternatives: `tomllib` (Python 3.11 stdlib, but TOML is less readable for nested config). | `accessatlas/utils.py` | PyYAML reads our YAML configuration file so that paths and settings can be changed without editing source code. |
| **RapidFuzz** | ≥3.6 | Fast fuzzy string matching for identity resolution (M2); C++ backend via wheels, significantly faster than `fuzzywuzzy` and does not require `python-Levenshtein`. Evaluates name/handle similarity with an ambiguity tie-breaker. | `resolution/`, `evaluation/` | RapidFuzz computes string similarity scores between usernames across platforms so we can match identities even when spellings or formats differ. |
| **NetworkX** | ≥3.2 | Directed graph library for the privilege graph (M3); handles cycles (via `simple_cycles`), shortest paths and graph traversal natively. | `graph/` (M3) | NetworkX lets us model identities, groups and policies as a graph so we can trace which permissions each identity inherits through nested group membership. |
| **FastAPI** | ≥0.110 | High-performance async API framework with automatic OpenAPI docs; CORS middleware built in for the React frontend. Alternatives: Flask (synchronous, less modern), Django REST (more opinionated). | `api/` (M4) | FastAPI automatically generates API documentation and handles JSON serialisation while supporting async requests for better performance. |
| **Uvicorn** | ≥0.27 | ASGI server for FastAPI; `[standard]` extras add `uvloop` for performance. | `api/` (M4) | Uvicorn is the server that runs the FastAPI application and serves HTTP requests. |

### Development dependencies

| Library | Why |
|---------|-----|
| **pytest** ≥8.0 | Standard Python test runner; parametrise, fixtures, and clear failure messages. |
| **pytest-cov** ≥4.1 | Coverage reporting so we can see which branches are untested. |
| **ruff** ≥0.3 | Single fast tool replacing flake8 + black + isort; enforced in CI. |

---

## Frontend (added in M4)

| Library | Why chosen | Module |
|---------|-----------|--------|
| **React 18** | Component model for a dynamic findings UI; required by spec. | All frontend components |
| **Vite** | Fast dev server and build tool for React; much faster than CRA. | Build tooling |
| **React Router** | Client-side routing for /findings, /identities/:id, /evaluation. | Navigation |
| **Recharts** | Declarative chart library built on D3 for the evaluation precision/recall charts. | Evaluation page |
| **React Flow** | Interactive node-edge graph for visualising the privilege path. | Identity detail page |
| **ESLint** | Lints JavaScript to catch errors and enforce style; run in CI. | Dev tooling |

---

## Infrastructure

| Tool | Why |
|------|-----|
| **Docker** | Reproducible build for backend (and frontend in M4); runs anywhere. |
| **docker-compose** | Runs both services together with a single command. |
| **GitHub Actions** | Free CI that runs lint and tests on every push. |

---

_Last updated: M2 (2026-10-21)_

