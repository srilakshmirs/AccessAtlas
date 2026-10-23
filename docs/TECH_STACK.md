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
| **NetworkX** | ≥3.2 | Directed graph library for the privilege graph (M3); handles cycles natively via BFS shortest-path traversal, calculates direct and effective privilege tiers, and tracks grant paths. | `graph/` (M3), `evaluation/` (M3) | NetworkX lets us model identities, groups and policies as a graph so we can trace which permissions each identity inherits through nested group membership and federation. |
| **FastAPI** | ≥0.110 | High-performance async API framework with automatic OpenAPI docs; CORS middleware built in for the React frontend. Alternatives: Flask (synchronous, less modern), Django REST (more opinionated). | `api/` (M4) | FastAPI automatically generates API documentation and handles JSON serialisation while supporting async requests for better performance. |
| **Uvicorn** | ≥0.27 | ASGI server for FastAPI; `[standard]` extras add `uvloop` for performance. | `api/` (M4) | Uvicorn is the server that runs the FastAPI application and serves HTTP requests. |

### Development dependencies

| Library | Why |
|---------|-----|
| **pytest** ≥8.0 | Standard Python test runner; parametrise, fixtures, and clear failure messages. |
| **pytest-cov** ≥4.1 | Coverage reporting so we can see which branches are untested. |
| **ruff** ≥0.3 | Single fast tool replacing flake8 + black + isort; enforced in CI. |
| **httpx** ≥0.27 | Test-only dependency required by Starlette's `TestClient` (`fastapi.testclient.TestClient`) to execute in-process HTTP requests against the FastAPI application in `tests/test_api.py`. |

---

## Frontend (added in M6)

| Library | Version | What it is | Why chosen over alternatives | Module(s) that use it | Examiner one-liner |
|---------|---------|------------|------------------------------|----------------------|-------------------|
| **React 18** | ≥18.3 | Component-based UI library | Industry-standard declarative component model for building dynamic single-page web applications. Alternatives: Vue, Angular, Svelte. | All frontend components | React provides the reactive component model and state management for rendering live IAM findings and metrics. |
| **react-dom** | ≥18.3 | DOM renderer for React | Required entrypoint and renderer for mounting React component trees into the browser DOM (`createRoot`). | `frontend/src/main.jsx` | react-dom translates React component definitions into actual browser DOM elements. |
| **Vite** | ≥5.2 | Next-generation frontend build tool | Extremely fast Hot Module Replacement (HMR) development server and Rollup-based production bundler; far faster and leaner than legacy Create React App or Webpack. | Build and development tooling | Vite provides near-instant local development server reload and minified static asset bundling. |
| **React Router DOM** | ≥6.23 | Client-side routing library | Standard declarative client-side navigation supporting deep-linked URLs (`/`, `/findings`, `/identities/:id`, `/evaluation`) without page reloads. Alternatives: TanStack Router. | `frontend/src/App.jsx`, `frontend/src/components/Navbar.jsx` | React Router enables smooth multi-page navigation and URL parameter routing within a single-page application. |
| **Recharts** | ≥2.12 | Composable charting library built on React and D3 | Declarative SVG-based charting components (`PieChart`, `BarChart`, `ResponsiveContainer`) that adapt seamlessly to responsive containers and dynamic light/dark color themes. Alternatives: Chart.js, Victory. | `frontend/src/pages/Overview.jsx` | Recharts renders interactive SVG severity and detection rule distribution charts for security posture analytics. |
| **@xyflow/react** | ≥12.0 | Node-based workflow and graph diagram library (React Flow) | Powerful, interactive SVG/canvas node-and-edge graph library supporting customizable node cards, animated edges, and auto-zoom for privilege grant chains. Alternatives: Cytoscape.js, Vis.js. | `frontend/src/pages/IdentityDetail.jsx` | React Flow visualizes multi-hop privilege escalation paths as an interactive chain of identities, groups, and permissions. |
| **ESLint** | ≥8.57 | Static code analysis linter for JavaScript | Enforces clean ES2020 JavaScript syntax, catches unused variables, and verifies React Hooks rules (`eslint-plugin-react-hooks`) in CI. | Dev tooling and CI workflow | ESLint inspects the frontend JavaScript source code for syntax errors and violations of React best practices. |

---

## Infrastructure

| Tool | Why |
|------|-----|
| **Docker** | Reproducible containerized builds for backend API and frontend Nginx static serving; runs consistently on any host. |
| **docker-compose** | Orchestrates both backend API and frontend static server services together with a single command. |
| **GitHub Actions** | Automated CI pipeline that executes linting, code formatting verification, and test suites on every push and pull request. |

---

_Last updated: M6 (2026-10-23)_


