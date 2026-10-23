# AccessAtlas — Security Intelligence Dashboard

Modern web dashboard for AccessAtlas providing multi-platform identity posture visibility, deterministic rule-based finding triage, effective privilege grant path visualization, and quantitative scenario benchmark evaluations across Active Directory, AWS IAM, and Okta.

---

## Technology Stack

- **Framework**: [React 18](https://react.dev/) (Plain JavaScript ES2020)
- **Build Tool**: [Vite 5](https://vitejs.dev/)
- **Routing**: [React Router DOM 6](https://reactrouter.com/)
- **Analytics & Charts**: [Recharts 2](https://recharts.org/)
- **Graph & Flow Visualizations**: [@xyflow/react 12](https://reactflow.dev/) (React Flow)
- **Styling**: Vanilla CSS with modern CSS variables, responsive design, and dynamic light/dark theme toggle synced with system preference and `localStorage`.
- **Linting**: ESLint 8 with `eslint-plugin-react` and `eslint-plugin-react-hooks`.

---

## Development

### Prerequisites

- Node.js 18+ (tested on Node.js 20 and 24)
- Running AccessAtlas FastAPI backend (defaults to `http://127.0.0.1:8000`)

### Installation

```bash
cd frontend
npm install
```

### Running Locally

```bash
npm run dev
```

The application will start at `http://localhost:5173`.

To point to a custom API host or port, define `VITE_API_URL`:
```bash
VITE_API_URL=http://localhost:8000 npm run dev
```

---

## Production Build & Linting

### Linting

```bash
npm run lint
```

### Building Bundle

```bash
npm run build
```

The compiled static assets will be output to `frontend/dist/`.

### Previewing Production Build

```bash
npm run preview
```

---

## Running with Docker

The multi-stage `Dockerfile` compiles the React frontend and serves static assets via a lightweight Nginx container:

```bash
docker build -t accessatlas-frontend .
docker run -d -p 80:80 accessatlas-frontend
```

Open `http://localhost` in your browser.
