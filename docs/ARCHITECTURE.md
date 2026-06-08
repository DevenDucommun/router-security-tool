# Router Security Tool — Web UI Architecture Plan

## Decision: Replace PyQt5 with React + FastAPI

**Why:** PyQt5 desktop GUIs are a dead end for security tool portfolio pieces. Every real
security tool (Nessus, Burp, Qualys, Shodan) is web-based. React + FastAPI gives full-stack
signal, trivial charting, proper dark theme, and a deployment story that works everywhere.

---

## Current Feature Inventory (PyQt5 GUI — what must be replicated)

| Feature | Current Location | Priority |
|---------|-----------------|----------|
| Device discovery (serial + network scan) | `connections/detector.py` | P0 |
| SSH connection management | `connections/manager.py` | P0 |
| Live SSH security assessment | `assessment/ssh_assessor.py` + profiles | P0 |
| Network vulnerability scan (port scan + CVE) | `assessment/vulnerability_scanner.py` | P0 |
| Real-time scan progress | QThread signals → UI | P0 |
| Findings display (grouped by severity) | `display_ssh_assessment_results()` | P0 |
| Risk score calculation + display | `_calculate_ssh_risk_score()` | P0 |
| Filesystem explorer | `scraper/filesystem.py` | P1 |
| Scan history (SQLite) | `database/scan_history.py` | P0 |
| History filtering (target, risk level) | `filter_history()` | P1 |
| Statistics dialog | `show_history_statistics()` | P1 |
| Report export (JSON/HTML/PDF) | `reports/export.py` | P0 |
| Demo mode (mock data) | `utils/mock_data.py` | P1 |
| Console output log | QTextEdit console tab | P1 |

## New Features (Issues #25 + #27 — what we're adding)

| Feature | Description |
|---------|-------------|
| Severity distribution chart | Pie/donut chart of findings by severity |
| Risk score trend | Line chart across scan history |
| Scan comparison | Side-by-side diff of two scans |
| Summary cards | At-a-glance metrics (total findings, risk, last scan) |
| Dark theme | Default dark, professional security-tool aesthetic |
| Keyboard shortcuts | Ctrl+S scan, Ctrl+E export, etc. |
| Responsive layout | Works on tablet-width screens |

## Future Expansion (designed for, not built yet)

| Feature | Notes |
|---------|-------|
| Multi-device fleet view | Scan multiple devices, aggregate dashboard |
| Scheduled scans | Cron-style recurring assessments |
| Remediation tracking | Mark findings as fixed, verify on next scan |
| Custom check authoring | YAML-defined checks users can add |
| Notifications / alerts | WebSocket push when critical finding detected |
| User accounts + RBAC | When moving beyond trusted local network |
| Plugin system | Third-party profile/check packages |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser (React SPA)                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │Dashboard │ │  Scan    │ │ History  │ │ Explorer │           │
│  │(charts)  │ │(live run)│ │(table)   │ │(files)   │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│         ↕ REST                    ↕ WebSocket                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                     ┌────────┴────────┐
                     │   FastAPI (src/api/)  │
                     │  ┌─────────────────┐ │
                     │  │ REST routes     │ │  POST /api/scan
                     │  │ WebSocket       │ │  WS /ws/scan (live progress)
                     │  │ Static files    │ │  GET /* (SPA in prod)
                     │  └─────────────────┘ │
                     └────────┬────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
┌────────┴────────┐  ┌───────┴───────┐   ┌───────┴───────┐
│  Assessment     │  │  Connections  │   │  Database     │
│  Engine         │  │  Manager      │   │  (SQLite)     │
│  ─────────────  │  │  ───────────  │   │  ───────────  │
│  ssh_assessor   │  │  SSH/Serial   │   │  scan_history │
│  profiles/*     │  │  detector     │   │  cve_manager  │
│  vuln_scanner   │  │               │   │               │
│  service_scan   │  │               │   │               │
└─────────────────┘  └───────────────┘   └───────────────┘
```

## Deployment Model: Single Container

```dockerfile
# Stage 1: Build React SPA
FROM node:20-slim AS frontend
WORKDIR /app/web
COPY web/ .
RUN npm ci && npm run build

# Stage 2: Python runtime
FROM python:3.12-slim
COPY --from=frontend /app/web/dist /app/web/dist
COPY src/ /app/src/
COPY pyproject.toml /app/
WORKDIR /app
RUN pip install .
EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

One image, one port. `web/dist/` is served as static files by FastAPI in production.
In development: Vite dev server on :5173 proxies `/api` and `/ws` to FastAPI on :8000.

## Tech Stack

### Backend (Python — existing + new API layer)
- **FastAPI** — async REST + WebSocket, auto-generated OpenAPI docs
- **Pydantic v2** — request/response validation, serialization
- **uvicorn** — ASGI server
- All existing modules unchanged: `assessment/`, `connections/`, `database/`, `scraper/`, `reports/`

### Frontend (TypeScript — new)
- **React 18** — component model
- **Vite** — bundler + HMR dev server
- **TypeScript** — type safety, matches Pydantic models
- **Tailwind CSS v4** — utility-first, dark theme by default
- **Recharts** — severity pie, risk trend line, scan comparison
- **Lucide React** — icons
- No component library (shadcn/ui patterns, but hand-rolled for fewer deps)

### State
- **SQLite** — scan history (existing, unchanged)
- **React state** — no Redux; useReducer for scan state, context for theme/connection

---

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Run assessment (blocking, returns full result) |
| WS | `/ws/scan` | Run assessment with real-time progress |
| GET | `/api/devices` | Discover available devices (serial + network) |
| GET | `/api/history` | List scan history |
| GET | `/api/history/stats` | Aggregate statistics |
| GET | `/api/history/{id}` | Full scan result by ID |
| DELETE | `/api/history/{id}` | Delete scan |
| POST | `/api/export/{format}` | Generate report (json/html/pdf), return file |
| POST | `/api/filesystem` | Start filesystem exploration |

## Frontend Pages

### 1. Dashboard (`/`)
- **Summary cards**: Total scans, avg risk score, devices scanned, critical findings
- **Severity donut chart**: Findings distribution from latest scan
- **Risk trend chart**: Line chart of risk score over time (from history)
- **Recent scans table**: Last 5 scans with quick status
- **Quick-scan button**: One-click rescan of last target

### 2. Scan (`/scan`)
- **Target input**: Host, port, username, password fields
- **Device discovery panel**: Auto-detected devices (click to populate)
- **Live progress**: WebSocket-driven progress messages during scan
- **Results view**: Findings grouped by severity with expand/collapse
  - Each finding: ID, title, description, evidence (code block), remediation
- **Risk gauge**: Visual risk score meter
- **Export buttons**: JSON / HTML / PDF download

### 3. History (`/history`)
- **Filterable table**: Target, date, risk score, finding count, device
- **Compare mode**: Select two scans → side-by-side diff (new/fixed/persistent findings)
- **Trend view**: Chart of risk scores over time per target
- **Bulk actions**: Delete, export selected

### 4. Explorer (`/explorer`)
- **File tree**: Collapsible directory tree from filesystem scraper
- **File details**: Permissions, size, interesting file markers
- **Security findings**: Inline warnings on suspicious files
- Requires active connection (disabled state when not connected)

### 5. Settings (`/settings`) — future
- Saved targets
- Custom check configuration
- Notification preferences
- Theme toggle (dark/light)

## Keyboard Shortcuts
| Key | Action |
|-----|--------|
| `Ctrl+N` | New scan |
| `Ctrl+E` | Export last result |
| `Ctrl+D` | Toggle dashboard |
| `Ctrl+H` | History |
| `Ctrl+K` | Command palette (future) |
| `Escape` | Cancel running scan |

## File Structure

```
router-security-tool/
├── src/
│   ├── api/                    # NEW — FastAPI backend
│   │   ├── __init__.py
│   │   ├── main.py             # App factory, middleware, static mount
│   │   ├── routes/
│   │   │   ├── scan.py         # POST /api/scan, WS /ws/scan
│   │   │   ├── devices.py      # GET /api/devices
│   │   │   ├── history.py      # CRUD /api/history
│   │   │   ├── export.py       # POST /api/export/{format}
│   │   │   └── filesystem.py   # POST /api/filesystem
│   │   └── schemas.py          # Pydantic models
│   ├── assessment/             # UNCHANGED
│   ├── connections/            # UNCHANGED
│   ├── database/               # UNCHANGED
│   ├── scraper/                # UNCHANGED
│   ├── reports/                # UNCHANGED
│   ├── utils/                  # UNCHANGED
│   └── cli.py                  # UNCHANGED
├── web/                        # NEW — React SPA
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx             # Router + layout shell
│   │   ├── api/                # API client + WebSocket hook
│   │   │   ├── client.ts       # fetch wrapper, typed endpoints
│   │   │   └── ws.ts           # useWebSocket hook for scan
│   │   ├── components/
│   │   │   ├── layout/         # Sidebar, Header, StatusBar
│   │   │   ├── charts/         # SeverityChart, RiskTrend, RiskGauge
│   │   │   ├── scan/           # ScanForm, FindingCard, ProgressFeed
│   │   │   ├── history/        # HistoryTable, CompareView
│   │   │   └── explorer/       # FileTree, FileDetails
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Scan.tsx
│   │   │   ├── History.tsx
│   │   │   └── Explorer.tsx
│   │   ├── hooks/              # useKeyboard, useScanState
│   │   └── types/              # TypeScript interfaces matching Pydantic
│   ├── index.html
│   ├── package.json
│   ├── tailwind.config.ts
│   ├── tsconfig.json
│   └── vite.config.ts
├── tests/
│   ├── unit/
│   │   ├── test_api.py         # NEW — FastAPI endpoint tests
│   │   └── ...existing...
│   └── integration/
├── Dockerfile                  # UPDATED — multi-stage (node + python)
├── pyproject.toml              # UPDATED — add fastapi, uvicorn
├── main.py                     # REMOVED (or kept as legacy shim)
└── README.md                   # UPDATED
```

## What Gets Deleted

| File/Dir | Reason |
|----------|--------|
| `src/gui/` | Fully replaced by `web/` |
| `main.py` | PyQt5 entry point, no longer needed |
| PyQt5 from optional deps | No longer used |

## Migration Steps (Implementation Order)

### Phase 1: API Layer (backend)
1. Refactor `src/api/main.py` into route modules
2. Add `/api/devices` endpoint (wraps ConnectionDetector)
3. Add `/api/filesystem` endpoint (wraps FileSystemScraper)
4. Add `/api/export/{format}` endpoint (wraps ReportExporter)
5. Write API tests with `httpx` + `TestClient`

### Phase 2: React Shell + Dashboard
1. Set up routing (react-router-dom)
2. Build layout: sidebar nav + main content area
3. Build Dashboard page with summary cards + charts
4. Connect to `/api/history/stats` for real data

### Phase 3: Scan Page (core feature)
1. Build ScanForm component
2. Implement WebSocket hook for live progress
3. Build FindingCard + severity grouping
4. Build RiskGauge component
5. Device discovery panel (calls `/api/devices`)

### Phase 4: History + Explorer
1. HistoryTable with filters and sorting
2. Scan comparison (diff two results)
3. FileTree explorer component
4. Export integration

### Phase 5: Polish + Ship
1. Keyboard shortcuts
2. Responsive breakpoints
3. Update Dockerfile (multi-stage)
4. Update README
5. Delete `src/gui/`, `main.py`
6. Tag v1.0.0

## Benefits

- **Portfolio impact**: Full-stack (Python API + React + WebSocket) > desktop GUI script
- **Industry alignment**: Security tools are web-based; hiring managers recognize the pattern
- **Charting**: Recharts severity pie + trend line in ~30 lines vs. fighting matplotlib/Qt
- **Dark theme**: Tailwind `dark:` classes — zero effort, looks professional
- **Testability**: API routes are independently testable; React components can be Storybook'd
- **Deployment**: Single Docker image, runs anywhere with a browser
- **Extensibility**: Adding pages/endpoints is trivial; future fleet view, scheduling, etc.
- **Dev experience**: Vite HMR, TypeScript autocomplete, FastAPI auto-docs at /docs

## Drawbacks / Trade-offs

- **More moving parts**: Node build step + Python runtime (mitigated by single Dockerfile)
- **No offline-first**: Requires server running (but so did the old GUI — it's a network tool)
- **Serial console**: Web app can't access USB ports directly. Serial stays CLI-only for now.
  (Future: could add USB passthrough via WebUSB API or keep CLI as the serial path)
- **Build time**: ~30s for React build + Python wheel (acceptable for CI)
- **Bundle size**: React + Recharts + Tailwind → ~200KB gzipped (fine for local tool)

## Auth Model

For v1.0: **No auth**. Trusted local network assumption — tool binds to localhost:8000 by default.
The CLI already handles credentials via env var `ROUTER_PASS`. The web form accepts password
per-scan (never stored, never logged).

Future: Add optional basic auth or session tokens when multi-user / remote access is needed.
