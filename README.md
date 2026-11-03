# Router Security Tool

[![CI](https://github.com/DevenDucommun/router-security-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/DevenDucommun/router-security-tool/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A full-stack security assessment platform for network devices. Connects to routers via SSH, runs 40+ automated security checks with device-specific profiles, and presents findings through a real-time web dashboard.

**Tech Stack:** React 18 + TypeScript + Tailwind CSS | FastAPI + WebSocket | SQLite | Paramiko SSH | Docker

![Dashboard](docs/screenshots/dashboard.png)

## Key Features

- **Real-time scanning** via WebSocket with live progress feed
- **Auto-detection** of device platform (OpenWrt, Linksys, Cisco IOS) with vendor-specific checks
- **Risk scoring** algorithm with severity-weighted findings and trend tracking
- **Web dashboard** with severity distribution charts, risk trends, and scan history
- **Scan comparison** — diff two scans of the same device: new, resolved, and still-open findings plus the risk change
- **Tags & notes** on scans (e.g. `pre-patch`, `post-update`) with tag filtering in History
- **Verify fix** — after remediating, re-run only the checks behind a finding (or all findings) and see Resolved / Still failing, without a full rescan
- **Batch scanning** — scan up to 256 devices in parallel from a list, CIDR (`10.0.0.0/29`), range (`192.168.1.10-20`), or uploaded hosts file, with per-device progress and a fleet summary (riskiest devices, most common findings)
- **Known CVEs** — matches detected OpenWrt, Cisco IOS, Dropbear, and BusyBox versions (and optionally the Linux kernel) against the NIST NVD, flags unpatched critical and actively exploited (CISA KEV) CVEs, and caches results for 24 hours
- **Remote filesystem explorer** with security finding annotations
- **Multi-format export** (JSON, HTML, PDF) for reporting
- **CLI mode** with exit codes suitable for CI/CD pipelines
- **Single-container Docker deployment** (multi-stage build: Node frontend + Python backend)

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                  React SPA (Vite + TypeScript + Tailwind)       │
│  Dashboard │ Scan (WebSocket) │ History │ Filesystem Explorer  │
└───────────────────────────┬────────────────────────────────────┘
                            │ REST + WebSocket
┌───────────────────────────┴────────────────────────────────────┐
│                     FastAPI Backend                              │
│  /api/scan  /api/devices  /api/history  /api/export  /ws/scan  │
└───────┬────────────┬───────────────┬───────────────────────────┘
        │            │               │
┌───────┴──────┐ ┌───┴────────┐ ┌───┴─────────┐
│  Assessment  │ │ Connections│ │  Database   │
│  Engine      │ │ Manager    │ │  (SQLite)   │
│  ──────────  │ │ ─────────  │ │  ─────────  │
│  ssh_assessor│ │ SSH/Serial │ │ scan_history│
│  profiles/*  │ │ detector   │ │ cve_manager │
│  vuln_scanner│ │            │ │             │
└──────────────┘ └────────────┘ └─────────────┘
```

## Quick Start

### Web UI (recommended)

```bash
git clone https://github.com/DevenDucommun/router-security-tool.git
cd router-security-tool
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cd web && npm install && npm run build && cd ..
router-security-web
# Open http://localhost:8000
```

### Docker

```bash
docker build -t router-security-tool .
docker run --rm -p 8000:8000 -v rst-data:/app/data router-security-tool
# or the published image: ghcr.io/devenducommun/router-security-tool:latest
# On Linux, add --network host (and drop -p) if routers are only reachable from the host network.
```

### CLI Only (no Node.js required)

```bash
pip install git+https://github.com/DevenDucommun/router-security-tool.git
router-security-tool scan 192.168.1.1 -u root -p $ROUTER_PASS
```

### Development (hot reload)

```bash
# Terminal 1: Backend
source .venv/bin/activate
uvicorn api.main:app --reload --app-dir src

# Terminal 2: Frontend
cd web && npm run dev
# Open http://localhost:5173 (proxies API to :8000)
```

## How It Works

1. **Connects** to a target device over SSH (paramiko)
2. **Auto-detects the platform** from SSH banner, filesystem, and system info
3. **Runs generic checks** — SSH hardening, default credentials, exposed services, firewall rules, file permissions, running processes
4. **Runs profile-specific checks** — vendor-appropriate security items for the detected platform
5. **Scores risk** using a severity-weighted algorithm (Critical=10, High=7.5, Medium=5, Low=2, Info=0.5) with a density multiplier
6. **Streams progress** over WebSocket to the frontend in real time
7. **Persists results** to SQLite for historical trend analysis

## Device Profiles

| Profile | Detection Signal | Example Checks |
|---------|-----------------|----------------|
| **OpenWrt** | `/etc/openwrt_release` | UCI firewall zones, LuCI exposure, wireless encryption, package audit, DNS rebinding |
| **Linksys** | Hostname `Community*` | JNAP API auth, firmware age, `/tmp/syscfg` permissions, cloud agent, default SSID |
| **Cisco IOS** | `Cisco IOS` in version | enable password type, VTY ACLs, SNMP communities, CDP, AAA, remote logging |

Adding a new profile: subclass `DeviceProfile`, implement `matches()` and `run_checks()`, register in `detect.py`.

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Run assessment (returns full result) |
| POST | `/api/scan/verify` | Re-run only the checks behind the given finding IDs (not saved to history) |
| POST | `/api/targets/parse` | Preview how a batch target list expands |
| WS | `/ws/batch` | Batch scan with per-device progress and a fleet summary |
| WS | `/ws/scan` | Run assessment with real-time progress |
| GET | `/api/devices` | Auto-discover network devices |
| GET | `/api/history` | List scan history (filterable by target, risk level, tag) |
| GET | `/api/history/stats` | Aggregate statistics |
| GET | `/api/history/tags` | Tags in use across all scans |
| GET | `/api/history/diff?base=&head=` | Compare two scans of the same target |
| GET | `/api/history/{id}` | Full stored scan result |
| GET | `/api/history/{id}/cves?refresh=&kernel=` | Known CVEs (NIST NVD) for the software versions recorded in a scan |
| PATCH | `/api/history/{id}` | Set tags and/or notes on a scan |
| DELETE | `/api/history/{id}` | Delete a scan record |
| POST | `/api/export/{format}` | Generate report (json/html/pdf) |
| POST | `/api/filesystem` | Explore remote filesystem |

Interactive API docs: `http://localhost:8000/docs` (Swagger UI)

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `ROUTER_SECURITY_HOST` / `ROUTER_SECURITY_PORT` | `127.0.0.1` / `8000` | Web server bind address (the Docker image uses `0.0.0.0`) |
| `ROUTER_SECURITY_DB` | `data/scan_history.db` | Scan history database |
| `ROUTER_SECURITY_CVE_DB` | next to the history DB | CVE lookup cache |
| `NVD_API_KEY` | unset | [NVD API key](https://nvd.nist.gov/developers/request-an-api-key): raises the rate limit from 5 to 50 requests per 30 s, so first lookups are much faster |
| `ROUTER_SECURITY_OFFLINE` | unset | `1` disables all NVD requests; CVE lookups use cached data only |

CVE lookups send only product names and versions (as CPE names) to NVD, never addresses, hostnames, or credentials. They run only when you click **Check NVD**.

## Testing

```bash
# Unit tests (300+ tests covering API, profiles, CLI, scanner, database, export, diff, batch)
pytest tests/unit/ -v

# Integration tests against a live device
ROUTER_PASS=yourpass pytest tests/integration/ -m network -v

# Coverage report
pytest --cov=src tests/unit/
```

## Project Structure

```
src/
├── api/              # FastAPI app, routes, schemas, WebSocket handler
├── assessment/       # SSH assessor, security check orchestration
├── connections/      # SSH/serial connection manager, device detector
├── database/         # SQLite scan history, CVE manager
├── profiles/         # Device-specific security profiles (OpenWrt, Linksys, Cisco)
├── reports/          # Export engine (JSON, HTML, PDF)
├── scraper/          # Remote filesystem explorer
└── utils/            # Mock data generator, helpers
web/
├── src/
│   ├── components/   # Charts, layout, scan UI components
│   ├── pages/        # Dashboard, Scan, History, Explorer
│   ├── api/          # REST client, WebSocket hook
│   └── hooks/        # Keyboard shortcuts
└── vite.config.ts    # Dev proxy + Tailwind
tests/
├── unit/             # 300+ unit tests
└── integration/      # Live device tests (requires SSH access)
```

## Security Notice

This tool is for **authorized security assessments only**. Only use on devices you own or have explicit written permission to test.

## License

MIT — see [LICENSE](LICENSE).
