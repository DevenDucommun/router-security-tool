# Router Security Tool

[![CI](https://github.com/DevenDucommun/router-security-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/DevenDucommun/router-security-tool/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A security assessment tool for network devices. Connects to routers via SSH, runs categorized security checks, and reports findings through a real-time web dashboard or CLI.

## What It Does

1. **Connects** to a device over SSH
2. **Runs generic security checks** — SSH hardening, default credentials, exposed services, firewall rules, file permissions, running processes
3. **Auto-detects the device platform** and runs vendor-specific checks (OpenWrt, Linksys, Cisco IOS)
4. **Reports findings** with severity ratings, evidence, and remediation steps
5. **Visualizes** risk scores, severity distribution, and trends over time

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

## Installation

### Quick Start (Web UI)

```bash
git clone https://github.com/DevenDucommun/router-security-tool.git
cd router-security-tool
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cd web && npm install && npm run build && cd ..
router-security-web
# Open http://localhost:8000
```

### CLI Only (no Node.js required)

```bash
pip install git+https://github.com/DevenDucommun/router-security-tool.git
router-security-tool scan 192.168.1.1 -p yourpass
```

### Docker (single container: API + Web UI)

```bash
docker build -t router-security-tool .
docker run --rm -p 8000:8000 --network host router-security-tool
# Open http://localhost:8000
```

### Development

```bash
# Terminal 1: Backend
source .venv/bin/activate
uvicorn api.main:app --reload --app-dir src

# Terminal 2: Frontend (hot reload)
cd web && npm run dev
# Open http://localhost:5173 (proxies API to :8000)
```

## Usage

### Web Dashboard

The web UI provides:
- **Dashboard** — Summary cards, severity donut chart, risk trend line, recent scans
- **Scan** — Target input, device discovery, real-time WebSocket progress, findings with evidence
- **History** — Filterable table, risk trend visualization, export/delete actions
- **Explorer** — Remote filesystem browsing with security findings

### CLI

```bash
# Quick scan with table output
router-security-tool scan 192.168.1.1 -u root -p $ROUTER_PASS

# JSON output for CI pipelines
router-security-tool scan 192.168.1.1 -p $ROUTER_PASS --format json

# Exit codes: 0=clean, 1=medium, 2=high, 3=critical
echo $?
```

### Programmatic

```python
from connections.manager import ConnectionManager
from assessment.ssh_assessor import SSHAssessor

conn = ConnectionManager()
conn.connect_ssh("192.168.1.1", "root", "password")

assessor = SSHAssessor(conn)
results = assessor.run_assessment()

for finding in results["findings"]:
    print(f"[{finding['severity']}] {finding['id']}: {finding['title']}")

conn.disconnect()
```

## Testing

```bash
# All unit tests (API + profiles + CLI + scanner)
pytest tests/unit/ -v

# Integration tests against a live device
ROUTER_PASS=yourpass pytest tests/integration/ -m network -v

# Coverage
pytest --cov=src tests/unit/
```

## Device Profiles

Auto-detects platform from SSH banner and system info:

| Profile | Detection Signal | Checks |
|---------|-----------------|--------|
| **OpenWrt** | `/etc/openwrt_release` | UCI firewall zones, LuCI exposure, wireless encryption, package audit, DNS rebinding |
| **Linksys** | Hostname `Community*` | JNAP API auth, firmware age, `/tmp/syscfg` permissions, cloud agent, default SSID |
| **Cisco IOS** | `Cisco IOS` in version | enable password type, VTY ACLs, SNMP communities, CDP, AAA, remote logging |

Adding a new profile: subclass `DeviceProfile`, implement `matches()` and `run_checks()`, register in `detect.py`.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Run assessment (returns full result) |
| WS | `/ws/scan` | Run assessment with real-time progress |
| GET | `/api/devices` | Auto-discover network devices |
| GET | `/api/history` | List scan history (filterable) |
| GET | `/api/history/stats` | Aggregate statistics |
| DELETE | `/api/history/{id}` | Delete a scan |
| POST | `/api/export/{format}` | Generate report (json/html/pdf) |
| POST | `/api/filesystem` | Explore remote filesystem |

Interactive API docs available at `http://localhost:8000/docs` (Swagger UI).

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+N` | New scan |
| `Ctrl+D` | Dashboard |
| `Ctrl+H` | History |

## Security Notice

This tool is for **authorized security assessments only**. Only use on devices you own or have explicit written permission to test.

## License

MIT — see [LICENSE](LICENSE).
