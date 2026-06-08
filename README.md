# Router Security Tool

[![CI](https://github.com/DevenDucommun/router-security-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/DevenDucommun/router-security-tool/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A security assessment tool for network devices. Connects to routers via SSH, runs categorized security checks, and generates actionable findings with vendor-specific intelligence.

## What It Does

1. **Connects** to a device over SSH (or serial console)
2. **Runs generic security checks** — SSH hardening, default credentials, exposed services, firewall rules, file permissions, running processes
3. **Auto-detects the device platform** and runs a vendor-specific profile (OpenWrt, Linksys, Cisco IOS)
4. **Reports findings** with severity ratings, evidence, and remediation steps

Example output from a live assessment:

```
PROFILE: linksys | FINDINGS: 6 | SEVERITY: 1 High, 4 Medium, 1 Info
  [High    ] FW-001      Firewall has no DROP/REJECT rules
  [Medium  ] SSH-001     Dropbear allows password authentication
  [Medium  ] NET-001     37 services exposed on all interfaces
  [Medium  ] PERM-001    Shadow file permissions too open
  [Medium  ] FILE-002    Config files may contain plaintext credentials
  [Info    ] LNK-JNAP-001  JNAP API service running
```

## Architecture

```
src/
├── assessment/
│   ├── ssh_assessor.py          # Core assessment engine (8 generic check categories)
│   ├── finding.py               # Finding data model shared across all checks
│   ├── profiles/                # Device-specific security profiles
│   │   ├── base.py              # Abstract profile base class
│   │   ├── detect.py            # Auto-detection (picks profile from device_info)
│   │   ├── openwrt.py           # UCI firewall, LuCI, wireless, packages, DNS
│   │   ├── linksys.py           # JNAP API, syscfg, firmware version, cloud agent
│   │   └── cisco.py             # running-config, VTY lines, SNMP, AAA, services
│   ├── service_scanner.py       # Network port/service scanning
│   └── vulnerability_scanner.py # CVE correlation and risk scoring
├── connections/
│   ├── manager.py               # SSH + serial connection handling
│   └── detector.py              # USB/network device auto-discovery
├── scraper/
│   └── filesystem.py            # Remote filesystem exploration
├── database/
│   ├── cve_manager.py           # NVD API integration and CVE caching
│   └── scan_history.py          # SQLite scan history
├── gui/
│   └── main_window.py           # PyQt5 interface with threaded workers
└── reports/
    └── export.py                # JSON/HTML/PDF report generation
```

## Installation

```bash
git clone https://github.com/DevenDucommun/router-security-tool.git
cd router-security-tool
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Requirements: Python 3.9+

## Usage

### GUI Mode

```bash
python main.py
```

Connect to a device, then click "Run Vulnerability Scan" for a full assessment.

### Programmatic Usage

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
# Unit tests (168 tests, no network required)
pytest tests/unit/

# Integration tests against a live device
ROUTER_PASS=yourpass pytest tests/integration/ -m network -v

# Full suite with coverage
pytest --cov=src
```

## Device Profiles

The tool auto-detects device type from SSH banner and system info, then runs platform-specific checks:

| Profile | Detection Signal | Checks |
|---------|-----------------|--------|
| **OpenWrt** | `/etc/openwrt_release` | UCI firewall zones, LuCI exposure, wireless encryption, package audit, DNS rebinding |
| **Linksys** | Hostname pattern `Community*` | JNAP API auth, firmware age, `/tmp/syscfg` permissions, cloud agent, default SSID |
| **Cisco IOS** | `Cisco IOS` in version string | enable password type, VTY ACLs, SNMP communities, CDP, AAA, remote logging |

Adding a new profile: subclass `DeviceProfile`, implement `matches()` and `run_checks()`, register in `detect.py`.

## Security Notice

This tool is for **authorized security assessments only**. Only use on devices you own or have explicit written permission to test.

## License

MIT — see [LICENSE](LICENSE).
