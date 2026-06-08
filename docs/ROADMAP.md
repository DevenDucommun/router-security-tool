# Roadmap

## v1.1 — Scan Intelligence

Focus: Make existing scan data more actionable.

### Features

| Feature | Description |
|---------|-------------|
| **Scan Diff View** | Compare two scans of the same target side-by-side. Show new findings, resolved findings, and risk score delta. Link from History page. |
| **Multi-Device Batch Scan** | Accept a list of targets (CIDR, comma-separated, or file upload) and scan them in parallel. Aggregate results view with per-device breakdown. |
| **Remediation Verification** | After fixing an issue, re-run only the specific failed checks (not the full assessment). One-click "verify fix" from a finding card. |
| **Scan Tags & Notes** | Add labels (e.g. "pre-patch", "post-update") and free-text notes to scans for context in History. |

### Technical Work
- WebSocket multiplexing for parallel scans
- Partial assessment engine (run subset of checks by ID)
- Diff algorithm for finding sets (match by check ID + target)
- Batch progress UI (per-target status cards)

---

## v1.2 — Monitoring & Alerts

Focus: Continuous security posture visibility without manual intervention.

### Features

| Feature | Description |
|---------|-------------|
| **Scheduled Scans** | Cron-style scheduling per device. Configure frequency (hourly/daily/weekly) and credential storage (encrypted at rest). Background worker runs scans on schedule. |
| **Risk Score Alerting** | Configurable thresholds: notify via webhook (Slack, Teams, generic HTTP) when risk score exceeds threshold or increases by N points between scans. |
| **CVE Correlation** | Pull NVD/CVE feeds for detected firmware versions. Show known CVEs alongside scan findings. Flag devices running firmware with unpatched critical CVEs. |
| **Dashboard Enhancements** | Fleet health heatmap (devices as colored tiles by risk). Alert history timeline. "Devices needing attention" priority list. |

### Technical Work
- Background task scheduler (APScheduler or Celery-lite)
- Encrypted credential store (Fernet symmetric encryption, key from env var)
- NVD API integration with local cache (SQLite table)
- Webhook dispatch with retry logic
- Settings page for alert config and schedules

---

## v1.3 — Extensibility

Focus: Power users and compliance teams can customize the tool for their environment.

### Features

| Feature | Description |
|---------|-------------|
| **Custom Check Authoring** | Define security checks via YAML files. Specify: command to run, regex to match, severity, remediation text. Hot-reload from a `checks/` directory. |
| **Compliance Frameworks** | Map findings to CIS Benchmarks (router/network device sections) and NIST 800-53 controls. Generate compliance summary reports showing pass/fail per control. |
| **PDF Report Branding** | Custom logo, company name, and header/footer in exported PDF reports. Configurable via settings. |
| **API Authentication** | Optional API key or JWT auth for multi-user or remote access deployments. RBAC: viewer (read history), operator (run scans), admin (settings). |

### Technical Work
- YAML check parser with schema validation
- Compliance mapping tables (check ID → CIS/NIST control IDs)
- Report template engine (Jinja2 for HTML→PDF pipeline)
- Auth middleware (disabled by default, opt-in via config)
- User/API key management endpoints

---

## v1.4 — Advanced Assessment

Focus: Deeper and broader security analysis capabilities.

### Features

| Feature | Description |
|---------|-------------|
| **Configuration Backup & Drift Detection** | Snapshot full device config, detect changes between scans. Alert on unexpected config modifications (e.g. firewall rule removed). |
| **Firmware Analysis** | Extract and analyze firmware images (uploaded or pulled from device). Check for hardcoded credentials, outdated libraries, known vulnerable binaries. |
| **Wireless Security Audit** | Dedicated wireless checks: WPA3 enforcement, rogue AP detection patterns, channel overlap, client isolation, PMF status. |
| **Service Fingerprinting** | Beyond port scanning — identify exact service versions via banner grabbing and probe responses. Cross-reference with CVE data. |

### Technical Work
- Config diff engine (structured UCI/IOS diff, not raw text)
- Binwalk/squashfs integration for firmware extraction
- Wireless-specific check profile (iwinfo/iw parsing)
- Nmap-style service probes (lightweight, focused on router services)

---

## v2.0 — Platform

Focus: Transform from single-user tool into a team security platform.

### Features

| Feature | Description |
|---------|-------------|
| **Network Topology Map** | Interactive D3/Cytoscape visualization of discovered devices, their relationships, and security status. Color-coded by risk level. Click-through to device details. |
| **Agent-Based Scanning** | Lightweight agent that runs on the device itself (OpenWrt package). Eliminates SSH credential management. Push-based results via MQTT or HTTP. Enables continuous monitoring without polling. |
| **Multi-Site Management** | Manage devices across multiple networks/locations. Site grouping, cross-site comparison, aggregate reporting. Site-level risk scoring. |
| **Plugin Ecosystem** | Formal plugin API for device profiles, check modules, exporters, and notification channels. Community-contributed plugins via registry. |
| **Remediation Playbooks** | Automated or semi-automated fix application. For each finding, offer a "Fix" button that runs the remediation command (with confirmation). Track fix history. |
| **Audit Trail** | Full history of who scanned what, when, and what actions were taken. Immutable log for compliance. Export to SIEM (syslog/CEF format). |

### Technical Work
- PostgreSQL migration (SQLite won't scale for multi-user)
- Real-time event bus (Redis pub/sub or SSE)
- Agent package (C/Lua for OpenWrt, fits in flash)
- Plugin SDK with typed interfaces and lifecycle hooks
- Topology discovery (CDP/LLDP/ARP table correlation)
- WebSocket channels per site for live updates
- Migration tooling (v1.x SQLite → v2.0 Postgres)

---

## Version Strategy

| Version | Theme | Target |
|---------|-------|--------|
| **1.1** | Scan Intelligence | Make current data more useful |
| **1.2** | Monitoring | Automate the manual "go scan" workflow |
| **1.3** | Extensibility | Let users customize for their environment |
| **1.4** | Advanced Assessment | Deeper security analysis |
| **2.0** | Platform | Multi-user, multi-site, agent-based |

Each minor version is independently shippable. No version depends on the one before it being complete — features can be cherry-picked across versions based on priority.
