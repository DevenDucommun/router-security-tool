# Changelog

## Unreleased (1.2 — Monitoring & Alerts)

### Added

- **Known CVEs**: a scan's OpenWrt, Cisco IOS / IOS XE, Dropbear, and BusyBox
  versions (and, opt-in, critical Linux kernel CVEs) are matched against the
  NIST NVD, which does the version-range matching. Each component lists its
  CVEs with severity, CVSS, and a CISA "known exploited" flag, and the device
  is flagged when it runs software with unpatched critical CVEs. Available on
  the Scan page and from History (`GET /api/history/{id}/cves`). Results are
  cached for 24 hours; NVD errors or `ROUTER_SECURITY_OFFLINE=1` fall back to
  cached data instead of failing. `NVD_API_KEY` raises NVD's rate limit.
- Scans now record the Dropbear and BusyBox versions and keep the raw
  `uname` / `os-release` text in history.

## 1.1.0 — Scan Intelligence

All four v1.1 roadmap items.

### Added

- **Scan comparison**: diff two scans of the same device (new, resolved, and
  still-open findings, severity changes, and the risk-score change) from the
  History page (`GET /api/history/diff`). (#28)
- **Tags & notes** on scans, tag filtering in History, and an inline editor
  (`PATCH /api/history/{id}`, `GET /api/history/tags`). Existing databases
  upgrade in place. (#29)
- **Verify fix**: re-run only the checks behind a finding, or all findings,
  and see Resolved / Still failing without a full rescan
  (`POST /api/scan/verify`; not saved to history). (#30)
- **Batch scanning**: up to 256 devices from a list, CIDR, last-octet range,
  or uploaded hosts file, scanned in parallel (1–8 at a time) with per-device
  progress and a fleet summary (`WS /ws/batch`, `POST /api/targets/parse`). (#31)
- CI now lints and builds the web app. (#29)

### Fixed

- **Docker image**: the published image (since 1.0.0) served no web UI and
  only listened on the container's loopback, so `-p 8000:8000` did not work.
  It now serves the dashboard, listens on all interfaces, and keeps history in
  the `/app/data` volume. New `ROUTER_SECURITY_HOST`, `ROUTER_SECURITY_PORT`,
  and `ROUTER_SECURITY_WEB_DIST` overrides; the local default stays loopback.
  CI now builds and smoke-tests the image on every PR.
- Scanning a device that matches no vendor profile crashed with a 500. (#30)
- Scans started from the web dashboard were never saved to history. (#28)
- History filters ran after the result limit, so older matching scans could
  be missing from a filtered view. (#29)
- History and export routes leaked SQLite connections. (#29)
- `/api/health` and the sidebar reported a hardcoded `1.0.0`. (#29, #31)
- Live scan progress was passed between threads unsafely. (#31)
- The test suite wrote fake scans into the developer's real
  `data/scan_history.db`; tests now use a temporary database
  (`ROUTER_SECURITY_DB`). (#31)

### Changed

- Python 3.10 is now the minimum; CI tests 3.10–3.14. Python 3.9 is end of
  life, and reportlab 5.1 no longer imports on it. (#28)
- Node 22 LTS for the Docker build and the release workflow; Node 20 is end
  of life. (#29)

## 1.0.1

- Modernized license metadata; post-1.0.0 fixes.

## 1.0.0

- Initial release: React + FastAPI dashboard, live SSH assessment with
  OpenWrt, Linksys, and Cisco IOS profiles, scan history, JSON/HTML/PDF export,
  CLI, and Docker image.
