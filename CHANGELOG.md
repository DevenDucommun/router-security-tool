# Changelog

## Unreleased (1.2 — Monitoring & Alerts)

### Added

- **Scheduled scans**: re-scan a device hourly, every 6 hours, daily, weekly, or
  any interval from 15 minutes to 30 days. A background worker in the web
  server runs due scans (two at a time) through the normal scan path; results
  are saved to History tagged `scheduled` plus the schedule's tags. New
  Schedules page: create, run now, pause/resume, change interval or password,
  delete, and see last status, error, risk score, and scan.
- **Encrypted credential store**: schedule passwords are encrypted with Fernet
  (`ROUTER_SECURITY_SECRET_KEY`, or a 0600 key file next to the database) and
  are never returned by the API.

### Fixed

- Opening a pre-1.1 history database from several scans at once (batch or
  scheduled) could fail with `duplicate column name: tags`.
- API validation errors showed as `[object Object]` in the web app.

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
