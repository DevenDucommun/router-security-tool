"""CVE correlation: match software versions found on a device against NVD.

Flow:
  identify_components(device_info) -> [Component]      (pure, no network)
  correlate(components, client, cache)  -> report dict (NVD lookups, cached)

NVD's ``virtualMatchString`` does the version-range matching server side, so a
CPE like ``cpe:2.3:o:openwrt:openwrt:21.02.0`` returns every CVE whose
configuration covers 21.02.0, including "versions before 21.02.7" ranges.

Lookups never fail a caller: network errors, rate limits, and offline mode
fall back to cached data and are reported in ``status`` / ``errors``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000
MAX_CVES_PER_COMPONENT = 2000  # hard cap on pages fetched for one component
TOP_CVES_RETURNED = 50  # per component, highest score first
DEFAULT_TTL = timedelta(hours=24)

# Without an API key NVD allows 5 requests / 30 s; with one, 50 / 30 s.
MIN_INTERVAL_NO_KEY = 6.5
MIN_INTERVAL_WITH_KEY = 0.7


# --------------------------------------------------------------------------- #
# Component identification
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Component:
    key: str  # stable id, e.g. "openwrt"
    name: str  # display name
    part: str  # CPE part: "o" (OS) or "a" (application)
    vendor: str
    product: str
    version: str
    source: str  # which device_info field it came from
    critical_only: bool = False  # query only CRITICAL CVEs (very large products)

    @property
    def cpe(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{cpe_escape(self.version)}"


def cpe_escape(value: str) -> str:
    """Escape a CPE 2.3 formatted-string component (lowercase, backslash specials)."""
    out = []
    for ch in value.lower():
        if ch.isalnum() or ch in "_-.":
            out.append(ch)
        else:
            out.append("\\" + ch)
    return "".join(out)


_OS_RELEASE_KV = re.compile(r"""^\s*([A-Z_]+)\s*=\s*["']?([^"'\n]*)["']?\s*$""", re.M)


def _kv(text: str) -> Dict[str, str]:
    return {k: v.strip() for k, v in _OS_RELEASE_KV.findall(text or "")}


def _openwrt_version(device_info: Dict[str, Any]) -> Optional[tuple]:
    for field in ("os_release", "firmware_version", "version"):
        kv = _kv(device_info.get(field, ""))
        ident = (kv.get("ID") or kv.get("DISTRIB_ID") or "").lower()
        if ident != "openwrt":
            continue
        ver = kv.get("VERSION_ID") or kv.get("DISTRIB_RELEASE") or kv.get("VERSION") or ""
        m = re.match(r"(\d+\.\d+(?:\.\d+)?(?:-rc\d+)?)", ver.lower())
        if m:
            return m.group(1), field
    return None


_CISCO_VERSION = re.compile(r"Cisco IOS[^\n]*?Version\s+([0-9][0-9A-Za-z.()]*[0-9A-Za-z)])", re.I)


def _cisco_component(device_info: Dict[str, Any]) -> Optional[Component]:
    for field in ("uname", "os_release", "firmware_version", "version"):
        text = device_info.get(field, "") or ""
        m = _CISCO_VERSION.search(text)
        if m:
            xe = re.search(r"IOS[\s-]XE", text, re.I)
            return Component(
                key="cisco_ios_xe" if xe else "cisco_ios",
                name="Cisco IOS XE" if xe else "Cisco IOS",
                part="o",
                vendor="cisco",
                product="ios_xe" if xe else "ios",
                version=m.group(1),
                source=field,
            )
    return None


def _kernel_version(uname: str) -> Optional[str]:
    parts = (uname or "").split()
    if len(parts) >= 3 and parts[0] == "Linux":
        m = re.match(r"(\d+\.\d+(?:\.\d+)?)", parts[2])
        if m:
            return m.group(1)
    return None


def identify_components(device_info: Dict[str, Any], include_kernel: bool = False) -> List[Component]:
    """Software with a reliable version string, mapped to NVD CPE names.

    Accepts both the live assessor ``device_info`` and the stored history form
    (where the firmware string is saved as ``version``).
    """
    found: List[Component] = []

    ow = _openwrt_version(device_info)
    if ow:
        found.append(Component("openwrt", "OpenWrt", "o", "openwrt", "openwrt", ow[0], ow[1]))

    cisco = _cisco_component(device_info)
    if cisco:
        found.append(cisco)

    m = re.search(r"Dropbear\s+v?(\d{4}\.\d+)", device_info.get("dropbear_version", "") or "", re.I)
    if m:
        found.append(Component(
            "dropbear", "Dropbear SSH", "a", "dropbear_ssh_project", "dropbear_ssh",
            m.group(1), "dropbear_version",
        ))

    m = re.search(r"BusyBox\s+v?(\d+\.\d+(?:\.\d+)?)", device_info.get("busybox_version", "") or "", re.I)
    if m:
        found.append(Component(
            "busybox", "BusyBox", "a", "busybox", "busybox", m.group(1), "busybox_version",
        ))

    if include_kernel:
        kv = _kernel_version(device_info.get("uname", ""))
        if kv:
            # The kernel matches thousands of CVEs; only CRITICAL ones are useful here.
            found.append(Component(
                "linux_kernel", "Linux kernel", "o", "linux", "linux_kernel", kv, "uname",
                critical_only=True,
            ))

    return found


def kernel_available(device_info: Dict[str, Any]) -> bool:
    return _kernel_version(device_info.get("uname", "")) is not None


# --------------------------------------------------------------------------- #
# NVD client
# --------------------------------------------------------------------------- #


class NvdError(Exception):
    pass


def _parse_cve(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id or cve.get("vulnStatus") == "Rejected":
        return None

    score = None
    severity = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or primary.get("baseSeverity")
        break

    description = next(
        (d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), ""
    )
    if len(description) > 400:
        description = description[:397].rstrip() + "..."

    return {
        "id": cve_id,
        "score": score,
        "severity": (severity or "UNKNOWN").upper(),
        "published": (cve.get("published") or "")[:10],
        "description": description,
        "known_exploited": bool(cve.get("cisaExploitAdd")),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


class NvdClient:
    """Minimal NVD 2.0 client with process-wide rate limiting."""

    _lock = threading.Lock()
    _last_request = 0.0

    def __init__(
        self,
        api_key: Optional[str] = None,
        http_get: Optional[Callable[..., Any]] = None,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = 30.0,
    ):
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY") or None
        self._sleep = sleep
        self.timeout = timeout
        if http_get is None:
            import requests

            http_get = requests.get
        self._get = http_get

    def _throttle(self) -> None:
        interval = MIN_INTERVAL_WITH_KEY if self.api_key else MIN_INTERVAL_NO_KEY
        with NvdClient._lock:
            wait = NvdClient._last_request + interval - time.monotonic()
            if wait > 0:
                self._sleep(wait)
            NvdClient._last_request = time.monotonic()

    def fetch(self, component: Component) -> Dict[str, Any]:
        """Return {"total": int, "cves": [...]} for one component."""
        params: Dict[str, Any] = {
            "virtualMatchString": component.cpe,
            "resultsPerPage": NVD_PAGE_SIZE,
            "noRejected": "",
        }
        if component.critical_only:
            params["cvssV3Severity"] = "CRITICAL"
        headers = {"apiKey": self.api_key} if self.api_key else {}

        cves: List[Dict[str, Any]] = []
        total = 0
        start = 0
        while True:
            self._throttle()
            try:
                resp = self._get(
                    NVD_URL, params={**params, "startIndex": start}, headers=headers, timeout=self.timeout
                )
            except Exception as e:  # network/DNS/timeout
                raise NvdError(f"NVD request failed: {e}") from e
            status = getattr(resp, "status_code", 200)
            if status in (403, 429):
                raise NvdError("NVD rate limit reached; try again shortly or set NVD_API_KEY")
            if status >= 400:
                raise NvdError(f"NVD returned HTTP {status}")
            try:
                data = resp.json()
            except ValueError as e:
                raise NvdError("NVD returned invalid JSON") from e

            total = int(data.get("totalResults") or 0)
            batch = data.get("vulnerabilities") or []
            for item in batch:
                parsed = _parse_cve(item)
                if parsed:
                    cves.append(parsed)
            start += len(batch)
            if not batch or start >= total or start >= MAX_CVES_PER_COMPONENT:
                break

        return {"total": total, "cves": cves}


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #


def default_cache_path() -> Path:
    explicit = os.environ.get("ROUTER_SECURITY_CVE_DB")
    if explicit:
        return Path(explicit)
    history = os.environ.get("ROUTER_SECURITY_DB")
    if history:
        return Path(history).with_name("cve_cache.db")
    return Path(__file__).parent.parent.parent / "data" / "cve_cache.db"


class CveCache:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else default_cache_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS cve_lookups (
                       query TEXT PRIMARY KEY,
                       fetched_at TEXT NOT NULL,
                       total INTEGER NOT NULL,
                       cves TEXT NOT NULL
                   )"""
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path))

    def get(self, query: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT fetched_at, total, cves FROM cve_lookups WHERE query = ?", (query,)
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        return {"fetched_at": row[0], "total": row[1], "cves": json.loads(row[2])}

    def put(self, query: str, total: int, cves: List[Dict[str, Any]]) -> str:
        fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cve_lookups (query, fetched_at, total, cves) VALUES (?, ?, ?, ?)",
                    (query, fetched_at, total, json.dumps(cves)),
                )
        finally:
            conn.close()
        return fetched_at


def _is_fresh(fetched_at: str, ttl: timedelta) -> bool:
    try:
        ts = datetime.fromisoformat(fetched_at)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - ts < ttl


# --------------------------------------------------------------------------- #
# Correlation
# --------------------------------------------------------------------------- #

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


def _sort_key(c: Dict[str, Any]):
    return (not c.get("known_exploited"), -(c.get("score") or 0), c.get("id", ""))


def offline_mode() -> bool:
    return os.environ.get("ROUTER_SECURITY_OFFLINE", "").lower() in ("1", "true", "yes")


def correlate(
    components: List[Component],
    client: Optional[NvdClient] = None,
    cache: Optional[CveCache] = None,
    refresh: bool = False,
    offline: Optional[bool] = None,
    ttl: timedelta = DEFAULT_TTL,
) -> Dict[str, Any]:
    """Look up CVEs for each component and build a report.

    status: "ok" (all components answered), "partial" (some served stale or
    missing because of errors/offline), "unavailable" (nothing could be looked
    up), or "no_components" (nothing identifiable on the device).
    """
    offline = offline_mode() if offline is None else offline
    cache = cache or CveCache()
    errors: List[str] = []
    results: List[Dict[str, Any]] = []
    answered = 0

    for comp in components:
        query = comp.cpe + ("|critical" if comp.critical_only else "")
        cached = cache.get(query)
        data = None
        stale = False

        if cached and not refresh and _is_fresh(cached["fetched_at"], ttl):
            data = cached
        elif offline:
            if cached:
                data, stale = cached, True
            else:
                errors.append(f"{comp.name} {comp.version}: offline and not cached")
        else:
            try:
                client = client or NvdClient()
                fetched = client.fetch(comp)
                fetched_at = cache.put(query, fetched["total"], fetched["cves"])
                data = {"fetched_at": fetched_at, **fetched}
            except NvdError as e:
                errors.append(f"{comp.name} {comp.version}: {e}")
                if cached:
                    data, stale = cached, True

        entry: Dict[str, Any] = {
            **{k: v for k, v in asdict(comp).items()},
            "cpe": comp.cpe,
            "looked_up": data is not None,
            "stale": stale,
            "fetched_at": data["fetched_at"] if data else None,
            "total": 0,
            "critical": 0,
            "high": 0,
            "known_exploited": 0,
            "max_score": None,
            "cves": [],
        }
        if data is not None:
            answered += 1
            cves = sorted(data["cves"], key=_sort_key)
            entry["total"] = data["total"]
            entry["critical"] = sum(1 for c in cves if c["severity"] == "CRITICAL")
            entry["high"] = sum(1 for c in cves if c["severity"] == "HIGH")
            entry["known_exploited"] = sum(1 for c in cves if c.get("known_exploited"))
            scores = [c["score"] for c in cves if c.get("score") is not None]
            entry["max_score"] = max(scores) if scores else None
            entry["cves"] = cves[:TOP_CVES_RETURNED]
        results.append(entry)

    if not components:
        status = "no_components"
    elif answered == 0:
        status = "unavailable"
    elif answered < len(components) or any(r["stale"] for r in results):
        status = "partial"
    else:
        status = "ok"

    scores = [r["max_score"] for r in results if r["max_score"] is not None]
    return {
        "status": status,
        "components": results,
        "summary": {
            "total": sum(r["total"] for r in results),
            "critical": sum(r["critical"] for r in results),
            "high": sum(r["high"] for r in results),
            "known_exploited": sum(r["known_exploited"] for r in results),
            "max_score": max(scores) if scores else None,
            "unpatched_critical": any(r["critical"] for r in results),
        },
        "errors": errors,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
