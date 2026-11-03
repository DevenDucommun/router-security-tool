"""CVE correlation: component identification, NVD client, cache, and the API."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from assessment import cve_correlation as cc

OPENWRT_OS_RELEASE = 'NAME="OpenWrt"\nVERSION="21.02.0"\nID="openwrt"\nVERSION_ID="21.02.0"\n'
OPENWRT_RELEASE_FILE = "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='19.07.7'\nDISTRIB_REVISION='r11306'\n"


def nvd_item(cve_id, score=None, severity=None, kev=False, status="Analyzed", metric="cvssMetricV31"):
    cve = {
        "id": cve_id,
        "vulnStatus": status,
        "published": "2024-01-02T03:04:05.000",
        "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": f"desc {cve_id}"}],
        "metrics": {},
    }
    if score is not None:
        cve["metrics"][metric] = [
            {"type": "Secondary", "cvssData": {"baseScore": 1.0, "baseSeverity": "LOW"}},
            {"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": severity}},
        ]
    if kev:
        cve["cisaExploitAdd"] = "2024-02-01"
    return {"cve": cve}


class FakeResp:
    def __init__(self, data=None, status=200):
        self._data = data
        self.status_code = status

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


def client_returning(*responses):
    get = MagicMock(side_effect=list(responses))
    return cc.NvdClient(api_key="k", http_get=get, sleep=lambda s: None), get


# --------------------------------------------------------------------------- #
# identify_components
# --------------------------------------------------------------------------- #


class TestIdentifyComponents:
    def test_openwrt_from_os_release(self):
        comps = cc.identify_components({"os_release": OPENWRT_OS_RELEASE})
        assert [(c.key, c.version, c.source) for c in comps] == [("openwrt", "21.02.0", "os_release")]
        assert comps[0].cpe == "cpe:2.3:o:openwrt:openwrt:21.02.0"

    def test_openwrt_from_stored_history_version_field(self):
        # Scans saved before v1.2 keep the /etc/openwrt_release text as "version".
        comps = cc.identify_components({"vendor": "openwrt", "version": OPENWRT_RELEASE_FILE})
        assert [(c.key, c.version) for c in comps] == [("openwrt", "19.07.7")]

    def test_openwrt_snapshot_is_skipped(self):
        assert cc.identify_components({"os_release": 'ID="openwrt"\nVERSION_ID="snapshot"\n'}) == []

    def test_non_openwrt_os_release_is_ignored(self):
        assert cc.identify_components({"os_release": 'ID="debian"\nVERSION_ID="12"\n'}) == []

    def test_cisco_ios_version_is_cpe_escaped(self):
        uname = "Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.2(4)M7, RELEASE SOFTWARE"
        (c,) = cc.identify_components({"uname": uname})
        assert (c.key, c.version) == ("cisco_ios", "15.2(4)M7")
        assert c.cpe == r"cpe:2.3:o:cisco:ios:15.2\(4\)m7"

    def test_cisco_ios_xe(self):
        text = "Cisco IOS XE Software, Version 17.03.04a\nCisco IOS Software [Amsterdam], Version 17.3.4a"
        (c,) = cc.identify_components({"os_release": text})
        assert c.product == "ios_xe"

    def test_dropbear_and_busybox(self):
        comps = cc.identify_components({
            "dropbear_version": "Dropbear v2022.82",
            "busybox_version": "BusyBox v1.36.1 (2023-11-07 18:53:09 UTC) multi-call binary.",
        })
        assert [(c.key, c.version) for c in comps] == [("dropbear", "2022.82"), ("busybox", "1.36.1")]
        assert comps[0].cpe == "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2022.82"

    def test_kernel_only_when_requested_and_critical_only(self):
        info = {"uname": "Linux OpenWrt 5.15.150 #0 SMP Thu Mar 7 2024 aarch64 GNU/Linux"}
        assert cc.identify_components(info) == []
        assert cc.kernel_available(info)
        (k,) = cc.identify_components(info, include_kernel=True)
        assert (k.version, k.critical_only) == ("5.15.150", True)

    def test_kernel_suffix_stripped(self):
        (k,) = cc.identify_components({"uname": "Linux pi 6.1.21-v8+ #1642 SMP"}, include_kernel=True)
        assert k.version == "6.1.21"

    def test_garbage_and_empty(self):
        assert cc.identify_components({}) == []
        assert cc.identify_components({"uname": "", "os_release": None, "dropbear_version": "nope"}) == []
        assert not cc.kernel_available({"uname": "Cisco IOS"})


def test_cpe_escape():
    assert cc.cpe_escape("15.2(4)M7") == r"15.2\(4\)m7"
    assert cc.cpe_escape("a b:c*") == r"a\ b\:c\*"
    assert cc.cpe_escape("1.0_rc-2") == "1.0_rc-2"


# --------------------------------------------------------------------------- #
# NvdClient
# --------------------------------------------------------------------------- #

OPENWRT = cc.Component("openwrt", "OpenWrt", "o", "openwrt", "openwrt", "21.02.0", "os_release")


class TestNvdClient:
    def test_parses_and_uses_primary_metric(self):
        client, get = client_returning(FakeResp({
            "totalResults": 3,
            "vulnerabilities": [
                nvd_item("CVE-1", 9.8, "CRITICAL", kev=True),
                nvd_item("CVE-2", 5.0, "MEDIUM", metric="cvssMetricV2"),
                nvd_item("CVE-3", status="Rejected"),
            ],
        }))
        out = client.fetch(OPENWRT)
        assert out["total"] == 3
        assert [c["id"] for c in out["cves"]] == ["CVE-1", "CVE-2"]  # rejected dropped
        c1 = out["cves"][0]
        assert (c1["score"], c1["severity"], c1["known_exploited"]) == (9.8, "CRITICAL", True)
        assert c1["description"] == "desc CVE-1"
        assert c1["published"] == "2024-01-02"
        assert c1["url"] == "https://nvd.nist.gov/vuln/detail/CVE-1"
        params = get.call_args.kwargs["params"]
        assert params["virtualMatchString"] == "cpe:2.3:o:openwrt:openwrt:21.02.0"
        assert "cvssV3Severity" not in params
        assert get.call_args.kwargs["headers"] == {"apiKey": "k"}

    def test_unscored_cve(self):
        client, _ = client_returning(FakeResp({"totalResults": 1, "vulnerabilities": [nvd_item("CVE-9")]}))
        (c,) = client.fetch(OPENWRT)["cves"]
        assert (c["score"], c["severity"]) == (None, "UNKNOWN")

    def test_pages_until_total(self):
        page1 = FakeResp({"totalResults": 3, "vulnerabilities": [nvd_item("A", 1, "LOW"), nvd_item("B", 1, "LOW")]})
        page2 = FakeResp({"totalResults": 3, "vulnerabilities": [nvd_item("C", 1, "LOW")]})
        client, get = client_returning(page1, page2)
        assert [c["id"] for c in client.fetch(OPENWRT)["cves"]] == ["A", "B", "C"]
        assert [call.kwargs["params"]["startIndex"] for call in get.call_args_list] == [0, 2]

    def test_critical_only_filter(self):
        kernel = cc.Component("linux_kernel", "Linux kernel", "o", "linux", "linux_kernel", "5.4.1", "uname", True)
        client, get = client_returning(FakeResp({"totalResults": 0, "vulnerabilities": []}))
        client.fetch(kernel)
        assert get.call_args.kwargs["params"]["cvssV3Severity"] == "CRITICAL"

    @pytest.mark.parametrize("status", [403, 429])
    def test_rate_limit(self, status):
        client, _ = client_returning(FakeResp({}, status=status))
        with pytest.raises(cc.NvdError, match="rate limit"):
            client.fetch(OPENWRT)

    def test_http_error_and_bad_json_and_network(self):
        client, _ = client_returning(FakeResp({}, status=503))
        with pytest.raises(cc.NvdError, match="503"):
            client.fetch(OPENWRT)
        client, _ = client_returning(FakeResp(ValueError("x")))
        with pytest.raises(cc.NvdError, match="invalid JSON"):
            client.fetch(OPENWRT)
        client, _ = client_returning(ConnectionError("dns"))
        with pytest.raises(cc.NvdError, match="request failed"):
            client.fetch(OPENWRT)

    def test_throttles_between_requests_without_key(self, monkeypatch):
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        sleeps = []
        get = MagicMock(return_value=FakeResp({"totalResults": 0, "vulnerabilities": []}))
        client = cc.NvdClient(http_get=get, sleep=sleeps.append)
        cc.NvdClient._last_request = 0.0
        client.fetch(OPENWRT)
        client.fetch(OPENWRT)
        assert sleeps and sleeps[-1] > cc.MIN_INTERVAL_NO_KEY - 1
        assert get.call_args.kwargs["headers"] == {}


# --------------------------------------------------------------------------- #
# correlate + cache
# --------------------------------------------------------------------------- #


@pytest.fixture
def cache(tmp_path):
    return cc.CveCache(tmp_path / "cve.db")


class FakeClient:
    def __init__(self, result=None, error=None):
        self.result = result or {"total": 0, "cves": []}
        self.error = error
        self.calls = []

    def fetch(self, comp):
        self.calls.append(comp.key)
        if self.error:
            raise cc.NvdError(self.error)
        return self.result


SAMPLE = {
    "total": 3,
    "cves": [
        {"id": "CVE-LOW", "score": 3.1, "severity": "LOW", "known_exploited": False},
        {"id": "CVE-CRIT", "score": 9.8, "severity": "CRITICAL", "known_exploited": False},
        {"id": "CVE-KEV", "score": 7.5, "severity": "HIGH", "known_exploited": True},
    ],
}


class TestCorrelate:
    def test_summary_and_ordering(self, cache):
        report = cc.correlate([OPENWRT], client=FakeClient(SAMPLE), cache=cache, offline=False)
        assert report["status"] == "ok"
        (comp,) = report["components"]
        # Known-exploited first, then by score.
        assert [c["id"] for c in comp["cves"]] == ["CVE-KEV", "CVE-CRIT", "CVE-LOW"]
        assert (comp["total"], comp["critical"], comp["high"], comp["known_exploited"]) == (3, 1, 1, 1)
        assert comp["max_score"] == 9.8
        assert report["summary"]["unpatched_critical"] is True
        assert report["summary"]["total"] == 3

    def test_cache_hit_skips_network(self, cache):
        first = FakeClient(SAMPLE)
        cc.correlate([OPENWRT], client=first, cache=cache, offline=False)
        second = FakeClient(error="should not be called")
        report = cc.correlate([OPENWRT], client=second, cache=cache, offline=False)
        assert second.calls == [] and report["status"] == "ok"
        assert report["components"][0]["total"] == 3

    def test_refresh_bypasses_cache(self, cache):
        cc.correlate([OPENWRT], client=FakeClient(SAMPLE), cache=cache, offline=False)
        again = FakeClient({"total": 0, "cves": []})
        report = cc.correlate([OPENWRT], client=again, cache=cache, refresh=True, offline=False)
        assert again.calls == ["openwrt"] and report["components"][0]["total"] == 0

    def test_expired_cache_refetches(self, cache):
        cc.correlate([OPENWRT], client=FakeClient(SAMPLE), cache=cache, offline=False)
        again = FakeClient(SAMPLE)
        cc.correlate([OPENWRT], client=again, cache=cache, offline=False, ttl=timedelta(seconds=-1))
        assert again.calls == ["openwrt"]

    def test_error_falls_back_to_stale_cache(self, cache):
        cc.correlate([OPENWRT], client=FakeClient(SAMPLE), cache=cache, offline=False)
        report = cc.correlate(
            [OPENWRT], client=FakeClient(error="NVD down"), cache=cache, offline=False, ttl=timedelta(seconds=-1)
        )
        assert report["status"] == "partial"
        assert report["components"][0]["stale"] is True
        assert report["components"][0]["total"] == 3
        assert "NVD down" in report["errors"][0]

    def test_error_without_cache_is_unavailable_not_exception(self, cache):
        report = cc.correlate([OPENWRT], client=FakeClient(error="NVD down"), cache=cache, offline=False)
        assert report["status"] == "unavailable"
        assert report["components"][0]["looked_up"] is False
        assert report["summary"]["unpatched_critical"] is False

    def test_offline_never_calls_client(self, cache):
        client = FakeClient(SAMPLE)
        report = cc.correlate([OPENWRT], client=client, cache=cache, offline=True)
        assert client.calls == [] and report["status"] == "unavailable"
        assert "offline" in report["errors"][0]

    def test_offline_env(self, cache, monkeypatch):
        monkeypatch.setenv("ROUTER_SECURITY_OFFLINE", "1")
        client = FakeClient(SAMPLE)
        cc.correlate([OPENWRT], client=client, cache=cache)
        assert client.calls == []

    def test_partial_when_one_component_fails(self, cache):
        class Mixed(FakeClient):
            def fetch(self, comp):
                if comp.key == "busybox":
                    raise cc.NvdError("boom")
                return SAMPLE

        busybox = cc.Component("busybox", "BusyBox", "a", "busybox", "busybox", "1.36.1", "busybox_version")
        report = cc.correlate([OPENWRT, busybox], client=Mixed(), cache=cache, offline=False)
        assert report["status"] == "partial"
        assert [c["looked_up"] for c in report["components"]] == [True, False]

    def test_no_components(self, cache):
        assert cc.correlate([], client=FakeClient(), cache=cache, offline=False)["status"] == "no_components"

    def test_top_n_cap(self, cache):
        many = {"total": 80, "cves": [
            {"id": f"CVE-{i}", "score": float(i % 10), "severity": "LOW", "known_exploited": False}
            for i in range(80)
        ]}
        comp = cc.correlate([OPENWRT], client=FakeClient(many), cache=cache, offline=False)["components"][0]
        assert len(comp["cves"]) == cc.TOP_CVES_RETURNED and comp["total"] == 80

    def test_cache_naive_timestamp_treated_as_utc(self):
        naive = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(tzinfo=None).isoformat()
        assert cc._is_fresh(naive, timedelta(hours=1))
        assert not cc._is_fresh("garbage", timedelta(hours=1))


def test_cache_path_follows_history_db(tmp_path, monkeypatch):
    monkeypatch.delenv("ROUTER_SECURITY_CVE_DB", raising=False)
    monkeypatch.setenv("ROUTER_SECURITY_DB", str(tmp_path / "h" / "scan_history.db"))
    assert cc.default_cache_path() == tmp_path / "h" / "cve_cache.db"
    monkeypatch.setenv("ROUTER_SECURITY_CVE_DB", str(tmp_path / "x.db"))
    assert cc.default_cache_path() == tmp_path / "x.db"


# --------------------------------------------------------------------------- #
# Assessor + API
# --------------------------------------------------------------------------- #


def test_assessor_records_component_versions():
    from assessment.ssh_assessor import SSHAssessor

    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "dropbear -V 2>&1 | head -n 1": "Dropbear v2022.82",
        "busybox 2>&1 | head -n 1": "BusyBox v1.36.1 (2023) multi-call binary.",
    }.get(cmd, "")
    info = SSHAssessor(conn)._gather_device_info()
    assert info["dropbear_version"] == "Dropbear v2022.82"
    assert info["busybox_version"].startswith("BusyBox v1.36.1")


def test_assessor_ignores_shell_errors_for_missing_tools():
    from assessment.ssh_assessor import SSHAssessor

    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "dropbear -V 2>&1 | head -n 1": "sh: dropbear: not found",
        "busybox 2>&1 | head -n 1": "sh: busybox: not found",
    }.get(cmd, "")
    info = SSHAssessor(conn)._gather_device_info()
    assert "busybox_version" not in info
    assert "dropbear_version" not in info  # "dropbear" in the error text is not a version
    assert cc.identify_components(info) == []


@pytest.fixture
def api_client():
    from api.main import app

    return TestClient(app)


def _save_scan(device_info):
    from database.scan_history import ScanHistoryDB

    with ScanHistoryDB() as db:
        return db.save_scan({
            "target": "192.168.1.1",
            "device_info": device_info,
            "risk_score": 3.0,
            "risk_level": "LOW",
            "scan_duration": 1.0,
            "vulnerabilities": [],
        })


class TestCveEndpoint:
    def test_404(self, api_client):
        assert api_client.get("/api/history/999999/cves").status_code == 404

    def test_report_for_saved_scan(self, api_client, monkeypatch):
        scan_id = _save_scan({
            "vendor": "openwrt", "product": "router", "version": OPENWRT_RELEASE_FILE,
            "uname": "Linux OpenWrt 5.4.143 #0 SMP mips GNU/Linux",
            "dropbear_version": "Dropbear v2020.81",
        })
        seen = []
        real_correlate = cc.correlate

        def fake_correlate(components, refresh=False, **kw):
            seen.append(([c.key for c in components], refresh))
            return real_correlate(components, client=FakeClient(SAMPLE), offline=False, refresh=refresh)

        monkeypatch.setattr(cc, "correlate", fake_correlate)
        body = api_client.get(f"/api/history/{scan_id}/cves").json()
        assert seen[-1] == (["openwrt", "dropbear"], False)
        assert body["scan_id"] == scan_id and body["target"] == "192.168.1.1"
        assert body["status"] == "ok" and body["kernel_available"] is True and body["kernel_included"] is False
        assert body["summary"]["unpatched_critical"] is True
        assert body["components"][0]["cves"][0]["id"] == "CVE-KEV"

        api_client.get(f"/api/history/{scan_id}/cves?kernel=true&refresh=true")
        assert seen[-1] == (["openwrt", "dropbear", "linux_kernel"], True)

    def test_scan_without_versions(self, api_client, monkeypatch):
        monkeypatch.setenv("ROUTER_SECURITY_OFFLINE", "1")
        scan_id = _save_scan({"vendor": "generic", "product": "box", "version": ""})
        body = api_client.get(f"/api/history/{scan_id}/cves").json()
        assert body["status"] == "no_components" and body["components"] == []

    def test_cache_db_is_isolated_from_repo(self, monkeypatch):
        from conftest import REPO_DATA_DB

        assert cc.default_cache_path() != REPO_DATA_DB.with_name("cve_cache.db")
