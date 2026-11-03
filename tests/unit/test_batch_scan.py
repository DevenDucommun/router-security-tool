"""Tests for batch target parsing, POST /api/targets/parse, and the /ws/batch scanner."""

import threading
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from assessment.targets import MAX_BATCH_TARGETS, TargetParseError, parse_targets


class TestParseTargets:
    def test_mixed_separators_comments_and_dedupe(self):
        text = "192.168.1.1, 192.168.1.2\n# lab gear\n\nrouter.LAN  192.168.1.1\n"
        assert parse_targets(text) == {"targets": ["192.168.1.1", "192.168.1.2", "router.lan"], "errors": []}

    def test_cidr_expands_to_usable_hosts(self):
        assert parse_targets("10.0.0.0/30")["targets"] == ["10.0.0.1", "10.0.0.2"]
        assert parse_targets("10.0.0.5/32")["targets"] == ["10.0.0.5"]

    def test_last_octet_range(self):
        assert parse_targets("192.168.1.10-12")["targets"] == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]

    def test_invalid_tokens_are_reported_not_scanned(self):
        result = parse_targets("192.168.1.300, 10.0.0.0/33, 192.168.1.20-10, bad_host!, 192.168.1.1")
        assert result["targets"] == ["192.168.1.1"]
        assert len(result["errors"]) == 4

    def test_ipv6_cidr_rejected(self):
        assert "IPv4" in parse_targets("fd00::/120")["errors"][0]

    def test_oversized_cidr_rejected_without_expanding(self):
        result = parse_targets("10.0.0.0/16")
        assert result["targets"] == [] and "max 256" in result["errors"][0]

    def test_total_cap_across_tokens(self):
        text = "\n".join(f"10.0.{i}.0/24" for i in range(2))  # 2 x 254 hosts
        with pytest.raises(TargetParseError):
            parse_targets(text)

    def test_cap_boundary(self):
        hosts = "\n".join(f"10.1.{i // 250}.{i % 250 + 1}" for i in range(MAX_BATCH_TARGETS))
        assert len(parse_targets(hosts)["targets"]) == MAX_BATCH_TARGETS

    def test_empty_input(self):
        assert parse_targets("") == {"targets": [], "errors": []}
        assert parse_targets(None) == {"targets": [], "errors": []}


@pytest.fixture
def client():
    return TestClient(app)


class TestParseEndpoint:
    def test_preview(self, client):
        data = client.post("/api/targets/parse", json={"targets": "10.0.0.0/30, nope!"}).json()
        assert data["targets"] == ["10.0.0.1", "10.0.0.2"]
        assert data["count"] == 2 and len(data["errors"]) == 1 and data["max_targets"] == 256

    def test_too_many_is_400(self, client):
        text = "10.0.0.0/24\n10.0.1.0/24"
        assert client.post("/api/targets/parse", json={"targets": text}).status_code == 400


def _assessment(host, port, username, password, progress_callback=None):
    if progress_callback:
        progress_callback(f"checking {host}")
    if host.endswith(".66"):
        raise ConnectionError(f"SSH connection to {host}:{port} failed")
    shared = {"id": "SSH-001", "title": "Root login permitted via SSH", "severity": "Medium"}
    extra = [{"id": "FW-001", "title": "No firewall", "severity": "High"}] if host.endswith(".2") else []
    return {"findings": [shared, *extra], "device_info": {"hostname": host}, "profile": None}


def _collect(ws):
    messages = []
    while True:
        message = ws.receive_json()
        messages.append(message)
        if message["type"] in ("batch_complete", "error"):
            return messages


class TestHistoryIsolation:
    """Regression: tests used to write fake scans into the real data/scan_history.db."""

    def test_unmocked_scan_persists_to_temp_db_not_repo(self, client, isolated_history_db):
        import sqlite3
        from unittest.mock import MagicMock
        from conftest import REPO_DATA_DB

        before = REPO_DATA_DB.stat().st_mtime_ns if REPO_DATA_DB.exists() else None
        conn = MagicMock()
        conn.is_connected.return_value = True
        conn.connect_ssh.return_value = True
        conn.send_command.return_value = ""
        with patch("connections.manager.ConnectionManager", return_value=conn):
            response = client.post("/api/scan", json={"host": "10.9.9.9", "password": "test-placeholder-not-real"})
        assert response.status_code == 200

        rows = sqlite3.connect(isolated_history_db).execute("select target from scans").fetchall()
        assert rows == [("10.9.9.9",)]
        after = REPO_DATA_DB.stat().st_mtime_ns if REPO_DATA_DB.exists() else None
        assert after == before


class TestBatchWebSocket:
    @patch("api.routes.scan._persist_scan")
    @patch("api.routes.scan._run_ssh_assessment", side_effect=_assessment)
    def test_batch_scans_all_targets_and_summarizes(self, _assess, persist, client):
        persist.side_effect = lambda result: {"192.168.1.1": 11, "192.168.1.2": 12}.get(result.target)
        with client.websocket_connect("/ws/batch") as ws:
            ws.send_json({
                "targets": "192.168.1.1-2, 192.168.1.66",
                "password": "test-placeholder-not-real",
                "concurrency": 2,
            })
            messages = _collect(ws)

        started = messages[0]
        assert started["type"] == "batch_started"
        assert started["targets"] == ["192.168.1.1", "192.168.1.2", "192.168.1.66"]
        assert started["concurrency"] == 2

        results = {m["target"]: m for m in messages if m["type"] == "target_result"}
        errors = {m["target"]: m for m in messages if m["type"] == "target_error"}
        assert set(results) == {"192.168.1.1", "192.168.1.2"}
        assert results["192.168.1.2"]["scan_id"] == 12
        assert results["192.168.1.1"]["data"]["profile"] == "generic"
        assert "failed" in errors["192.168.1.66"]["message"]
        assert any(m["type"] == "target_progress" and m["message"] == "checking 192.168.1.1" for m in messages)

        summary = messages[-1]["summary"]
        assert summary["total"] == 3 and summary["succeeded"] == 2 and summary["failed"] == 1
        assert summary["highest_risk"][0]["target"] == "192.168.1.2"
        common = {f["id"]: f["devices"] for f in summary["common_findings"]}
        assert common == {"SSH-001": 2, "FW-001": 1}
        assert persist.call_count == 2  # failed device is not saved

    @patch("api.routes.scan._persist_scan", return_value=None)
    def test_concurrency_limit_is_enforced(self, _persist, client):
        lock = threading.Lock()
        state = {"running": 0, "peak": 0}

        def slow(host, port, username, password, progress_callback=None):
            with lock:
                state["running"] += 1
                state["peak"] = max(state["peak"], state["running"])
            time.sleep(0.05)
            with lock:
                state["running"] -= 1
            return {"findings": [], "device_info": {}, "profile": None}

        with patch("api.routes.scan._run_ssh_assessment", side_effect=slow):
            with client.websocket_connect("/ws/batch") as ws:
                ws.send_json({"targets": "10.0.0.1-6", "password": "test-placeholder-not-real", "concurrency": 2})
                messages = _collect(ws)

        assert messages[-1]["summary"]["succeeded"] == 6
        assert state["peak"] == 2

    def test_concurrency_is_clamped(self, client):
        with patch("api.routes.scan._run_ssh_assessment", side_effect=_assessment), \
                patch("api.routes.scan._persist_scan", return_value=None):
            with client.websocket_connect("/ws/batch") as ws:
                ws.send_json({"targets": "10.0.0.1", "password": "test-placeholder-not-real", "concurrency": 99})
                assert ws.receive_json()["concurrency"] == 8

    @pytest.mark.parametrize("payload,needle", [
        ({"targets": "10.0.0.1"}, "password"),
        ({"targets": "", "password": "x"}, "no targets"),
        ({"targets": "10.0.0.1, bogus!", "password": "x"}, "not an IP"),
        ({"targets": "10.0.0.0/24 10.0.1.0/24", "password": "x"}, "too many"),
    ])
    def test_rejects_bad_requests_before_scanning(self, payload, needle, client):
        with patch.dict("os.environ", {}, clear=True), \
                patch("api.routes.scan._run_ssh_assessment") as assess:
            with client.websocket_connect("/ws/batch") as ws:
                ws.send_json(payload)
                message = ws.receive_json()
        assert message["type"] == "error" and needle in message["message"]
        assess.assert_not_called()
