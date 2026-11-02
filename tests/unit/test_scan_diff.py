"""Tests for the scan diff engine, the /api/history/diff endpoint, and WS persistence."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from assessment.scan_diff import diff_scans, finding_key, normalize_severity


def _f(fid, title, severity):
    return {"id": fid, "title": title, "severity": severity}


BASE = {
    "target": "192.168.1.1",
    "risk_score": 7.5,
    "vulnerabilities": [
        _f("SSH-001", "Password auth enabled", "Medium"),
        _f("SSH-002", "Root login permitted", "High"),
        _f("NET-004", "Telnet open", "Critical"),
    ],
}

HEAD = {
    "target": "192.168.1.1",
    "risk_score": 4.0,
    "vulnerabilities": [
        _f("SSH-001", "Password auth enabled", "Medium"),
        _f("SSH-002", "Root login permitted", "Low"),
        _f("FW-010", "Firmware out of date", "High"),
    ],
}


class TestDiffEngine:
    def test_classifies_new_resolved_persisting(self):
        diff = diff_scans(BASE, HEAD, base_id=1, head_id=2)
        assert [f["id"] for f in diff["new"]] == ["FW-010"]
        assert [f["id"] for f in diff["resolved"]] == ["NET-004"]
        assert sorted(f["id"] for f in diff["persisting"]) == ["SSH-001", "SSH-002"]
        assert diff["risk_delta"] == -3.5
        assert diff["summary"]["new"] == 1
        assert diff["summary"]["resolved"] == 1
        assert diff["summary"]["new_by_severity"]["High"] == 1
        assert diff["summary"]["resolved_by_severity"]["Critical"] == 1

    def test_reports_severity_change(self):
        diff = diff_scans(BASE, HEAD)
        changed = {f["id"]: f for f in diff["persisting"]}
        assert changed["SSH-002"]["severity_changed"] is True
        assert changed["SSH-002"]["previous_severity"] == "High"
        assert changed["SSH-002"]["severity"] == "Low"
        assert changed["SSH-001"]["severity_changed"] is False
        assert diff["summary"]["severity_changed"] == 1

    def test_identical_scans_have_no_changes(self):
        diff = diff_scans(BASE, BASE)
        assert diff["new"] == [] and diff["resolved"] == []
        assert diff["risk_delta"] == 0
        assert len(diff["persisting"]) == 3

    def test_title_fallback_when_no_check_id(self):
        # Legacy/mock records carry only a title, with upper-case severities.
        base = {"vulnerabilities": [{"title": "UPnP  Enabled", "severity": "MEDIUM"}]}
        head = {"vulnerabilities": [{"title": "upnp enabled", "severity": "HIGH"}]}
        diff = diff_scans(base, head)
        assert diff["new"] == [] and diff["resolved"] == []
        assert diff["persisting"][0]["previous_severity"] == "Medium"
        assert diff["persisting"][0]["severity"] == "High"

    def test_accepts_live_findings_key(self):
        diff = diff_scans({"findings": []}, {"findings": [_f("X-1", "x", "Low")]})
        assert [f["id"] for f in diff["new"]] == ["X-1"]

    def test_duplicate_check_keeps_most_severe(self):
        head = {"vulnerabilities": [_f("A", "a", "Low"), _f("A", "a", "Critical")]}
        diff = diff_scans({"vulnerabilities": []}, head)
        assert len(diff["new"]) == 1
        assert diff["new"][0]["severity"] == "Critical"

    def test_new_findings_sorted_by_severity(self):
        head = {"vulnerabilities": [_f("L", "l", "Low"), _f("C", "c", "Critical")]}
        diff = diff_scans({"vulnerabilities": []}, head)
        assert [f["id"] for f in diff["new"]] == ["C", "L"]

    def test_helpers(self):
        assert normalize_severity("CRITICAL") == "Critical"
        assert normalize_severity(None) == "Info"
        assert normalize_severity("bogus") == "Info"
        assert finding_key({"id": " SSH-1 "}) == ("id", "SSH-1")
        assert finding_key({"title": "A  B"}) == ("title", "a b")


def _mock_db(scans):
    db = MagicMock()
    db.get_scan_summary.side_effect = lambda sid: (
        {"target": scans[sid]["target"], "scan_timestamp": f"2026-11-0{sid}T00:00:00",
         "risk_score": scans[sid]["risk_score"]}
        if sid in scans else None
    )
    db.get_scan_by_id.side_effect = lambda sid: scans.get(sid)
    return db


@pytest.fixture
def client():
    return TestClient(app)


class TestDiffEndpoint:
    @patch("api.routes.history._get_db")
    def test_diff_success(self, mock_get_db, client):
        db = _mock_db({1: BASE, 2: HEAD})
        mock_get_db.return_value = db
        response = client.get("/api/history/diff?base=1&head=2")
        assert response.status_code == 200
        data = response.json()
        assert data["base"]["id"] == 1 and data["head"]["id"] == 2
        assert data["head"]["scan_timestamp"] == "2026-11-02T00:00:00"
        assert data["summary"]["new"] == 1
        assert data["risk_delta"] == -3.5
        db.close.assert_called_once()

    @patch("api.routes.history._get_db")
    def test_diff_missing_scan(self, mock_get_db, client):
        mock_get_db.return_value = _mock_db({1: BASE})
        response = client.get("/api/history/diff?base=1&head=99")
        assert response.status_code == 404
        assert "#99" in response.json()["detail"]

    @patch("api.routes.history._get_db")
    def test_diff_rejects_different_targets(self, mock_get_db, client):
        other = dict(HEAD, target="10.0.0.1")
        mock_get_db.return_value = _mock_db({1: BASE, 2: other})
        response = client.get("/api/history/diff?base=1&head=2")
        assert response.status_code == 400
        assert "same target" in response.json()["detail"]

    def test_diff_rejects_same_scan(self, client):
        response = client.get("/api/history/diff?base=3&head=3")
        assert response.status_code == 400

    def test_diff_requires_both_params(self, client):
        assert client.get("/api/history/diff?base=1").status_code == 422

    def test_diff_against_real_database(self, client, tmp_path):
        from database.scan_history import ScanHistoryDB

        db_path = tmp_path / "history.db"
        with ScanHistoryDB(str(db_path)) as db:
            base_id = db.save_scan(dict(BASE, risk_level="HIGH"))
            head_id = db.save_scan(dict(HEAD, risk_level="MEDIUM"))

        with patch("api.routes.history._get_db", lambda: ScanHistoryDB(str(db_path))):
            response = client.get(f"/api/history/diff?base={base_id}&head={head_id}")
        assert response.status_code == 200
        data = response.json()
        assert [f["id"] for f in data["resolved"]] == ["NET-004"]
        assert data["base"]["scan_timestamp"]  # filled from the indexed row


class TestWebSocketPersistence:
    @patch("api.routes.scan._persist_scan", return_value=42)
    @patch("api.routes.scan._run_ssh_assessment")
    def test_ws_scan_is_saved_to_history(self, mock_assess, mock_persist, client):
        mock_assess.return_value = {
            "findings": [_f("SSH-001", "Password auth enabled", "Medium")],
            "device_info": {"hostname": "router"},
            "profile": "openwrt",
        }
        with client.websocket_connect("/ws/scan") as ws:
            ws.send_json({"host": "192.168.1.1", "password": "test-placeholder-not-real"})
            message = ws.receive_json()
            while message["type"] == "progress":
                message = ws.receive_json()

        assert message["type"] == "result"
        assert message["scan_id"] == 42
        mock_persist.assert_called_once()
        assert mock_persist.call_args[0][0].target == "192.168.1.1"
