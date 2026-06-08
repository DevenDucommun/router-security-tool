"""
Unit tests for FastAPI endpoints.
Uses httpx TestClient with mocked assessment engine.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture
def client():
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"


class TestScanEndpoint:
    @patch("api.routes.scan._run_ssh_assessment")
    def test_scan_success(self, mock_assess, client):
        mock_assess.return_value = {
            "findings": [
                {
                    "id": "SSH-001",
                    "title": "Password auth enabled",
                    "severity": "Medium",
                    "category": "ssh",
                    "description": "SSH allows password authentication",
                    "evidence": "PasswordAuthentication yes",
                    "remediation": "Disable password auth",
                }
            ],
            "device_info": {
                "hostname": "router",
                "uname": "Linux router 5.15",
                "firmware_version": "1.0.0",
                "uptime": "3 days",
                "os_release": "OpenWrt 23.05",
            },
            "severity_summary": {"Medium": 1},
            "profile": "openwrt",
        }

        response = client.post("/api/scan", json={
            "host": "192.168.1.1",
            "username": "root",
            "password": "test-placeholder-not-real",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["target"] == "192.168.1.1"
        assert data["profile"] == "openwrt"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["id"] == "SSH-001"
        assert data["findings"][0]["severity"] == "Medium"
        assert data["risk_score"] > 0
        assert data["scan_duration"] >= 0

    def test_scan_missing_password(self, client):
        with patch.dict("os.environ", {}, clear=True):
            response = client.post("/api/scan", json={
                "host": "192.168.1.1",
                "username": "root",
            })
            assert response.status_code == 400
            assert "Password required" in response.json()["detail"]

    @patch("api.routes.scan._run_ssh_assessment")
    def test_scan_connection_failure(self, mock_assess, client):
        mock_assess.side_effect = ConnectionError("SSH connection to 10.0.0.1:22 failed")

        response = client.post("/api/scan", json={
            "host": "10.0.0.1",
            "username": "root",
            "password": "placeholder-invalid",
        })

        assert response.status_code == 502
        assert "failed" in response.json()["detail"]

    @patch("api.routes.scan._run_ssh_assessment")
    def test_scan_internal_error(self, mock_assess, client):
        mock_assess.side_effect = RuntimeError("Unexpected failure")

        response = client.post("/api/scan", json={
            "host": "192.168.1.1",
            "username": "root",
            "password": "pass",
        })

        assert response.status_code == 500

    @patch("api.routes.scan._run_ssh_assessment")
    def test_scan_with_env_password(self, mock_assess, client):
        mock_assess.return_value = {
            "findings": [],
            "device_info": {},
            "severity_summary": {},
            "profile": "generic",
        }

        with patch.dict("os.environ", {"ROUTER_PASS": "env-placeholder-not-real"}):
            response = client.post("/api/scan", json={
                "host": "192.168.1.1",
                "username": "root",
            })

        assert response.status_code == 200
        mock_assess.assert_called_once_with(
            "192.168.1.1", 22, "root", "env-placeholder-not-real"
        )

    @patch("api.routes.scan._run_ssh_assessment")
    def test_scan_risk_score_calculation(self, mock_assess, client):
        mock_assess.return_value = {
            "findings": [
                {"id": "F1", "title": "Critical finding", "severity": "Critical",
                 "category": "", "description": "", "evidence": "", "remediation": ""},
                {"id": "F2", "title": "High finding", "severity": "High",
                 "category": "", "description": "", "evidence": "", "remediation": ""},
                {"id": "F3", "title": "Medium finding", "severity": "Medium",
                 "category": "", "description": "", "evidence": "", "remediation": ""},
            ],
            "device_info": {},
            "severity_summary": {"Critical": 1, "High": 1, "Medium": 1},
            "profile": "generic",
        }

        response = client.post("/api/scan", json={
            "host": "192.168.1.1",
            "password": "pass",
        })

        data = response.json()
        assert data["risk_score"] > 0
        assert data["risk_score"] <= 10.0


class TestDevicesEndpoint:
    @patch("api.routes.devices._discover_devices")
    def test_discover_devices(self, mock_discover, client):
        mock_discover.return_value = [
            {"ip": "192.168.1.1", "port": 22, "type": "network",
             "description": "Router SSH", "device": "", "likely_router": True},
            {"ip": "192.168.1.2", "port": 22, "type": "network",
             "description": "Unknown device", "device": "", "likely_router": False},
        ]

        response = client.get("/api/devices")
        assert response.status_code == 200
        data = response.json()
        assert len(data["devices"]) == 2
        assert data["devices"][0]["ip"] == "192.168.1.1"
        assert data["devices"][0]["likely_router"] is True

    @patch("api.routes.devices._discover_devices")
    def test_discover_no_devices(self, mock_discover, client):
        mock_discover.return_value = []

        response = client.get("/api/devices")
        assert response.status_code == 200
        assert response.json()["devices"] == []


class TestHistoryEndpoint:
    @patch("api.routes.history._get_db")
    def test_get_history(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.get_all_scans.return_value = [
            {
                "id": 1,
                "target": "192.168.1.1",
                "scan_timestamp": "2024-01-15T10:30:00",
                "risk_score": 6.5,
                "vulnerability_count": 4,
                "risk_level": "MEDIUM",
                "device_vendor": "linksys",
                "device_model": "WRT3200ACM",
            }
        ]
        mock_get_db.return_value = mock_db

        response = client.get("/api/history")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["target"] == "192.168.1.1"
        assert data[0]["risk_score"] == 6.5

    @patch("api.routes.history._get_db")
    def test_get_history_with_target_filter(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.get_all_scans.return_value = [
            {"id": 1, "target": "192.168.1.1", "scan_timestamp": "2024-01-15T10:30:00",
             "risk_score": 6.5, "vulnerability_count": 4, "risk_level": "MEDIUM",
             "device_vendor": "", "device_model": ""},
            {"id": 2, "target": "10.0.0.1", "scan_timestamp": "2024-01-16T10:30:00",
             "risk_score": 3.0, "vulnerability_count": 1, "risk_level": "LOW",
             "device_vendor": "", "device_model": ""},
        ]
        mock_get_db.return_value = mock_db

        response = client.get("/api/history?target=192.168.1.1")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["target"] == "192.168.1.1"

    @patch("api.routes.history._get_db")
    def test_get_history_stats(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.get_statistics.return_value = {
            "total_scans": 10,
            "unique_targets": 3,
            "total_vulnerabilities": 42,
            "avg_risk_score": 5.5,
            "risk_distribution": {"HIGH": 3, "MEDIUM": 5, "LOW": 2},
        }
        mock_get_db.return_value = mock_db

        response = client.get("/api/history/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_scans"] == 10
        assert data["avg_risk_score"] == 5.5
        assert data["risk_distribution"]["HIGH"] == 3

    @patch("api.routes.history._get_db")
    def test_delete_scan(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.delete_scan.return_value = True
        mock_get_db.return_value = mock_db

        response = client.delete("/api/history/1")
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

    @patch("api.routes.history._get_db")
    def test_delete_scan_not_found(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.delete_scan.return_value = False
        mock_get_db.return_value = mock_db

        response = client.delete("/api/history/999")
        assert response.status_code == 404


class TestExportEndpoint:
    @patch("api.routes.export._get_db")
    def test_export_invalid_format(self, mock_get_db, client):
        response = client.post("/api/export/xml")
        assert response.status_code == 400

    @patch("api.routes.export._get_db")
    def test_export_no_scans(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.get_all_scans.return_value = []
        mock_get_db.return_value = mock_db

        response = client.post("/api/export/json")
        assert response.status_code == 404


class TestFilesystemEndpoint:
    @patch("api.routes.filesystem._explore_filesystem")
    def test_filesystem_success(self, mock_explore, client):
        mock_explore.return_value = {
            "file_structure": {"/etc": [{"name": "passwd", "permissions": "-rw-r--r--"}]},
            "interesting_files": [{"path": "/etc/shadow", "reason": "password file"}],
            "security_findings": [{"severity": "medium", "description": "World-readable shadow"}],
        }

        response = client.post("/api/filesystem", json={
            "host": "192.168.1.1",
            "username": "root",
            "password": "pass",
        })

        assert response.status_code == 200
        data = response.json()
        assert "/etc" in data["file_structure"]
        assert len(data["interesting_files"]) == 1
        assert len(data["security_findings"]) == 1

    def test_filesystem_missing_password(self, client):
        with patch.dict("os.environ", {}, clear=True):
            response = client.post("/api/filesystem", json={
                "host": "192.168.1.1",
                "username": "root",
            })
            assert response.status_code == 400

    @patch("api.routes.filesystem._explore_filesystem")
    def test_filesystem_connection_failure(self, mock_explore, client):
        mock_explore.side_effect = ConnectionError("SSH failed")

        response = client.post("/api/filesystem", json={
            "host": "192.168.1.1",
            "password": "pass",
        })

        assert response.status_code == 502
