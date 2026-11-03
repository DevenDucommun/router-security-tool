"""Tests for remediation verification: check registries, partial runs, and POST /api/scan/verify."""

import inspect
import re
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from assessment.profiles.base import finding_family
from assessment.profiles.cisco import CiscoIOSProfile
from assessment.profiles.linksys import LinksysProfile
from assessment.profiles.openwrt import OpenWrtProfile
from assessment.ssh_assessor import SSHAssessor

ID_PATTERN = re.compile(r'"([A-Z]+(?:-[A-Z]+)*-\d+[A-Z]?)"')
REGISTRIES = [
    (SSHAssessor, SSHAssessor.GENERIC_CHECKS),
    (OpenWrtProfile, OpenWrtProfile.CHECKS),
    (LinksysProfile, LinksysProfile.CHECKS),
    (CiscoIOSProfile, CiscoIOSProfile.CHECKS),
]


class TestCheckRegistries:
    """Guard against drift: verification is only correct if the tables match the code."""

    @pytest.mark.parametrize("cls,checks", REGISTRIES, ids=lambda x: getattr(x, "__name__", ""))
    def test_every_emitted_id_is_declared_by_its_method(self, cls, checks):
        for _, method_name, families in checks:
            source = inspect.getsource(getattr(cls, method_name))
            ids = ID_PATTERN.findall(source)
            assert ids, f"{cls.__name__}.{method_name} emits no finding IDs"
            for check_id in ids:
                assert finding_family(check_id) in families, (
                    f"{cls.__name__}.{method_name} emits {check_id} but declares {families}"
                )

    @pytest.mark.parametrize("cls,checks", REGISTRIES, ids=lambda x: getattr(x, "__name__", ""))
    def test_every_check_method_is_registered(self, cls, checks):
        registered = {method_name for _, method_name, _ in checks}
        defined = {name for name, _ in inspect.getmembers(cls, inspect.isfunction) if name.startswith("_check_")}
        assert defined == registered

    def test_families_do_not_overlap_between_registries(self):
        seen = {}
        for cls, checks in REGISTRIES:
            for _, method_name, families in checks:
                for family in families:
                    assert family not in seen, f"{family} declared by {seen.get(family)} and {cls.__name__}"
                    seen[family] = f"{cls.__name__}.{method_name}"

    def test_finding_family(self):
        assert finding_family("OWRT-FW-002") == "OWRT-FW"
        assert finding_family("SSH-001") == "SSH"
        assert finding_family("CISCO-AUTH-003") == "CISCO-AUTH"
        assert finding_family("NOSUFFIX") == "NOSUFFIX"


def _connection(responses):
    conn = MagicMock()
    conn.is_connected.return_value = True
    calls = []

    def send(cmd):
        calls.append(cmd)
        return responses.get(cmd, "")

    conn.send_command.side_effect = send
    return conn, calls


SSHD = "cat /etc/ssh/sshd_config 2>/dev/null"


class TestRunVerification:
    def test_still_failing_and_resolved(self):
        conn, _ = _connection({SSHD: "PermitRootLogin yes\nMaxAuthTries 3\n"})
        results = SSHAssessor(conn).run_verification(["SSH-001", "SSH-002"])
        assert results["verification"] == {"SSH-001": "still_failing", "SSH-002": "resolved"}
        assert results["families_run"] == ["SSH"]

    def test_only_requested_checks_run(self):
        conn, calls = _connection({SSHD: "MaxAuthTries 3\n"})
        SSHAssessor(conn).run_verification(["SSH-001"])
        # Device info gathering plus the SSH check only: no firewall, shadow, ps, etc.
        assert not any("iptables" in c or "/etc/shadow" in c or c.startswith("ps") for c in calls)
        assert SSHD in calls

    def test_full_assessment_still_runs_everything(self):
        conn, calls = _connection({})
        results = SSHAssessor(conn).run_assessment()
        assert {"SSH", "CRED", "NET", "PERM", "FW", "FILE", "PROC", "HARD"} <= set(results["families_run"])
        assert "verification" not in results

    def test_unknown_family_is_reported_not_resolved(self):
        conn, _ = _connection({SSHD: "MaxAuthTries 3\n"})
        # Generic device: no profile matches, so OWRT-* checks cannot run here.
        results = SSHAssessor(conn).run_verification(["OWRT-FW-002", "BOGUS-1"])
        assert results["verification"] == {"OWRT-FW-002": "unknown", "BOGUS-1": "unknown"}
        assert results["findings"] == []

    def test_profile_subset_runs_only_matching_method(self):
        openwrt = {
            "cat /etc/os-release 2>/dev/null || cat /etc/version 2>/dev/null": 'NAME="OpenWrt"',
            "uci show firewall 2>/dev/null": "",  # no firewall config -> OWRT-FW-001
        }
        conn, calls = _connection(openwrt)
        with patch.object(OpenWrtProfile, "_check_wireless_config") as wireless:
            results = SSHAssessor(conn).run_verification(["OWRT-FW-001"])
        wireless.assert_not_called()
        assert results["profile"] == "openwrt"
        assert results["verification"] == {"OWRT-FW-001": "still_failing"}
        assert results["families_run"] == ["OWRT-FW"]

    def test_duplicate_and_blank_ids_are_ignored(self):
        conn, _ = _connection({SSHD: "PermitRootLogin yes\n"})
        results = SSHAssessor(conn).run_verification(["SSH-001", " SSH-001 ", ""])
        assert results["verification"] == {"SSH-001": "still_failing"}

    def test_requires_connection(self):
        conn = MagicMock()
        conn.is_connected.return_value = False
        with pytest.raises(ConnectionError):
            SSHAssessor(conn).run_verification(["SSH-001"])


@pytest.fixture
def client():
    return TestClient(app)


def _verify_results(statuses, findings):
    return {
        "device_info": {},
        "findings": findings,
        "severity_summary": {},
        "profile": None,
        "families_run": ["SSH"],
        "verification": statuses,
    }


class TestGenericDeviceScan:
    """Regression: a device matching no vendor profile used to crash POST /api/scan with a 500."""

    def test_scan_of_generic_device_succeeds(self, client):
        conn, _ = _connection({SSHD: "PermitRootLogin yes\n"})
        with patch("connections.manager.ConnectionManager", return_value=conn):
            conn.connect_ssh.return_value = True
            response = client.post("/api/scan", json={
                "host": "10.0.0.9", "password": "test-placeholder-not-real",
            })
        assert response.status_code == 200
        data = response.json()
        assert data["profile"] == "generic"
        assert any(f["id"] == "SSH-001" for f in data["findings"])

    def test_verify_on_generic_device_succeeds(self, client):
        conn, _ = _connection({SSHD: "MaxAuthTries 3\n"})
        with patch("connections.manager.ConnectionManager", return_value=conn):
            conn.connect_ssh.return_value = True
            response = client.post("/api/scan/verify", json={
                "host": "10.0.0.9", "password": "test-placeholder-not-real", "check_ids": ["SSH-001"],
            })
        assert response.status_code == 200
        assert response.json()["results"] == [{"id": "SSH-001", "status": "resolved", "title": ""}]


class TestVerifyEndpoint:
    @patch("api.routes.scan._run_ssh_verification")
    def test_verify_success(self, mock_verify, client):
        mock_verify.return_value = _verify_results(
            {"SSH-001": "still_failing", "SSH-002": "resolved"},
            [{"id": "SSH-001", "title": "Root login permitted via SSH", "severity": "Medium"}],
        )
        response = client.post("/api/scan/verify", json={
            "host": "192.168.1.1", "password": "test-placeholder-not-real",
            "check_ids": ["SSH-001", "SSH-002"],
        })
        assert response.status_code == 200
        data = response.json()
        assert data["results"] == [
            {"id": "SSH-001", "status": "still_failing", "title": "Root login permitted via SSH"},
            {"id": "SSH-002", "status": "resolved", "title": ""},
        ]
        assert data["checks_run"] == ["SSH"]
        assert mock_verify.call_args[0][4] == ["SSH-001", "SSH-002"]

    @patch("api.routes.scan._persist_scan")
    @patch("api.routes.scan._run_ssh_verification")
    def test_verify_is_not_saved_to_history(self, mock_verify, mock_persist, client):
        mock_verify.return_value = _verify_results({"SSH-001": "resolved"}, [])
        client.post("/api/scan/verify", json={
            "host": "192.168.1.1", "password": "test-placeholder-not-real", "check_ids": ["SSH-001"],
        })
        mock_persist.assert_not_called()

    def test_verify_requires_password(self, client):
        with patch.dict("os.environ", {}, clear=True):
            response = client.post("/api/scan/verify", json={"host": "192.168.1.1", "check_ids": ["SSH-001"]})
        assert response.status_code == 400

    def test_verify_rejects_empty_and_oversized_ids(self, client):
        base = {"host": "192.168.1.1", "password": "test-placeholder-not-real"}
        assert client.post("/api/scan/verify", json={**base, "check_ids": []}).status_code == 422
        assert client.post("/api/scan/verify", json={**base, "check_ids": ["  "]}).status_code == 422
        assert client.post("/api/scan/verify", json={**base, "check_ids": ["X"] * 51}).status_code == 422
        assert client.post("/api/scan/verify", json={**base, "check_ids": ["A" * 65]}).status_code == 422

    @patch("api.routes.scan._run_ssh_verification")
    def test_verify_connection_failure(self, mock_verify, client):
        mock_verify.side_effect = ConnectionError("SSH connection to 10.0.0.1:22 failed")
        response = client.post("/api/scan/verify", json={
            "host": "10.0.0.1", "password": "test-placeholder-not-real", "check_ids": ["SSH-001"],
        })
        assert response.status_code == 502
