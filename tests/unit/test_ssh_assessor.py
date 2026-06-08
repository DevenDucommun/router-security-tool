"""Tests for SSH Assessment Engine"""

import pytest
from unittest.mock import MagicMock, patch

from assessment.ssh_assessor import SSHAssessor
from assessment.finding import Finding


@pytest.fixture
def mock_connection():
    """Create a mock ConnectionManager that simulates SSH responses."""
    conn = MagicMock()
    conn.is_connected.return_value = True
    return conn


@pytest.fixture
def assessor(mock_connection):
    return SSHAssessor(mock_connection)


class TestFinding:
    def test_finding_to_dict(self):
        f = Finding("TEST-001", "Test Title", "High", "Test description", "evidence", "fix it")
        d = f.to_dict()
        assert d["id"] == "TEST-001"
        assert d["title"] == "Test Title"
        assert d["severity"] == "High"
        assert d["description"] == "Test description"
        assert d["evidence"] == "evidence"
        assert d["remediation"] == "fix it"
        assert d["type"] == "SSH Assessment"


class TestSSHAssessorDeviceInfo:
    def test_gather_device_info(self, assessor, mock_connection):
        mock_connection.send_command.side_effect = lambda cmd: {
            "uname -a": "Linux router 5.10.0 #1 SMP armv7l GNU/Linux",
            "hostname": "my-router",
        }.get(cmd, "")

        info = assessor._gather_device_info()
        assert info["uname"] == "Linux router 5.10.0 #1 SMP armv7l GNU/Linux"
        assert info["hostname"] == "my-router"


class TestSSHChecks:
    def test_check_ssh_config_root_login(self, assessor, mock_connection):
        mock_connection.send_command.side_effect = lambda cmd: {
            "cat /etc/ssh/sshd_config 2>/dev/null": "PermitRootLogin yes\nPasswordAuthentication yes\n",
        }.get(cmd, "")

        assessor._check_ssh_config()
        ids = [f.check_id for f in assessor.findings]
        assert "SSH-001" in ids
        assert "SSH-002" in ids

    def test_check_ssh_config_protocol_1(self, assessor, mock_connection):
        mock_connection.send_command.side_effect = lambda cmd: {
            "cat /etc/ssh/sshd_config 2>/dev/null": "Protocol 1\n",
        }.get(cmd, "")

        assessor._check_ssh_config()
        ids = [f.check_id for f in assessor.findings]
        assert "SSH-003" in ids
        assert assessor.findings[0].severity == "Critical"

    def test_check_ssh_dropbear(self, assessor, mock_connection):
        mock_connection.send_command.side_effect = lambda cmd: {
            "cat /etc/ssh/sshd_config 2>/dev/null": "",
            "cat /etc/config/dropbear 2>/dev/null": "option PasswordAuth 'on'\noption RootLogin '1'\n",
        }.get(cmd, "")

        assessor._check_ssh_config()
        ids = [f.check_id for f in assessor.findings]
        assert "SSH-001" in ids
        assert "SSH-002" in ids

    def test_check_default_credentials_empty_password(self, assessor, mock_connection):
        mock_connection.send_command.side_effect = lambda cmd: {
            "cat /etc/shadow 2>/dev/null": "root:$6$$:18000:0:99999:7:::\nadmin:$1$$:18000:0:99999:7:::\n",
            "cat /etc/passwd 2>/dev/null": "root:x:0:0:root:/root:/bin/sh\n",
        }.get(cmd, "")

        assessor._check_default_credentials()
        ids = [f.check_id for f in assessor.findings]
        assert "CRED-001" in ids

    def test_check_default_credentials_uid0_users(self, assessor, mock_connection):
        mock_connection.send_command.side_effect = lambda cmd: {
            "cat /etc/shadow 2>/dev/null": "root:$6$salted$hash:18000:0:99999:7:::\n",
            "cat /etc/passwd 2>/dev/null": "root:x:0:0:root:/root:/bin/sh\ntoor:x:0:0:toor:/root:/bin/sh\n",
        }.get(cmd, "")

        assessor._check_default_credentials()
        ids = [f.check_id for f in assessor.findings]
        assert "CRED-002" in ids

    def test_check_listening_services_dangerous(self, assessor, mock_connection):
        mock_connection.send_command.side_effect = lambda cmd: {
            "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null": (
                "Proto Recv-Q Send-Q Local Address\n"
                "tcp   0      0      0.0.0.0:23   0.0.0.0:*   LISTEN  1234/telnetd\n"
                "tcp   0      0      0.0.0.0:22   0.0.0.0:*   LISTEN  1235/sshd\n"
            ),
        }.get(cmd, "")

        assessor._check_listening_services()
        ids = [f.check_id for f in assessor.findings]
        assert "NET-001" in ids  # Services on 0.0.0.0
        assert "NET-23" in ids   # Telnet

    def test_check_firewall_no_drop_rules(self, assessor, mock_connection):
        mock_connection.send_command.side_effect = lambda cmd: {
            "iptables -L -n 2>/dev/null | head -30": (
                "Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\nACCEPT all -- 0.0.0.0/0 0.0.0.0/0\n"
            ),
        }.get(cmd, "")

        assessor._check_firewall()
        ids = [f.check_id for f in assessor.findings]
        assert "FW-001" in ids

    def test_check_firewall_no_firewall(self, assessor, mock_connection):
        mock_connection.send_command.side_effect = lambda cmd: {
            "iptables -L -n 2>/dev/null | head -30": "",
            "uci show firewall 2>/dev/null | head -20": "",
        }.get(cmd, "")

        assessor._check_firewall()
        ids = [f.check_id for f in assessor.findings]
        assert "FW-003" in ids


class TestFullAssessment:
    def test_run_assessment_not_connected(self, mock_connection):
        mock_connection.is_connected.return_value = False
        assessor = SSHAssessor(mock_connection)
        with pytest.raises(ConnectionError):
            assessor.run_assessment()

    def test_run_assessment_returns_structure(self, assessor, mock_connection):
        mock_connection.send_command.return_value = ""

        results = assessor.run_assessment()
        assert "device_info" in results
        assert "findings" in results
        assert "finding_count" in results
        assert "severity_summary" in results
        assert isinstance(results["findings"], list)

    def test_progress_callback_called(self, assessor, mock_connection):
        mock_connection.send_command.return_value = ""
        messages = []
        assessor.run_assessment(progress_callback=messages.append)
        assert len(messages) > 0
        assert "Gathering device information" in messages[0]
