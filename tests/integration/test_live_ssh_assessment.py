"""
Integration test: Live SSH Assessment against a real device.

Requires a reachable router at 192.168.1.1 with SSH access.
Run with: pytest tests/integration/test_live_ssh_assessment.py -v -m network
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from connections.manager import ConnectionManager
from assessment.ssh_assessor import SSHAssessor


ROUTER_HOST = "192.168.1.1"
ROUTER_USER = "root"
ROUTER_PASS = os.environ.get("ROUTER_PASS", "")


@pytest.fixture(scope="module")
def ssh_connection():
    """Establish real SSH connection to lab router."""
    conn = ConnectionManager()
    success = conn.connect_ssh(ROUTER_HOST, ROUTER_USER, ROUTER_PASS)
    if not success:
        pytest.skip(f"Cannot connect to {ROUTER_HOST} — device not reachable")
    yield conn
    conn.disconnect()


@pytest.mark.network
class TestLiveSSHConnection:
    def test_connection_established(self, ssh_connection):
        assert ssh_connection.is_connected()

    def test_can_execute_command(self, ssh_connection):
        result = ssh_connection.send_command("echo hello")
        assert "hello" in result


@pytest.mark.network
class TestLiveSSHAssessment:
    def test_full_assessment_runs(self, ssh_connection):
        assessor = SSHAssessor(ssh_connection)
        progress_messages = []
        results = assessor.run_assessment(progress_callback=progress_messages.append)

        assert "device_info" in results
        assert "findings" in results
        assert "severity_summary" in results
        assert results["finding_count"] >= 0
        assert len(progress_messages) > 0

    def test_device_info_gathered(self, ssh_connection):
        assessor = SSHAssessor(ssh_connection)
        info = assessor._gather_device_info()

        assert info.get("hostname") or info.get("uname")
        print(f"\n  Device info: {info}")

    def test_findings_have_structure(self, ssh_connection):
        assessor = SSHAssessor(ssh_connection)
        results = assessor.run_assessment()

        for finding in results["findings"]:
            assert "id" in finding
            assert "title" in finding
            assert "severity" in finding
            assert finding["severity"] in ("Critical", "High", "Medium", "Low", "Info")
            assert "description" in finding

    def test_assessment_report_summary(self, ssh_connection):
        """Print a human-readable summary for visual verification."""
        assessor = SSHAssessor(ssh_connection)
        results = assessor.run_assessment()

        print(f"\n{'='*60}")
        print(f"  LIVE ASSESSMENT: {ROUTER_HOST}")
        print(f"{'='*60}")
        print(f"  Device: {results['device_info'].get('hostname', 'unknown')}")
        print(f"  Kernel: {results['device_info'].get('uname', 'unknown')[:60]}")
        print(f"  Findings: {results['finding_count']}")
        print(f"  Severity: {results['severity_summary']}")
        print(f"{'='*60}")
        for f in results["findings"]:
            print(f"  [{f['severity']:8}] {f['id']:12} {f['title']}")
        print(f"{'='*60}\n")
