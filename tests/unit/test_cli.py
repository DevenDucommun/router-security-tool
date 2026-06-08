"""Tests for CLI interface."""

import json
import pytest
from unittest.mock import patch, MagicMock
from io import StringIO

from cli import (
    build_parser,
    cmd_scan,
    cmd_report,
    severity_to_exit_code,
    print_findings_table,
    EXIT_CLEAN,
    EXIT_LOW,
    EXIT_HIGH,
    EXIT_CRITICAL,
)


class TestExitCodes:
    def test_clean_when_no_findings(self):
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        assert severity_to_exit_code(summary) == EXIT_CLEAN

    def test_low_on_medium_findings(self):
        summary = {"Critical": 0, "High": 0, "Medium": 2, "Low": 1, "Info": 0}
        assert severity_to_exit_code(summary) == EXIT_LOW

    def test_high_on_high_findings(self):
        summary = {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0}
        assert severity_to_exit_code(summary) == EXIT_HIGH

    def test_critical_on_critical_findings(self):
        summary = {"Critical": 1, "High": 3, "Medium": 5, "Low": 0, "Info": 0}
        assert severity_to_exit_code(summary) == EXIT_CRITICAL

    def test_info_only_is_clean(self):
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 5}
        assert severity_to_exit_code(summary) == EXIT_CLEAN


class TestParser:
    def test_scan_command_parses(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "192.168.1.1", "-u", "admin", "-p", "pass123"])
        assert args.command == "scan"
        assert args.host == "192.168.1.1"
        assert args.user == "admin"
        assert args.password == "pass123"

    def test_scan_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "10.0.0.1"])
        assert args.port == 22
        assert args.json is False
        assert args.verbose is False
        assert args.quiet is False

    def test_report_command_parses(self):
        parser = build_parser()
        args = parser.parse_args(["report", "192.168.1.1", "-o", "report.json", "-p", "pw"])
        assert args.command == "report"
        assert args.output == "report.json"

    def test_no_command_returns_none(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.command is None


class TestCmdScan:
    @pytest.fixture
    def mock_assessment_results(self):
        return {
            "device_info": {"uname": "Linux router 5.10.0", "hostname": "test-router"},
            "findings": [
                {
                    "id": "SSH-001", "title": "Root login enabled",
                    "severity": "Medium", "type": "SSH Assessment",
                    "description": "Root login via SSH is enabled",
                    "evidence": "", "remediation": "Disable root login",
                    "affected_component": "Device Configuration",
                }
            ],
            "finding_count": 1,
            "severity_summary": {"Critical": 0, "High": 0, "Medium": 1, "Low": 0, "Info": 0},
            "profile": "openwrt",
        }

    @patch("cli.ConnectionManager")
    def test_scan_no_password_exits_critical(self, mock_conn_cls, monkeypatch):
        monkeypatch.delenv("ROUTER_PASS", raising=False)
        parser = build_parser()
        args = parser.parse_args(["scan", "192.168.1.1"])
        result = cmd_scan(args)
        assert result == EXIT_CRITICAL

    @patch("cli.ConnectionManager")
    def test_scan_connection_failure(self, mock_conn_cls, monkeypatch):
        monkeypatch.setenv("ROUTER_PASS", "testpass")
        mock_conn = MagicMock()
        mock_conn.connect_ssh.return_value = False
        mock_conn_cls.return_value = mock_conn

        parser = build_parser()
        args = parser.parse_args(["scan", "192.168.1.1"])
        result = cmd_scan(args)
        assert result == EXIT_CRITICAL

    @patch("cli.SSHAssessor")
    @patch("cli.ConnectionManager")
    def test_scan_success_returns_severity_code(
        self, mock_conn_cls, mock_assessor_cls, mock_assessment_results, monkeypatch
    ):
        monkeypatch.setenv("ROUTER_PASS", "testpass")
        mock_conn = MagicMock()
        mock_conn.connect_ssh.return_value = True
        mock_conn_cls.return_value = mock_conn

        mock_assessor = MagicMock()
        mock_assessor.run_assessment.return_value = mock_assessment_results
        mock_assessor_cls.return_value = mock_assessor

        parser = build_parser()
        args = parser.parse_args(["scan", "192.168.1.1", "-q"])
        result = cmd_scan(args)
        assert result == EXIT_LOW

    @patch("cli.SSHAssessor")
    @patch("cli.ConnectionManager")
    def test_scan_json_output(
        self, mock_conn_cls, mock_assessor_cls, mock_assessment_results, monkeypatch, capsys
    ):
        monkeypatch.setenv("ROUTER_PASS", "testpass")
        mock_conn = MagicMock()
        mock_conn.connect_ssh.return_value = True
        mock_conn_cls.return_value = mock_conn

        mock_assessor = MagicMock()
        mock_assessor.run_assessment.return_value = mock_assessment_results
        mock_assessor_cls.return_value = mock_assessor

        parser = build_parser()
        args = parser.parse_args(["scan", "192.168.1.1", "--json"])
        cmd_scan(args)

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["finding_count"] == 1
        assert output["profile"] == "openwrt"

    @patch("cli.SSHAssessor")
    @patch("cli.ConnectionManager")
    def test_scan_disconnects_on_success(
        self, mock_conn_cls, mock_assessor_cls, mock_assessment_results, monkeypatch
    ):
        monkeypatch.setenv("ROUTER_PASS", "testpass")
        mock_conn = MagicMock()
        mock_conn.connect_ssh.return_value = True
        mock_conn_cls.return_value = mock_conn

        mock_assessor = MagicMock()
        mock_assessor.run_assessment.return_value = mock_assessment_results
        mock_assessor_cls.return_value = mock_assessor

        parser = build_parser()
        args = parser.parse_args(["scan", "192.168.1.1", "-q", "-p", "pass"])
        cmd_scan(args)
        mock_conn.disconnect.assert_called_once()


class TestCmdReport:
    @patch("cli.SSHAssessor")
    @patch("cli.ConnectionManager")
    def test_report_writes_json(
        self, mock_conn_cls, mock_assessor_cls, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ROUTER_PASS", "testpass")
        mock_conn = MagicMock()
        mock_conn.connect_ssh.return_value = True
        mock_conn_cls.return_value = mock_conn

        results = {
            "device_info": {"hostname": "rtr"},
            "findings": [],
            "finding_count": 0,
            "severity_summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "profile": None,
        }
        mock_assessor = MagicMock()
        mock_assessor.run_assessment.return_value = results
        mock_assessor_cls.return_value = mock_assessor

        output_file = tmp_path / "report.json"
        parser = build_parser()
        args = parser.parse_args(["report", "192.168.1.1", "-o", str(output_file), "-q"])
        result = cmd_report(args)

        assert result == EXIT_CLEAN
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["finding_count"] == 0


class TestPrintFindings:
    def test_print_table_no_findings(self, capsys):
        results = {
            "device_info": {"hostname": "test", "uname": "Linux test 5.0"},
            "findings": [],
            "finding_count": 0,
            "severity_summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "profile": "generic",
        }
        print_findings_table(results)
        captured = capsys.readouterr()
        assert "No security findings" in captured.out
        assert "Clean" in captured.out

    def test_print_table_with_findings(self, capsys):
        results = {
            "device_info": {"hostname": "router-1", "uname": "Linux rtr"},
            "findings": [
                {"id": "TEST-001", "title": "Test finding", "severity": "High"}
            ],
            "finding_count": 1,
            "severity_summary": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0},
            "profile": "openwrt",
        }
        print_findings_table(results)
        captured = capsys.readouterr()
        assert "TEST-001" in captured.out
        assert "Test finding" in captured.out
        assert "1 High" in captured.out
