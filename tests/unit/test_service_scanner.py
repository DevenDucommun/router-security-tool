"""
Unit tests for Service Scanner module
"""

import pytest
import socket
from unittest.mock import Mock, patch, MagicMock
from src.assessment.service_scanner import ServiceScanner


@pytest.fixture
def service_scanner():
    """Create a ServiceScanner instance"""
    return ServiceScanner()


@pytest.fixture
def mock_socket():
    """Create a mock socket"""
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0  # Port is open
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_7.4\r\n"
    return mock_sock


class TestServiceScannerInit:
    """Test ServiceScanner initialization"""

    def test_init_creates_common_ports(self, service_scanner):
        """Test that common ports are initialized"""
        assert len(service_scanner.common_ports) > 0
        assert 22 in service_scanner.common_ports
        assert service_scanner.common_ports[22] == "SSH"
        assert 80 in service_scanner.common_ports
        assert 443 in service_scanner.common_ports

    def test_init_empty_results(self, service_scanner):
        """Test that results structures are initialized empty"""
        assert service_scanner.service_banners == {}
        assert service_scanner.scan_results == {}


class TestPortScanning:
    """Test port scanning functionality"""

    @patch("socket.socket")
    def test_scan_port_open(self, mock_socket_class, service_scanner):
        """Test scanning an open port"""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_7.4\r\n"
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        is_open, banner, service_info = service_scanner._scan_port(
            "192.168.1.1", 22, 1.0
        )

        assert is_open is True
        assert banner is not None
        mock_sock.connect_ex.assert_called_once()

    @patch("socket.socket")
    def test_scan_port_closed(self, mock_socket_class, service_scanner):
        """Test scanning a closed port"""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # Port closed
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        is_open, banner, service_info = service_scanner._scan_port(
            "192.168.1.1", 9999, 1.0
        )

        assert is_open is False
        assert banner is None
        assert service_info is None

    @patch("socket.socket")
    def test_scan_port_timeout(self, mock_socket_class, service_scanner):
        """Test port scan with timeout"""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        is_open, banner, service_info = service_scanner._scan_port(
            "192.168.1.1", 22, 0.1
        )

        assert is_open is False


class TestBannerGrabbing:
    """Test banner grabbing functionality"""

    @patch("socket.socket")
    def test_grab_banner_ssh(self, mock_socket_class, service_scanner):
        """Test grabbing SSH banner"""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_7.4\r\n"
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        banner = service_scanner._grab_banner("192.168.1.1", 22)

        assert banner is not None
        assert "SSH" in banner

    @patch("socket.socket")
    def test_grab_banner_http(self, mock_socket_class, service_scanner):
        """Test grabbing HTTP banner"""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = (
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\n"
        )
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        banner = service_scanner._grab_banner("192.168.1.1", 80)

        assert banner is not None
        mock_sock.send.assert_called_once()

    @patch("socket.socket")
    def test_grab_banner_timeout(self, mock_socket_class, service_scanner):
        """Test banner grab with timeout"""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        banner = service_scanner._grab_banner("192.168.1.1", 22, timeout=0.1)

        assert banner is None

    @patch("socket.socket")
    def test_grab_banner_empty_response(
        self, mock_socket_class, service_scanner
    ):
        """Test banner grab with empty response"""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        banner = service_scanner._grab_banner("192.168.1.1", 22)

        assert banner is None


class TestServiceIdentification:
    """Test service identification methods"""

    def test_guess_service_from_banner_ssh(self, service_scanner):
        """Test service identification from SSH banner"""
        banner = "SSH-2.0-OpenSSH_7.4"
        service = service_scanner._guess_service_from_banner(banner)

        assert service == "SSH"

    def test_guess_service_from_banner_http(self, service_scanner):
        """Test service identification from HTTP banner"""
        banner = "HTTP/1.1 200 OK\\nServer: Apache/2.4.41"
        service = service_scanner._guess_service_from_banner(banner)

        assert service == "HTTP"

    def test_guess_service_from_banner_ftp(self, service_scanner):
        """Test service identification from FTP banner"""
        banner = "220 FTP Server ready"
        service = service_scanner._guess_service_from_banner(banner)

        assert service == "FTP"

    def test_guess_service_from_banner_cisco(self, service_scanner):
        """Test service identification from Cisco banner"""
        banner = "Cisco IOS Software, Version 15.1"
        service = service_scanner._guess_service_from_banner(banner)

        assert service == "Cisco Service"

    def test_guess_service_from_banner_unknown(self, service_scanner):
        """Test service identification with unknown banner"""
        banner = "Unknown Service v1.0"
        service = service_scanner._guess_service_from_banner(banner)

        assert service is None

    def test_guess_service_from_banner_empty(self, service_scanner):
        """Test service identification with empty banner"""
        service = service_scanner._guess_service_from_banner("")

        assert service is None


class TestProtocolAnalysis:
    """Test protocol security analysis"""

    def test_analyze_protocols_telnet_issue(self, service_scanner):
        """Test detection of insecure Telnet protocol"""
        scan_results = {"open_ports": [23]}

        analysis = service_scanner._analyze_protocols(
            "192.168.1.1", scan_results
        )

        assert len(analysis["protocol_issues"]) > 0
        telnet_issue = analysis["protocol_issues"][0]
        assert telnet_issue["port"] == 23
        assert telnet_issue["severity"] == "High"
        assert "Telnet" in telnet_issue["protocol"]

    def test_analyze_protocols_http_only(self, service_scanner):
        """Test detection of HTTP without HTTPS"""
        scan_results = {"open_ports": [80]}

        analysis = service_scanner._analyze_protocols(
            "192.168.1.1", scan_results
        )

        assert len(analysis["protocol_issues"]) > 0
        http_issue = next(
            (i for i in analysis["protocol_issues"] if i["port"] == 80), None
        )
        assert http_issue is not None
        assert http_issue["severity"] == "Medium"

    def test_analyze_protocols_snmp(self, service_scanner):
        """Test detection of SNMP security issues"""
        scan_results = {"open_ports": [161]}

        analysis = service_scanner._analyze_protocols(
            "192.168.1.1", scan_results
        )

        assert len(analysis["protocol_issues"]) > 0
        snmp_issue = next(
            (i for i in analysis["protocol_issues"] if i["port"] == 161), None
        )
        assert snmp_issue is not None
        assert "SNMP" in snmp_issue["protocol"]

    def test_analyze_protocols_admin_interfaces(self, service_scanner):
        """Test detection of administrative interfaces"""
        scan_results = {"open_ports": [443, 8080]}

        analysis = service_scanner._analyze_protocols(
            "192.168.1.1", scan_results
        )

        assert len(analysis["security_notes"]) > 0

    def test_analyze_protocols_no_issues(self, service_scanner):
        """Test analysis with no security issues"""
        scan_results = {"open_ports": [22, 443]}

        analysis = service_scanner._analyze_protocols(
            "192.168.1.1", scan_results
        )

        # Should have minimal or no protocol issues for SSH and HTTPS
        assert "protocol_issues" in analysis


class TestFullHostScan:
    """Test full host scanning"""

    @patch("src.assessment.service_scanner.ServiceScanner._scan_port")
    @patch("src.assessment.service_scanner.ServiceScanner._identify_service")
    def test_scan_host_with_open_ports(
        self, mock_identify, mock_scan_port, service_scanner
    ):
        """Test scanning a host with open ports"""
        # Mock _scan_port to return open ports
        mock_scan_port.return_value = (True, "SSH-2.0-OpenSSH_7.4", "SSH")

        # Mock _identify_service
        mock_identify.return_value = ("SSH-2.0-OpenSSH_7.4", "SSH 2.0")

        results = service_scanner.scan_host(
            "192.168.1.1", ports=[22, 23, 80]
        )

        assert results["host"] == "192.168.1.1"
        assert "scan_time" in results
        assert len(results["open_ports"]) > 0
        assert "services" in results
        assert "banners" in results

    @patch("src.assessment.service_scanner.ServiceScanner._scan_port")
    def test_scan_host_no_ports_specified(
        self, mock_scan_port, service_scanner
    ):
        """Test scanning without specifying ports (uses common ports)"""
        mock_scan_port.return_value = (False, None, None)

        results = service_scanner.scan_host("192.168.1.1")

        assert results["host"] == "192.168.1.1"
        # Should scan common ports
        assert mock_scan_port.call_count == len(
            service_scanner.common_ports
        )

    @patch("src.assessment.service_scanner.ServiceScanner._scan_port")
    def test_scan_host_handles_exceptions(
        self, mock_scan_port, service_scanner
    ):
        """Test that scan handles port scanning exceptions"""
        mock_scan_port.side_effect = Exception("Network error")

        results = service_scanner.scan_host("192.168.1.1", ports=[22])

        # Should still return results structure even with errors
        assert results["host"] == "192.168.1.1"
        assert "open_ports" in results


class TestServiceVulnerabilities:
    """Test service vulnerability detection"""

    def test_get_service_vulnerabilities_telnet(self, service_scanner):
        """Test vulnerability detection for Telnet"""
        vulns = service_scanner.get_service_vulnerabilities("Telnet")

        assert len(vulns) > 0
        assert any("plaintext" in v["description"].lower() for v in vulns)

    def test_get_service_vulnerabilities_snmpv1(self, service_scanner):
        """Test vulnerability detection for SNMPv1"""
        vulns = service_scanner.get_service_vulnerabilities("SNMP v1")

        assert len(vulns) > 0
        assert any("community" in v["description"].lower() for v in vulns)

    def test_get_service_vulnerabilities_unknown(self, service_scanner):
        """Test vulnerability detection for unknown service"""
        vulns = service_scanner.get_service_vulnerabilities("UnknownService")

        # Should return empty list or minimal results
        assert isinstance(vulns, list)


class TestWebServiceIdentification:
    """Test web service identification"""

    @patch("requests.get")
    def test_identify_web_service_success(
        self, mock_get, service_scanner
    ):
        """Test successful web service identification"""
        mock_response = Mock()
        mock_response.headers = {
            "Server": "nginx/1.14.0",
            "Content-Type": "text/html",
        }
        mock_response.text = "<html><head><title>Router Admin</title></head></html>"
        mock_get.return_value = mock_response

        banner, service_detail = service_scanner._identify_web_service(
            "192.168.1.1", 80
        )

        assert banner is not None
        assert "nginx" in banner
        assert service_detail is not None
        assert "HTTP" in service_detail

    @patch("requests.get")
    def test_identify_web_service_timeout(self, mock_get, service_scanner):
        """Test web service identification with timeout"""
        mock_get.side_effect = Exception("Timeout")

        banner, service_detail = service_scanner._identify_web_service(
            "192.168.1.1", 80
        )

        # Should handle gracefully
        assert service_detail == "HTTP"


class TestSSHServiceIdentification:
    """Test SSH service identification"""

    @patch("socket.socket")
    def test_identify_ssh_service_openssh(
        self, mock_socket_class, service_scanner
    ):
        """Test identification of OpenSSH service"""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        banner, service_detail = service_scanner._identify_ssh_service(
            "192.168.1.1", 22
        )

        assert banner is not None
        assert "SSH-2.0" in banner
        assert "OpenSSH" in service_detail

    @patch("socket.socket")
    def test_identify_ssh_service_cisco(
        self, mock_socket_class, service_scanner
    ):
        """Test identification of Cisco SSH service"""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-1.99-Cisco-1.25"
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        banner, service_detail = service_scanner._identify_ssh_service(
            "192.168.1.1", 22
        )

        assert "Cisco" in service_detail


class TestTelnetServiceIdentification:
    """Test Telnet service identification"""

    @patch("socket.socket")
    def test_identify_telnet_service_cisco(
        self, mock_socket_class, service_scanner
    ):
        """Test identification of Cisco Telnet service"""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"User Access Verification\\r\\n\\r\\nCisco Router\\r\\n"
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        banner, service_detail = service_scanner._identify_telnet_service(
            "192.168.1.1", 23
        )

        assert banner is not None
        assert "Cisco" in service_detail

    @patch("socket.socket")
    def test_identify_telnet_service_generic_login(
        self, mock_socket_class, service_scanner
    ):
        """Test identification of generic Telnet login"""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"Login: "
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        banner, service_detail = service_scanner._identify_telnet_service(
            "192.168.1.1", 23
        )

        assert "Login prompt" in service_detail
