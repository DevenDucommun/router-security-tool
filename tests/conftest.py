"""
Pytest configuration and shared fixtures
"""

import pytest
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock
import sys

# Add src to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    yield db_path

    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def mock_cve_data():
    """Sample CVE data for testing"""
    return {
        "cve_id": "CVE-2023-1234",
        "description": "Test vulnerability in test product",
        "cvss_v3_score": 7.5,
        "cvss_v3_severity": "High",
        "cvss_v2_score": None,
        "published_date": "2023-01-01T00:00:00",
        "last_modified": "2023-01-02T00:00:00",
        "cpe_matches": [
            {
                "criteria": "cpe:2.3:*:cisco:ios:15.0:*:*:*:*:*:*:*",
                "vulnerable": True,
            }
        ],
        "references": [
            {"url": "https://example.com/advisory", "source": "vendor"}
        ],
        "raw_data": {},
    }


@pytest.fixture
def mock_service_scan_results():
    """Sample service scan results for testing"""
    return {
        "host": "192.168.1.1",
        "scan_time": 1234567890.0,
        "open_ports": [22, 80, 443],
        "services": {
            22: "SSH 2.0 (OpenSSH)",
            80: "HTTP - Apache",
            443: "HTTPS - nginx",
        },
        "banners": {
            22: "SSH-2.0-OpenSSH_7.4",
            80: "Server: Apache/2.4.41",
            443: "Server: nginx/1.18.0",
        },
        "protocol_issues": [
            {
                "port": 80,
                "protocol": "HTTP",
                "severity": "Medium",
                "issue": "Unencrypted web interface",
                "recommendation": "Enable HTTPS",
            }
        ],
        "security_notes": ["Administrative interfaces found on ports: [80, 443]"],
    }


@pytest.fixture
def mock_socket():
    """Mock socket for network testing"""
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0  # Port open
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_7.4"
    return mock_sock


@pytest.fixture
def mock_requests():
    """Mock requests library responses"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"Server": "Apache/2.4.41"}
    mock_response.text = "<html><title>Test Router</title></html>"
    mock_response.json.return_value = {
        "vulnerabilities": [{"cve": {"id": "CVE-2023-1234"}}]
    }
    return mock_response


@pytest.fixture
def sample_device_banner():
    """Sample device banners for testing"""
    return {
        "cisco": "Cisco IOS Software, C2960 Software Version 15.0",
        "linksys": "Linksys WRT1900AC Router HTTP Server",
        "netgear": "NETGEAR R7000 ReadyNAS HTTP Server",
        "generic_ssh": "SSH-2.0-OpenSSH_7.4",
        "generic_http": "Apache/2.4.41 (Unix)",
    }


@pytest.fixture
def mock_cve_manager():
    """Mock CVE Manager for testing"""
    manager = Mock()
    manager.search_cves_by_product.return_value = [
        {
            "cve_id": "CVE-2023-1234",
            "description": "Test vulnerability",
            "cvss_v3_score": 7.5,
            "cvss_v3_severity": "High",
            "cvss_v2_score": None,
            "published_date": "2023-01-01",
            "last_modified": "2023-01-02",
            "cpe_matches": [],
            "references": [],
        }
    ]
    manager.fetch_cves_for_vendor.return_value = []
    manager.get_database_stats.return_value = {
        "total_cves": 100,
        "total_vendors": 10,
        "total_products": 50,
        "critical_cves": 15,
    }
    return manager


@pytest.fixture
def mock_service_scanner():
    """Mock Service Scanner for testing"""
    scanner = Mock()
    scanner.scan_host.return_value = {
        "host": "192.168.1.1",
        "scan_time": 1234567890.0,
        "open_ports": [22, 80, 443],
        "services": {22: "SSH", 80: "HTTP", 443: "HTTPS"},
        "banners": {22: "SSH-2.0-OpenSSH_7.4"},
        "protocol_issues": [],
        "security_notes": [],
    }
    return scanner


@pytest.fixture(autouse=True)
def reset_logging():
    """Reset logging configuration between tests"""
    import logging

    # Clear all handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Reset to default level
    logging.root.setLevel(logging.WARNING)

    yield

    # Cleanup after test
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
