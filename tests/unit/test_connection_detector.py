"""
Unit tests for Connection Detector module
"""

import pytest
import subprocess
from unittest.mock import patch, MagicMock
from src.connections.detector import ConnectionDetector


@pytest.fixture
def detector():
    return ConnectionDetector()


class TestSerialPortDetection:
    """Tests for serial/USB port detection"""

    @patch("serial.tools.list_ports.comports")
    def test_detect_serial_ports_basic(self, mock_comports, detector):
        mock_port = MagicMock()
        mock_port.device = "/dev/tty.usbserial-FTDI"
        mock_port.description = "USB-Serial Controller D (FTDI)"
        mock_port.hwid = "FTDI1234"
        mock_port.vid = 0x0403
        mock_port.pid = 0x6001
        mock_port.manufacturer = "FTDI"
        mock_comports.return_value = [mock_port]

        ports = detector.detect_serial_ports()

        assert len(ports) == 1
        assert ports[0]["device"].startswith("/dev/tty")
        assert ports[0]["likely_router"] is True

    @patch("serial.tools.list_ports.comports")
    def test_detect_serial_ports_no_ports(self, mock_comports, detector):
        mock_comports.return_value = []

        ports = detector.detect_serial_ports()

        assert ports == []


class TestUSBDetection:
    """Tests for USB device detection via system_profiler"""

    @patch("subprocess.run")
    def test_detect_usb_devices_with_known_vendor(self, mock_run, detector):
        mock_result = MagicMock()
        mock_result.stdout = "Cisco USB Console Cable\nVendor: Cisco"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        devices = detector.detect_usb_devices()

        assert any(d["manufacturer"].lower() == "cisco" for d in devices)

    @patch("subprocess.run")
    def test_detect_usb_devices_timeout(self, mock_run, detector):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="system_profiler", timeout=10)

        devices = detector.detect_usb_devices()

        assert devices == []


class TestNetworkRangeScan:
    """Tests for network range scanning"""

    @patch("src.connections.detector.ConnectionDetector._test_tcp_connection")
    def test_scan_network_range_common_ips(self, mock_test, detector):
        mock_test.side_effect = [True, False, False, False, False, False, False, False, False, False, False, False]

        targets = detector.scan_network_range("192.168.1.0/24")

        assert any(t["service"] == "ssh" for t in targets)
        assert all(t["type"] == "network" for t in targets)

    @patch("src.connections.detector.ConnectionDetector._test_tcp_connection")
    def test_scan_network_range_no_targets(self, mock_test, detector):
        mock_test.return_value = False

        targets = detector.scan_network_range("192.168.1.0/24")

        assert targets == []


class TestGetAllConnections:
    """Tests for getting all connections"""

    @patch.object(ConnectionDetector, "detect_serial_ports")
    @patch.object(ConnectionDetector, "detect_usb_devices")
    @patch.object(ConnectionDetector, "scan_network_range")
    def test_get_all_connections_aggregates(
        self, mock_scan, mock_usb, mock_serial, detector
    ):
        mock_serial.return_value = [
            {"device": "/dev/tty.usbserial-FTDI", "type": "serial"}
        ]
        mock_usb.return_value = [
            {"manufacturer": "Cisco", "type": "usb_device", "detected": True}
        ]
        mock_scan.return_value = [
            {"ip": "192.168.1.1", "port": 22, "service": "ssh", "type": "network"}
        ]

        connections = detector.get_all_connections()

        assert len(connections) == 3
        assert any(c.get("type") == "serial" for c in connections)
        assert any(c.get("type") == "usb_device" for c in connections)
        assert any(c.get("type") == "network" for c in connections)
