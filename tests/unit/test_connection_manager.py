"""
Unit tests for Connection Manager module
"""

import pytest
from unittest.mock import patch, MagicMock, Mock
from src.connections.manager import ConnectionManager
import serial
import paramiko
import socket


@pytest.fixture
def manager():
    """Create a ConnectionManager instance"""
    return ConnectionManager()


class TestConnectionManagerInit:
    """Test ConnectionManager initialization"""

    def test_init_state(self, manager):
        """Test initial state"""
        assert manager.connection is None
        assert manager.connection_type is None
        assert manager.connection_info == {}


class TestSerialConnection:
    """Test serial connection functionality"""

    @patch("serial.Serial")
    def test_connect_serial_success(self, mock_serial_class, manager):
        """Test successful serial connection"""
        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_conn.read.return_value = b"Router>"
        mock_serial_class.return_value = mock_conn

        result = manager.connect_serial("/dev/ttyUSB0", baudrate=9600)

        assert result is True
        assert manager.connection_type == "serial"
        assert manager.connection_info["port"] == "/dev/ttyUSB0"
        mock_serial_class.assert_called_once()

    @patch("serial.Serial")
    def test_connect_serial_failure(self, mock_serial_class, manager):
        """Test failed serial connection"""
        mock_serial_class.side_effect = serial.SerialException("Port not found")

        result = manager.connect_serial("/dev/ttyUSB99")

        assert result is False
        assert manager.connection is None

    @patch("serial.Serial")
    def test_connect_serial_custom_baudrate(self, mock_serial_class, manager):
        """Test serial connection with custom baudrate"""
        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_serial_class.return_value = mock_conn

        result = manager.connect_serial("/dev/ttyUSB0", baudrate=115200)

        assert result is True
        call_args = mock_serial_class.call_args
        assert call_args[1]["baudrate"] == 115200


class TestSSHConnection:
    """Test SSH connection functionality"""

    @patch("paramiko.SSHClient")
    def test_connect_ssh_success(self, mock_ssh_class, manager):
        """Test successful SSH connection"""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Mock exec_command for connection test
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"Connection test"
        mock_stderr = MagicMock()
        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        result = manager.connect_ssh(
            "192.168.1.1", "admin", "password", port=22
        )

        assert result is True
        assert manager.connection_type == "ssh"
        assert manager.connection_info["hostname"] == "192.168.1.1"
        assert manager.connection_info["username"] == "admin"
        mock_client.connect.assert_called_once()

    @patch("paramiko.SSHClient")
    def test_connect_ssh_auth_failure(self, mock_ssh_class, manager):
        """Test SSH connection with authentication failure"""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = paramiko.AuthenticationException()

        result = manager.connect_ssh("192.168.1.1", "admin", "wrongpass")

        assert result is False
        # Connection object is created but not saved on failure

    @patch("paramiko.SSHClient")
    def test_connect_ssh_timeout(self, mock_ssh_class, manager):
        """Test SSH connection timeout"""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = socket.timeout()

        result = manager.connect_ssh("192.168.1.1", "admin", "password")

        assert result is False

    @patch("paramiko.SSHClient")
    def test_connect_ssh_connection_error(self, mock_ssh_class, manager):
        """Test SSH connection error"""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = paramiko.SSHException("Connection failed")

        result = manager.connect_ssh("192.168.1.1", "admin", "password")

        assert result is False


class TestSendCommand:
    """Test sending commands"""

    def test_send_command_no_connection(self, manager):
        """Test sending command without active connection"""
        result = manager.send_command("show version")

        assert result is None

    @patch("serial.Serial")
    def test_send_command_serial(self, mock_serial_class, manager):
        """Test sending command via serial connection"""
        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_conn.in_waiting = 10
        mock_conn.read.return_value = b"Router version 1.0"
        mock_serial_class.return_value = mock_conn

        manager.connect_serial("/dev/ttyUSB0")
        result = manager.send_command("show version")

        assert result is not None
        mock_conn.write.assert_called()

    @patch("paramiko.SSHClient")
    def test_send_command_ssh(self, mock_ssh_class, manager):
        """Test sending command via SSH connection"""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Setup connection test
        mock_stdout_test = MagicMock()
        mock_stdout_test.read.return_value = b"Connection test"

        # Setup actual command
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"Router version 1.0"
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        mock_client.exec_command.side_effect = [
            (MagicMock(), mock_stdout_test, MagicMock()),
            (MagicMock(), mock_stdout, mock_stderr),
        ]

        manager.connect_ssh("192.168.1.1", "admin", "password")
        result = manager.send_command("show version")

        assert "Router version 1.0" in result

    @patch("paramiko.SSHClient")
    def test_send_command_ssh_with_error(self, mock_ssh_class, manager):
        """Test sending command via SSH with stderr output"""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Setup connection test
        mock_stdout_test = MagicMock()
        mock_stdout_test.read.return_value = b"Connection test"

        # Setup actual command with error
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"Output"
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b"Warning: something"

        mock_client.exec_command.side_effect = [
            (MagicMock(), mock_stdout_test, MagicMock()),
            (MagicMock(), mock_stdout, mock_stderr),
        ]

        manager.connect_ssh("192.168.1.1", "admin", "password")
        result = manager.send_command("show version")

        assert result is not None


class TestReadResponse:
    """Test reading responses from serial connections"""

    def test_read_response_no_connection(self, manager):
        """Test reading response without active connection"""
        result = manager.read_response()

        assert result == ""

    def test_read_response_not_serial(self, manager):
        """Test reading response from non-serial connection"""
        manager.connection = MagicMock()
        manager.connection_type = "ssh"

        result = manager.read_response()

        assert result == ""

    @patch("serial.Serial")
    def test_read_response_serial(self, mock_serial_class, manager):
        """Test reading response from serial connection"""
        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_conn.in_waiting = 10
        mock_conn.read.return_value = b"Response data"
        mock_serial_class.return_value = mock_conn

        manager.connect_serial("/dev/ttyUSB0")
        result = manager.read_response(timeout=0.1)

        assert "Response data" in result


class TestExecuteCommands:
    """Test executing multiple commands"""

    @patch("paramiko.SSHClient")
    def test_execute_commands_multiple(self, mock_ssh_class, manager):
        """Test executing multiple commands"""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Setup connection test
        mock_stdout_test = MagicMock()
        mock_stdout_test.read.return_value = b"Connection test"

        # Setup multiple command responses
        mock_stdout1 = MagicMock()
        mock_stdout1.read.return_value = b"Command 1 output"
        mock_stdout2 = MagicMock()
        mock_stdout2.read.return_value = b"Command 2 output"

        mock_client.exec_command.side_effect = [
            (MagicMock(), mock_stdout_test, MagicMock()),
            (MagicMock(), mock_stdout1, MagicMock()),
            (MagicMock(), mock_stdout2, MagicMock()),
        ]

        manager.connect_ssh("192.168.1.1", "admin", "password")
        results = manager.execute_commands(["show version", "show config"])

        assert len(results) == 2
        assert "show version" in results
        assert "show config" in results

    def test_execute_commands_no_connection(self, manager):
        """Test executing commands without connection"""
        results = manager.execute_commands(["show version"])

        assert "show version" in results
        assert results["show version"] == ""


class TestIsConnected:
    """Test connection status check"""

    def test_is_connected_no_connection(self, manager):
        """Test is_connected with no connection"""
        assert manager.is_connected() is False

    @patch("serial.Serial")
    def test_is_connected_serial(self, mock_serial_class, manager):
        """Test is_connected with serial connection"""
        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_serial_class.return_value = mock_conn

        manager.connect_serial("/dev/ttyUSB0")

        assert manager.is_connected() is True

    @patch("serial.Serial")
    def test_is_connected_serial_closed(self, mock_serial_class, manager):
        """Test is_connected with closed serial connection"""
        mock_conn = MagicMock()
        mock_conn.is_open = False
        mock_serial_class.return_value = mock_conn

        manager.connect_serial("/dev/ttyUSB0")
        mock_conn.is_open = False

        assert manager.is_connected() is False

    @patch("paramiko.SSHClient")
    def test_is_connected_ssh(self, mock_ssh_class, manager):
        """Test is_connected with SSH connection"""
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        # Setup connection test
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"Connection test"
        mock_client.exec_command.return_value = (
            MagicMock(),
            mock_stdout,
            MagicMock(),
        )

        manager.connect_ssh("192.168.1.1", "admin", "password")

        assert manager.is_connected() is True

    @patch("paramiko.SSHClient")
    def test_is_connected_ssh_inactive(self, mock_ssh_class, manager):
        """Test is_connected with inactive SSH connection"""
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = False
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        # Setup connection test
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"Connection test"
        mock_client.exec_command.return_value = (
            MagicMock(),
            mock_stdout,
            MagicMock(),
        )

        manager.connect_ssh("192.168.1.1", "admin", "password")
        mock_transport.is_active.return_value = False

        assert manager.is_connected() is False


class TestDisconnect:
    """Test disconnection"""

    @patch("serial.Serial")
    def test_disconnect_serial(self, mock_serial_class, manager):
        """Test disconnecting serial connection"""
        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_serial_class.return_value = mock_conn

        manager.connect_serial("/dev/ttyUSB0")
        manager.disconnect()

        mock_conn.close.assert_called_once()
        assert manager.connection is None
        assert manager.connection_type is None

    @patch("paramiko.SSHClient")
    def test_disconnect_ssh(self, mock_ssh_class, manager):
        """Test disconnecting SSH connection"""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Setup connection test
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"Connection test"
        mock_client.exec_command.return_value = (
            MagicMock(),
            mock_stdout,
            MagicMock(),
        )

        manager.connect_ssh("192.168.1.1", "admin", "password")
        manager.disconnect()

        mock_client.close.assert_called_once()
        assert manager.connection is None

    def test_disconnect_no_connection(self, manager):
        """Test disconnecting with no active connection"""
        # Should not raise any errors
        manager.disconnect()

        assert manager.connection is None

    @patch("serial.Serial")
    def test_disconnect_error_handling(self, mock_serial_class, manager):
        """Test disconnect handles errors gracefully"""
        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_conn.close.side_effect = Exception("Close error")
        mock_serial_class.return_value = mock_conn

        manager.connect_serial("/dev/ttyUSB0")
        manager.disconnect()

        # Should still clear connection state despite error
        assert manager.connection is None
        assert manager.connection_type is None
