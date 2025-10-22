"""
Connection Manager
Handles actual connections to devices via serial, SSH, etc.
"""

import logging
import serial
import paramiko
import socket
import time
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages connections to network devices"""

    def __init__(self):
        self.connection = None
        self.connection_type = None
        self.connection_info = {}

    def connect_serial(
        self, port: str, baudrate: int = 9600, timeout: int = 1
    ) -> bool:
        """Connect via serial port"""
        try:
            logger.info(f"Connecting to serial port {port} at {baudrate} baud")

            self.connection = serial.Serial(
                port=port,
                baudrate=baudrate,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                bytesize=serial.EIGHTBITS,
                timeout=timeout,
            )

            self.connection_type = "serial"
            self.connection_info = {
                "port": port,
                "baudrate": baudrate,
                "timeout": timeout,
            }

            # Test connection with a simple command
            if self.connection.is_open:
                self.send_command("\\n")  # Send newline to get prompt
                time.sleep(0.5)
                response = self.read_response()
                logger.debug(f"Initial response: {response}")
                return True

        except serial.SerialException as e:
            logger.error(f"Serial connection failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during serial connection: {e}")
            return False

        return False

    def connect_ssh(
        self, hostname: str, username: str, password: str, port: int = 22
    ) -> bool:
        """Connect via SSH"""
        try:
            logger.info(
                f"Connecting to {hostname}:{port} via SSH as {username}"
            )

            self.connection = paramiko.SSHClient()
            self.connection.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )

            self.connection.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )

            self.connection_type = "ssh"
            self.connection_info = {
                "hostname": hostname,
                "port": port,
                "username": username,
            }

            # Test connection
            stdin, stdout, stderr = self.connection.exec_command(
                'echo "Connection test"'
            )
            result = stdout.read().decode().strip()
            if result == "Connection test":
                logger.info("SSH connection successful")
                return True

        except paramiko.AuthenticationException:
            logger.error("SSH authentication failed")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH connection failed: {e}")
            return False
        except socket.timeout:
            logger.error("SSH connection timed out")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during SSH connection: {e}")
            return False

        return False

    def send_command(self, command: str) -> Optional[str]:
        """Send command to connected device"""
        if not self.connection:
            logger.error("No active connection")
            return None

        try:
            if self.connection_type == "serial":
                # Send command via serial
                self.connection.write(f"{command}\\n".encode())
                time.sleep(0.1)  # Give device time to process
                return self.read_response()

            elif self.connection_type == "ssh":
                # Execute command via SSH
                stdin, stdout, stderr = self.connection.exec_command(command)
                output = stdout.read().decode()
                error = stderr.read().decode()

                if error:
                    logger.warning(f"Command stderr: {error}")

                return output

        except Exception as e:
            logger.error(f"Failed to send command '{command}': {e}")
            return None

    def read_response(self, timeout: float = 2.0) -> str:
        """Read response from device"""
        if not self.connection or self.connection_type != "serial":
            return ""

        try:
            response = ""
            start_time = time.time()

            while time.time() - start_time < timeout:
                if self.connection.in_waiting > 0:
                    data = self.connection.read(self.connection.in_waiting)
                    response += data.decode("utf-8", errors="ignore")
                else:
                    time.sleep(0.1)

            return response.strip()

        except Exception as e:
            logger.error(f"Failed to read response: {e}")
            return ""

    def execute_commands(self, commands: list) -> Dict[str, str]:
        """Execute multiple commands and return results"""
        results = {}

        for command in commands:
            logger.debug(f"Executing command: {command}")
            result = self.send_command(command)
            results[command] = result or ""
            time.sleep(0.2)  # Brief pause between commands

        return results

    def is_connected(self) -> bool:
        """Check if connection is active"""
        if not self.connection:
            return False

        try:
            if self.connection_type == "serial":
                return self.connection.is_open
            elif self.connection_type == "ssh":
                # Try a simple command to test connection
                transport = self.connection.get_transport()
                return transport and transport.is_active()
        except Exception:
            return False

        return False

    def disconnect(self):
        """Close the connection"""
        if self.connection:
            try:
                if self.connection_type == "serial":
                    self.connection.close()
                elif self.connection_type == "ssh":
                    self.connection.close()

                logger.info(
                    f"Disconnected from {self.connection_type} connection"
                )

            except Exception as e:
                logger.error(f"Error during disconnect: {e}")
            finally:
                self.connection = None
                self.connection_type = None
                self.connection_info = {}
