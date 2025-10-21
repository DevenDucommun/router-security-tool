"""
Connection Detection Module
Handles detection of USB/serial ports and network connections
"""

import logging
import subprocess
import re
import serial
import serial.tools.list_ports
from typing import List, Dict, Optional
import socket
import paramiko

logger = logging.getLogger(__name__)

class ConnectionDetector:
    """Detects available connection methods for network devices"""
    
    def __init__(self):
        self.serial_ports = []
        self.network_targets = []
        
    def detect_serial_ports(self) -> List[Dict]:
        """Detect available serial/USB ports"""
        logger.info("Scanning for serial/USB ports...")
        ports = []
        
        # Use pyserial to detect ports
        for port in serial.tools.list_ports.comports():
            port_info = {
                'device': port.device,
                'description': port.description,
                'hwid': port.hwid,
                'vid': port.vid,
                'pid': port.pid,
                'manufacturer': port.manufacturer,
                'type': 'serial'
            }
            
            # Common router/network device identifiers
            router_keywords = ['ftdi', 'prolific', 'cp210', 'ch340', 'console', 'serial']
            if any(keyword in port.description.lower() for keyword in router_keywords):
                port_info['likely_router'] = True
            
            ports.append(port_info)
            logger.debug(f"Found port: {port_info}")
        
        self.serial_ports = ports
        return ports
    
    def detect_usb_devices(self) -> List[Dict]:
        """Detect USB devices that might be network equipment"""
        logger.info("Scanning for USB devices...")
        devices = []
        
        try:
            # Use system_profiler on macOS
            result = subprocess.run(
                ['system_profiler', 'SPUSBDataType', '-xml'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Parse USB device info (simplified version)
            usb_text = result.stdout
            
            # Look for common network device manufacturers
            manufacturers = ['cisco', 'linksys', 'netgear', 'tp-link', 'dlink', 'asus']
            
            for manufacturer in manufacturers:
                if manufacturer.lower() in usb_text.lower():
                    devices.append({
                        'manufacturer': manufacturer,
                        'type': 'usb_device',
                        'detected': True
                    })
                    
        except subprocess.TimeoutExpired:
            logger.warning("USB device detection timed out")
        except FileNotFoundError:
            logger.warning("system_profiler not available (not on macOS?)")
        
        return devices
    
    def scan_network_range(self, network: str = "192.168.1.0/24") -> List[Dict]:
        """Scan local network for potential router/switch management interfaces"""
        logger.info(f"Scanning network range: {network}")
        targets = []
        
        # Common router IP addresses
        common_ips = [
            "192.168.1.1", "192.168.0.1", "10.0.0.1", "172.16.0.1",
            "192.168.1.254", "192.168.0.254"
        ]
        
        for ip in common_ips:
            if self._test_tcp_connection(ip, 22):  # SSH
                targets.append({
                    'ip': ip,
                    'port': 22,
                    'service': 'ssh',
                    'type': 'network'
                })
            
            if self._test_tcp_connection(ip, 23):  # Telnet
                targets.append({
                    'ip': ip,
                    'port': 23,
                    'service': 'telnet',
                    'type': 'network'
                })
        
        self.network_targets = targets
        return targets
    
    def _test_tcp_connection(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Test if a TCP port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except:
            return False
    
    def get_all_connections(self) -> List[Dict]:
        """Get all detected connection options"""
        all_connections = []
        
        # Add serial ports
        all_connections.extend(self.detect_serial_ports())
        
        # Add USB devices
        all_connections.extend(self.detect_usb_devices())
        
        # Add network targets
        all_connections.extend(self.scan_network_range())
        
        return all_connections