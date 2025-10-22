"""
Service Enumeration Module
Network port scanning and service identification capabilities
"""

import logging
import socket
import time
import subprocess
import re
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl
import requests

logger = logging.getLogger(__name__)


class ServiceScanner:
    """Network service enumeration and identification"""

    def __init__(self):
        self.common_ports = {
            # Web services
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            # Remote access
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            5900: "VNC",
            # Network management
            161: "SNMP",
            162: "SNMP-Trap",
            69: "TFTP",
            # File services
            21: "FTP",
            990: "FTPS",
            # Network infrastructure
            53: "DNS",
            67: "DHCP-Server",
            68: "DHCP-Client",
            123: "NTP",
            514: "Syslog",
            # Database
            3306: "MySQL",
            5432: "PostgreSQL",
            1521: "Oracle",
            # Enterprise
            389: "LDAP",
            636: "LDAPS",
            1812: "RADIUS-Auth",
            1813: "RADIUS-Acct",
        }

        self.service_banners = {}
        self.scan_results = {}

    def scan_host(
        self,
        host: str,
        ports: List[int] = None,
        timeout: float = 1.0,
        max_threads: int = 50,
    ) -> Dict:
        """Scan a single host for open ports and services"""
        logger.info(f"Scanning host: {host}")

        if ports is None:
            ports = list(self.common_ports.keys())

        results = {
            "host": host,
            "scan_time": time.time(),
            "open_ports": [],
            "services": {},
            "banners": {},
            "vulnerabilities": [],
        }

        # Parallel port scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(self._scan_port, host, port, timeout): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, banner, service_info = future.result()
                    if is_open:
                        results["open_ports"].append(port)
                        results["services"][port] = (
                            service_info
                            or self.common_ports.get(port, "Unknown")
                        )
                        if banner:
                            results["banners"][port] = banner

                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {e}")

        # Service identification and banner grabbing
        for port in results["open_ports"]:
            try:
                banner, service_detail = self._identify_service(host, port)
                if banner:
                    results["banners"][port] = banner
                if service_detail:
                    results["services"][port] = service_detail
            except Exception as e:
                logger.debug(f"Error identifying service on port {port}: {e}")

        # Protocol-specific analysis
        results.update(self._analyze_protocols(host, results))

        logger.info(
            f"Scan complete for {host}: {len(results['open_ports'])} open ports"
        )
        return results

    def _scan_port(
        self, host: str, port: int, timeout: float
    ) -> Tuple[bool, str, str]:
        """Scan a single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))

                if result == 0:
                    # Port is open, try to grab banner
                    banner = self._grab_banner(host, port, timeout)
                    service_info = (
                        self._guess_service_from_banner(banner)
                        if banner
                        else None
                    )
                    return True, banner, service_info
                else:
                    return False, None, None

        except Exception as e:
            logger.debug(f"Port scan error {host}:{port} - {e}")
            return False, None, None

    def _grab_banner(
        self, host: str, port: int, timeout: float = 2.0
    ) -> Optional[str]:
        """Grab service banner from open port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))

                # Send appropriate probe based on port
                if port in [80, 8080]:
                    sock.send(
                        b"GET / HTTP/1.1\\r\\nHost: "
                        + host.encode()
                        + b"\\r\\n\\r\\n"
                    )
                elif port == 21:
                    pass  # FTP sends banner automatically
                elif port == 22:
                    pass  # SSH sends banner automatically
                elif port == 23:
                    sock.send(b"\\r\\n")
                elif port == 25:
                    sock.send(b"EHLO test\\r\\n")
                else:
                    sock.send(b"\\r\\n")

                # Read response
                banner = (
                    sock.recv(1024).decode("utf-8", errors="ignore").strip()
                )
                return banner if banner else None

        except Exception as e:
            logger.debug(f"Banner grab error {host}:{port} - {e}")
            return None

    def _identify_service(
        self, host: str, port: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """Detailed service identification"""
        try:
            if port in [80, 8080, 8443]:
                return self._identify_web_service(host, port)
            elif port == 443:
                return self._identify_https_service(host, port)
            elif port == 22:
                return self._identify_ssh_service(host, port)
            elif port == 161:
                return self._identify_snmp_service(host, port)
            elif port == 23:
                return self._identify_telnet_service(host, port)
            else:
                banner = self._grab_banner(host, port)
                service = self._guess_service_from_banner(banner)
                return banner, service

        except Exception as e:
            logger.debug(f"Service identification error {host}:{port} - {e}")
            return None, None

    def _identify_web_service(
        self, host: str, port: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """Identify web service details"""
        try:
            url = f"http://{host}:{port}"
            response = requests.get(url, timeout=5, verify=False)

            server = response.headers.get("Server", "Unknown")
            title = ""

            # Extract title from HTML
            if "text/html" in response.headers.get("Content-Type", ""):
                title_match = re.search(
                    r"<title>(.*?)</title>", response.text, re.IGNORECASE
                )
                if title_match:
                    title = title_match.group(1).strip()

            service_detail = f"HTTP - {server}"
            if title:
                service_detail += f" ({title})"

            banner = f"Server: {server}\\nTitle: {title}"
            return banner, service_detail

        except Exception as e:
            logger.debug(f"Web service identification error: {e}")
            return None, "HTTP"

    def _identify_https_service(
        self, host: str, port: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """Identify HTTPS service and certificate details"""
        try:
            # Get SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

            # Extract certificate details
            subject = dict(x[0] for x in cert["subject"])
            issuer = dict(x[0] for x in cert["issuer"])

            banner = f"SSL Certificate:\\n"
            banner += f"Subject: {subject.get('commonName', 'Unknown')}\\n"
            banner += f"Issuer: {issuer.get('organizationName', 'Unknown')}\\n"
            banner += f"Cipher: {cipher[0] if cipher else 'Unknown'}"

            service_detail = (
                f"HTTPS - {subject.get('commonName', 'Unknown SSL')}"
            )

            # Try to get web server info
            try:
                url = f"https://{host}:{port}"
                response = requests.get(url, timeout=5, verify=False)
                server = response.headers.get("Server")
                if server:
                    service_detail += f" ({server})"
            except Exception:
                pass

            return banner, service_detail

        except Exception as e:
            logger.debug(f"HTTPS service identification error: {e}")
            return None, "HTTPS"

    def _identify_ssh_service(
        self, host: str, port: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """Identify SSH service version"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((host, port))
                banner = (
                    sock.recv(1024).decode("utf-8", errors="ignore").strip()
                )

            # Parse SSH version
            if banner.startswith("SSH-"):
                version_match = re.search(r"SSH-([\\d\\.]+)", banner)
                version = (
                    version_match.group(1) if version_match else "Unknown"
                )

                service_detail = f"SSH {version}"
                if "OpenSSH" in banner:
                    service_detail += " (OpenSSH)"
                elif "Cisco" in banner:
                    service_detail += " (Cisco)"

                return banner, service_detail
            else:
                return banner, "SSH"

        except Exception as e:
            logger.debug(f"SSH service identification error: {e}")
            return None, "SSH"

    def _identify_snmp_service(
        self, host: str, port: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """Identify SNMP service and community strings"""
        try:
            # Try common community strings
            communities = ["public", "private", "community", "admin"]

            for community in communities:
                try:
                    # Simple SNMP GET request for system description
                    result = subprocess.run(
                        [
                            "snmpget",
                            "-v2c",
                            "-c",
                            community,
                            host,
                            "1.3.6.1.2.1.1.1.0",  # sysDescr
                        ],
                        capture_output=True,
                        text=True,
                        timeout=3,
                    )

                    if result.returncode == 0 and result.stdout:
                        banner = f"SNMP Community: {community}\\n{result.stdout.strip()}"
                        service_detail = f"SNMP v2c (Community: {community})"
                        return banner, service_detail

                except subprocess.TimeoutExpired:
                    continue
                except FileNotFoundError:
                    # snmpget not available
                    break

            return None, "SNMP"

        except Exception as e:
            logger.debug(f"SNMP service identification error: {e}")
            return None, "SNMP"

    def _identify_telnet_service(
        self, host: str, port: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """Identify Telnet service"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((host, port))

                # Send initial data and read response
                sock.send(b"\\r\\n")
                time.sleep(0.5)
                banner = (
                    sock.recv(1024).decode("utf-8", errors="ignore").strip()
                )

            service_detail = "Telnet"
            if "cisco" in banner.lower():
                service_detail += " (Cisco)"
            elif "login" in banner.lower():
                service_detail += " (Login prompt)"

            return banner, service_detail

        except Exception as e:
            logger.debug(f"Telnet service identification error: {e}")
            return None, "Telnet"

    def _guess_service_from_banner(self, banner: str) -> Optional[str]:
        """Guess service type from banner"""
        if not banner:
            return None

        banner_lower = banner.lower()

        if "ssh-" in banner_lower:
            return "SSH"
        elif "http" in banner_lower:
            return "HTTP"
        elif "ftp" in banner_lower:
            return "FTP"
        elif "smtp" in banner_lower:
            return "SMTP"
        elif "mysql" in banner_lower:
            return "MySQL"
        elif "cisco" in banner_lower:
            return "Cisco Service"
        else:
            return None

    def _analyze_protocols(self, host: str, scan_results: Dict) -> Dict:
        """Analyze protocols for security issues"""
        analysis = {"protocol_issues": [], "security_notes": []}

        open_ports = scan_results.get("open_ports", [])

        # Check for insecure protocols
        if 23 in open_ports:  # Telnet
            analysis["protocol_issues"].append(
                {
                    "port": 23,
                    "protocol": "Telnet",
                    "severity": "High",
                    "issue": "Unencrypted remote access protocol",
                    "recommendation": "Use SSH instead of Telnet",
                }
            )

        if 80 in open_ports and 443 not in open_ports:  # HTTP only
            analysis["protocol_issues"].append(
                {
                    "port": 80,
                    "protocol": "HTTP",
                    "severity": "Medium",
                    "issue": "Unencrypted web interface",
                    "recommendation": "Enable HTTPS and redirect HTTP to HTTPS",
                }
            )

        if 161 in open_ports:  # SNMP
            analysis["protocol_issues"].append(
                {
                    "port": 161,
                    "protocol": "SNMP",
                    "severity": "Medium",
                    "issue": "SNMP may use weak community strings",
                    "recommendation": "Use SNMPv3 with strong authentication",
                }
            )

        if 21 in open_ports:  # FTP
            analysis["protocol_issues"].append(
                {
                    "port": 21,
                    "protocol": "FTP",
                    "severity": "Medium",
                    "issue": "Unencrypted file transfer protocol",
                    "recommendation": "Use SFTP or FTPS instead",
                }
            )

        # Check for administrative interfaces
        admin_ports = [8080, 8443, 443, 80]
        admin_found = [p for p in admin_ports if p in open_ports]
        if admin_found:
            analysis["security_notes"].append(
                f"Administrative interfaces found on ports: {admin_found}"
            )

        return analysis

    def scan_network_range(
        self, network_range: str, ports: List[int] = None
    ) -> List[Dict]:
        """Scan multiple hosts in a network range"""
        # This would implement network range scanning
        # For now, just return empty list as it requires more complex networking
        logger.info(
            f"Network range scanning not yet implemented for: {network_range}"
        )
        return []

    def get_service_vulnerabilities(
        self, service: str, version: str = None
    ) -> List[Dict]:
        """Get known vulnerabilities for a service/version combination"""
        # This would integrate with the CVE database
        # Placeholder for now
        vulnerabilities = []

        # Common vulnerable services
        if "telnet" in service.lower():
            vulnerabilities.append(
                {
                    "type": "Protocol Vulnerability",
                    "severity": "High",
                    "description": "Telnet transmits credentials in plaintext",
                }
            )

        if "snmp" in service.lower() and "v1" in service.lower():
            vulnerabilities.append(
                {
                    "type": "Protocol Vulnerability",
                    "severity": "Medium",
                    "description": "SNMPv1 uses weak community-based authentication",
                }
            )

        return vulnerabilities
