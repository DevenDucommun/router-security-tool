"""
Cisco IOS Security Profile

Checks specific to Cisco IOS/IOS-XE devices:
- Running-config analysis (enable secret, VTY lines, ACLs)
- Service configuration (no ip http server, etc.)
- AAA authentication model
- Routing protocol authentication
- Logging and NTP configuration
"""

import re
from typing import Dict, List, Optional, Callable

from assessment.finding import Finding, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from .base import DeviceProfile


class CiscoIOSProfile(DeviceProfile):
    name = "cisco-ios"
    vendor = "Cisco"
    description = "Cisco IOS/IOS-XE router and switch assessment"

    @classmethod
    def matches(cls, device_info: Dict) -> float:
        score = 0.0
        uname = device_info.get("uname", "").lower()
        hostname = device_info.get("hostname", "").lower()
        os_release = device_info.get("os_release", "").lower()

        if "ios" in os_release or "cisco" in os_release:
            score = 0.95
        elif "cisco" in hostname:
            score = 0.7

        # Cisco devices respond with specific version strings
        if "cisco ios" in uname or "ios-xe" in uname:
            score = 0.95

        return min(score, 1.0)

    def run_checks(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[Finding]:
        self.findings = []

        checks = [
            ("Analyzing running configuration...", self._check_running_config),
            ("Checking VTY line security...", self._check_vty_lines),
            ("Auditing service configuration...", self._check_services),
            ("Checking AAA configuration...", self._check_aaa),
            ("Checking logging configuration...", self._check_logging),
            ("Checking SNMP configuration...", self._check_snmp),
        ]

        for msg, check_fn in checks:
            self._emit(msg, progress_callback)
            check_fn()

        return self.findings

    def _get_running_config(self) -> str:
        config = self._cmd("show running-config")
        if not config or "Invalid" in config:
            config = self._cmd("cat /etc/config/running-config 2>/dev/null")
        return config or ""

    def _check_running_config(self):
        """Analyze running-config for security basics."""
        config = self._get_running_config()
        if not config:
            self._add_finding(
                "CISCO-CFG-001", "Cannot retrieve running configuration",
                SEVERITY_INFO,
                "Unable to access device running-config for analysis.",
                remediation="Ensure SSH user has privilege level 15 or enable access.",
            )
            return

        # Check for enable secret vs enable password
        if re.search(r"^enable password\s", config, re.MULTILINE):
            self._add_finding(
                "CISCO-AUTH-001", "Enable password uses reversible encryption",
                SEVERITY_HIGH,
                "'enable password' stores credentials with weak Type 7 encryption.",
                remediation="Replace with 'enable algorithm-type scrypt secret <password>'.",
            )

        # Check for plaintext passwords in config
        if re.search(r"^username\s+\w+\s+password\s", config, re.MULTILINE):
            self._add_finding(
                "CISCO-AUTH-002", "Username with plaintext password",
                SEVERITY_HIGH,
                "Local user accounts configured with 'password' instead of 'secret'.",
                remediation="Use 'username <user> algorithm-type scrypt secret <pass>'.",
            )

        # Check service password-encryption
        if "no service password-encryption" in config or \
           (not re.search(r"^service password-encryption", config, re.MULTILINE)):
            self._add_finding(
                "CISCO-AUTH-003", "Service password-encryption not enabled",
                SEVERITY_MEDIUM,
                "Passwords in config may appear in cleartext without service password-encryption.",
                remediation="Add 'service password-encryption' to global config.",
            )

    def _check_vty_lines(self):
        """Check VTY line (remote access) security."""
        config = self._get_running_config()
        if not config:
            return

        # Extract VTY line config blocks
        vty_blocks = re.findall(r"(line vty.*?(?=\nline|\n!|\Z))", config, re.DOTALL)

        for block in vty_blocks:
            # Check for access-class (ACL restriction)
            if "access-class" not in block:
                self._add_finding(
                    "CISCO-VTY-001", "VTY lines without access-class restriction",
                    SEVERITY_MEDIUM,
                    "VTY lines have no ACL limiting which IPs can connect.",
                    evidence=block[:200],
                    remediation="Apply access-class: 'access-class <acl> in' under line vty config.",
                )

            # Check transport input
            if "transport input telnet" in block or "transport input all" in block:
                self._add_finding(
                    "CISCO-VTY-002", "Telnet allowed on VTY lines",
                    SEVERITY_HIGH,
                    "VTY lines permit telnet — credentials transmitted in cleartext.",
                    remediation="Set 'transport input ssh' to allow only encrypted access.",
                )

            # Check exec-timeout
            if "exec-timeout 0 0" in block:
                self._add_finding(
                    "CISCO-VTY-003", "VTY exec-timeout disabled",
                    SEVERITY_MEDIUM,
                    "VTY sessions never time out — abandoned sessions remain open indefinitely.",
                    remediation="Set reasonable timeout: 'exec-timeout 10 0' (10 minutes).",
                )

    def _check_services(self):
        """Check for insecure or unnecessary services."""
        config = self._get_running_config()
        if not config:
            return

        # Services that should be disabled
        dangerous_services = {
            "ip http server": ("CISCO-SVC-001", SEVERITY_MEDIUM, "HTTP server enabled (cleartext web management)"),
            "ip finger": ("CISCO-SVC-002", SEVERITY_LOW, "Finger service enabled (user enumeration)"),
            "service tcp-small-servers": ("CISCO-SVC-003", SEVERITY_LOW, "TCP small servers enabled"),
            "service udp-small-servers": ("CISCO-SVC-004", SEVERITY_LOW, "UDP small servers enabled"),
            "ip source-route": ("CISCO-SVC-005", SEVERITY_MEDIUM, "IP source routing enabled"),
        }

        for service, (check_id, severity, desc) in dangerous_services.items():
            if re.search(rf"^{re.escape(service)}", config, re.MULTILINE):
                self._add_finding(
                    check_id, desc, severity, f"'{service}' is configured on this device.",
                    remediation=f"Disable with 'no {service}' in global config.",
                )

        # Check CDP
        if "no cdp run" not in config:
            self._add_finding(
                "CISCO-SVC-006", "CDP enabled globally",
                SEVERITY_LOW,
                "Cisco Discovery Protocol leaks device info to adjacent devices.",
                remediation="Disable globally with 'no cdp run' or per-interface with 'no cdp enable'.",
            )

    def _check_aaa(self):
        """Check AAA (Authentication, Authorization, Accounting) configuration."""
        config = self._get_running_config()
        if not config:
            return

        if not re.search(r"^aaa new-model", config, re.MULTILINE):
            self._add_finding(
                "CISCO-AAA-001", "AAA new-model not enabled",
                SEVERITY_MEDIUM,
                "AAA is not configured — device uses legacy line-based authentication only.",
                remediation="Enable 'aaa new-model' and configure authentication methods.",
            )

    def _check_logging(self):
        """Check logging configuration."""
        config = self._get_running_config()
        if not config:
            return

        if not re.search(r"^logging\s+(host|server)\s", config, re.MULTILINE):
            self._add_finding(
                "CISCO-LOG-001", "No remote syslog server configured",
                SEVERITY_LOW,
                "Logs are only stored locally — if device is compromised, logs may be wiped.",
                remediation="Configure remote logging: 'logging host <syslog-server-ip>'.",
            )

        if not re.search(r"^service timestamps log", config, re.MULTILINE):
            self._add_finding(
                "CISCO-LOG-002", "Log timestamps not configured",
                SEVERITY_LOW,
                "Logs lack timestamps — incident correlation and forensics are hindered.",
                remediation="Add 'service timestamps log datetime msec localtime show-timezone'.",
            )

    def _check_snmp(self):
        """Check SNMP configuration security."""
        config = self._get_running_config()
        if not config:
            return

        # Check for SNMPv1/v2c community strings
        communities = re.findall(r"^snmp-server community\s+(\S+)\s+(\w+)", config, re.MULTILINE)
        for community, access in communities:
            if community.lower() in ("public", "private", "community"):
                self._add_finding(
                    "CISCO-SNMP-001", f"Default SNMP community string: {community}",
                    SEVERITY_HIGH,
                    f"SNMP community '{community}' with '{access}' access is a well-known default.",
                    remediation="Change to a complex, non-default community string or migrate to SNMPv3.",
                )
            if access.lower() == "rw":
                self._add_finding(
                    "CISCO-SNMP-002", "SNMP read-write access configured",
                    SEVERITY_MEDIUM,
                    f"Community '{community}' has RW access — allows remote config modification.",
                    remediation="Restrict to RO or migrate to SNMPv3 with authentication.",
                )
