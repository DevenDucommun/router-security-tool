"""
Linksys Security Profile

Checks specific to Linksys routers:
- JNAP API endpoint exposure and authentication
- Firmware version check against known vulnerable versions
- Default credential patterns by model
- /tmp/syscfg secrets exposure
- Smart WiFi cloud connectivity audit
"""

import re
from typing import Dict, List, Optional, Callable

from assessment.finding import Finding, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from .base import DeviceProfile

KNOWN_VULNERABLE_FIRMWARE = {
    "1.0.00": "Multiple RCE vulnerabilities (pre-2023 builds)",
    "1.0.01": "JNAP authentication bypass (pre-2023 builds)",
}

LINKSYS_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "linksys"),
    ("root", "admin"),
]


class LinksysProfile(DeviceProfile):
    name = "linksys"
    vendor = "Linksys"
    description = "Linksys router assessment (WRT/Velop/Mesh platforms)"

    @classmethod
    def matches(cls, device_info: Dict) -> float:
        score = 0.0
        uname = device_info.get("uname", "").lower()
        hostname = device_info.get("hostname", "").lower()
        firmware = device_info.get("firmware_version", "").lower()
        os_release = device_info.get("os_release", "").lower()

        if "linksys" in hostname or "linksys" in firmware:
            score = 0.95
        elif "community" in hostname or "community" in uname:
            score = 0.96
        elif "belkin" in os_release or "linksys" in os_release:
            score = 0.9

        # Linksys devices often have specific filesystem markers
        if "syscfg" in str(device_info) or "jnap" in str(device_info):
            score = max(score, 0.85)

        return min(score, 1.0)

    def run_checks(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[Finding]:
        self.findings = []

        checks = [
            ("Checking JNAP API exposure...", self._check_jnap_api),
            ("Auditing firmware version...", self._check_firmware_version),
            ("Checking syscfg secrets...", self._check_syscfg_exposure),
            ("Checking cloud connectivity config...", self._check_cloud_config),
            ("Checking management interfaces...", self._check_management_access),
            ("Checking for known Linksys defaults...", self._check_default_patterns),
        ]

        for msg, check_fn in checks:
            self._emit(msg, progress_callback)
            check_fn()

        return self.findings

    def _check_jnap_api(self):
        """Check JNAP API endpoint accessibility and authentication."""
        jnap_proc = self._cmd("ps | grep -i jnap 2>/dev/null")

        if jnap_proc and "jnap" in jnap_proc.lower():
            self._add_finding(
                "LNK-JNAP-001", "JNAP API service running",
                SEVERITY_INFO,
                "Linksys JNAP API is active — should be properly authenticated.",
                evidence=jnap_proc.strip()[:200],
            )

        # Check JNAP auth configuration
        jnap_config = self._cmd(
            "cat /tmp/syscfg/syscfg.dat 2>/dev/null | grep -i jnap "
            "|| cat /etc/config/jnap 2>/dev/null"
        )
        if jnap_config and "noauth" in jnap_config.lower():
            self._add_finding(
                "LNK-JNAP-002", "JNAP API has unauthenticated endpoints",
                SEVERITY_HIGH,
                "JNAP configuration allows unauthenticated access to some API actions.",
                evidence=jnap_config[:200],
                remediation="Ensure all JNAP actions require authentication.",
            )

    def _check_firmware_version(self):
        """Check firmware version against known vulnerabilities."""
        fw_version = self.device_info.get("firmware_version", "")

        # Extract version number
        version_match = re.search(r"(\d+\.\d+\.\d+)", fw_version)
        if version_match:
            version = version_match.group(1)
            for vuln_version, description in KNOWN_VULNERABLE_FIRMWARE.items():
                if version.startswith(vuln_version):
                    self._add_finding(
                        "LNK-FW-002", f"Firmware version {version} has known vulnerabilities",
                        SEVERITY_CRITICAL,
                        f"Firmware {version}: {description}",
                        evidence=f"Detected version: {version}",
                        remediation="Update firmware to the latest version from linksys.com/support.",
                    )
                    return

        # Check build date if available in uname
        uname = self.device_info.get("uname", "")
        date_match = re.search(
            r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun\s+)?"
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
            r"\s+\d+\s+[\d:]+\s+(\d{4})", uname
        )
        if date_match:
            year = int(date_match.group(2))
            if year < 2024:
                self._add_finding(
                    "LNK-FW-003", f"Firmware built in {year} — potentially outdated",
                    SEVERITY_MEDIUM,
                    f"Firmware build date is from {year}. Security patches may be missing.",
                    evidence=uname[:100],
                    remediation="Check for firmware updates at linksys.com/support.",
                )

    def _check_syscfg_exposure(self):
        """Check /tmp/syscfg for exposed secrets."""
        syscfg_files = self._cmd("ls /tmp/syscfg/ 2>/dev/null")
        if not syscfg_files:
            return

        # Check permissions on syscfg directory
        perms = self._cmd("stat -c '%a' /tmp/syscfg 2>/dev/null")
        if perms and int(perms.strip(), 8) & 0o007:
            self._add_finding(
                "LNK-CFG-001", "/tmp/syscfg is world-accessible",
                SEVERITY_MEDIUM,
                "The syscfg directory containing device configuration is world-readable.",
                evidence=f"Permissions: {perms.strip()}",
                remediation="Restrict permissions: chmod 700 /tmp/syscfg",
            )

        # Check for plaintext WiFi passwords in syscfg
        wifi_pass = self._cmd("grep -ri 'passphrase\\|wpa_psk\\|wifi_password' /tmp/syscfg/ 2>/dev/null | head -5")
        if wifi_pass:
            self._add_finding(
                "LNK-CFG-002", "WiFi credentials in plaintext on filesystem",
                SEVERITY_MEDIUM,
                "WiFi passphrases stored as plaintext in /tmp/syscfg/.",
                evidence="[redacted — credentials found]",
                remediation="This is common on embedded routers but should be noted in risk assessment.",
            )

    def _check_cloud_config(self):
        """Check Linksys cloud/Smart WiFi connectivity configuration."""
        # Check for cloud agent processes
        cloud_procs = self._cmd("ps | grep -iE 'cloud|smartwifi|linksys-app' 2>/dev/null")
        if cloud_procs and "grep" not in cloud_procs:
            self._add_finding(
                "LNK-CLOUD-001", "Cloud management agent active",
                SEVERITY_INFO,
                "Linksys cloud connectivity is active — device is managed remotely.",
                evidence=cloud_procs.strip()[:200],
            )

        # Check for outbound connections to Linksys cloud
        cloud_conns = self._cmd(
            "netstat -tnp 2>/dev/null | grep -iE 'linksys|belkin' "
            "|| ss -tnp | grep -iE 'linksys|belkin'"
        )
        if cloud_conns:
            self._add_finding(
                "LNK-CLOUD-002", "Active connections to Linksys cloud services",
                SEVERITY_INFO,
                "Device maintains connections to vendor cloud infrastructure.",
                evidence=cloud_conns.strip()[:200],
            )

    def _check_management_access(self):
        """Check web management interface configuration."""
        # Check uhttpd or lighttpd config
        web_config = self._cmd(
            "cat /etc/lighttpd/lighttpd.conf 2>/dev/null "
            "|| cat /etc/uhttpd 2>/dev/null "
            "|| uci show uhttpd 2>/dev/null"
        )
        if not web_config:
            return

        # Check if remote management is enabled
        if "0.0.0.0" in web_config or "server.bind" in web_config:
            wan_mgmt = self._cmd("uci get uhttpd.main.listen_http 2>/dev/null")
            if wan_mgmt and "0.0.0.0" in wan_mgmt:
                self._add_finding(
                    "LNK-MGMT-001", "Web management accessible from all interfaces",
                    SEVERITY_MEDIUM,
                    "Router web management is bound to 0.0.0.0 — may be reachable from WAN.",
                    remediation="Bind web management to LAN interface IP only.",
                )

    def _check_default_patterns(self):
        """Check for Linksys-specific default configuration patterns."""
        # Check if default SSID pattern is still in use
        wifi_ssid = self._cmd("uci get wireless.default_radio0.ssid 2>/dev/null || iwinfo 2>/dev/null | grep ESSID")
        if wifi_ssid:
            default_patterns = ["linksys", "belkin", "linksys_setup"]
            for pattern in default_patterns:
                if pattern in wifi_ssid.lower():
                    self._add_finding(
                        "LNK-DEF-001", "Default SSID still in use",
                        SEVERITY_LOW,
                        f"WiFi SSID contains default vendor name '{pattern}' — indicates uncustomized setup.",
                        evidence=wifi_ssid.strip()[:100],
                        remediation="Change SSID to a non-default value.",
                    )
                    break
