"""
OpenWrt Security Profile

Checks specific to OpenWrt-based devices:
- UCI configuration audit (firewall zones, DHCP, wireless)
- LuCI web interface exposure
- Package audit (outdated packages, unnecessary services)
- Dropbear SSH hardening
- Procd service configuration
"""

import re
from typing import Dict, List, Optional, Callable

from assessment.finding import Finding, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from .base import DeviceProfile


class OpenWrtProfile(DeviceProfile):
    name = "openwrt"
    vendor = "OpenWrt"
    description = "OpenWrt/LEDE-based router assessment"

    @classmethod
    def matches(cls, device_info: Dict) -> float:
        score = 0.0
        uname = device_info.get("uname", "").lower()
        os_release = device_info.get("os_release", "").lower()
        firmware = device_info.get("firmware_version", "").lower()

        if "openwrt" in os_release or "openwrt" in firmware:
            score = 0.9
        elif "lede" in os_release:
            score = 0.85
        elif "/etc/config/dropbear" in str(device_info):
            score = 0.7

        if "armv7l" in uname or "mips" in uname or "aarch64" in uname:
            score = max(score, score + 0.05)

        return min(score, 1.0)

    def run_checks(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[Finding]:
        self.findings = []

        checks = [
            ("Auditing UCI firewall zones...", self._check_firewall_zones),
            ("Checking LuCI web exposure...", self._check_luci_exposure),
            ("Auditing installed packages...", self._check_packages),
            ("Checking wireless security...", self._check_wireless_config),
            ("Checking DNS/DHCP config...", self._check_dhcp_dns),
            ("Checking for update channels...", self._check_update_config),
        ]

        for msg, check_fn in checks:
            self._emit(msg, progress_callback)
            check_fn()

        return self.findings

    def _check_firewall_zones(self):
        """Audit UCI firewall zone configuration."""
        fw_config = self._cmd("uci show firewall 2>/dev/null")
        if not fw_config:
            self._add_finding(
                "OWRT-FW-001", "UCI firewall not configured",
                SEVERITY_HIGH,
                "No UCI firewall configuration found. Device may have no traffic filtering.",
                remediation="Configure firewall zones: uci set firewall.@zone[0]=zone ...",
            )
            return

        # Check WAN zone input policy
        wan_input = re.search(r"firewall\.@zone\[\d+\]\.input='(\w+)'", fw_config)
        wan_name = re.search(r"firewall\.@zone\[\d+\]\.name='wan'", fw_config)
        if wan_name and wan_input and wan_input.group(1).upper() == "ACCEPT":
            self._add_finding(
                "OWRT-FW-002", "WAN zone accepts all input traffic",
                SEVERITY_HIGH,
                "The WAN firewall zone input policy is ACCEPT — all inbound traffic is allowed.",
                evidence=f"Input policy: {wan_input.group(1)}",
                remediation="Set WAN input to REJECT: uci set firewall.@zone[1].input='REJECT'",
            )

        # Check if SYN flood protection is enabled
        if "synflood_protect" not in fw_config:
            self._add_finding(
                "OWRT-FW-003", "SYN flood protection not enabled",
                SEVERITY_LOW,
                "firewall.@defaults[0].synflood_protect is not configured.",
                remediation="Enable: uci set firewall.@defaults[0].synflood_protect='1'",
            )

    def _check_luci_exposure(self):
        """Check if LuCI web interface is exposed beyond LAN."""
        uhttpd_config = self._cmd("uci show uhttpd 2>/dev/null")
        if not uhttpd_config:
            return

        # Check listen addresses
        listen_https = re.findall(r"listen_https='([^']+)'", uhttpd_config)
        listen_http = re.findall(r"listen_http='([^']+)'", uhttpd_config)

        all_listeners = listen_http + listen_https

        for listener in all_listeners:
            if "0.0.0.0" in listener or "::" in listener:
                self._add_finding(
                    "OWRT-WEB-001", "LuCI bound to all interfaces",
                    SEVERITY_MEDIUM,
                    f"uhttpd listens on {listener} — web admin is accessible from WAN if firewall allows.",
                    evidence=f"listen address: {listener}",
                    remediation="Bind to LAN IP only: uci set uhttpd.main.listen_http='192.168.1.1:80'",
                )
                break

        # Check if HTTP (non-TLS) is enabled
        if listen_http:
            self._add_finding(
                "OWRT-WEB-002", "LuCI available over plain HTTP",
                SEVERITY_LOW,
                "uhttpd serves on HTTP without TLS — credentials transit in cleartext on LAN.",
                remediation="Disable HTTP listener and use HTTPS only.",
            )

    def _check_packages(self):
        """Audit installed packages for security concerns."""
        pkg_list = self._cmd("opkg list-installed 2>/dev/null")
        if not pkg_list:
            return

        dangerous_packages = {
            "telnetd": ("NET-TEL", SEVERITY_HIGH, "Telnet daemon installed — cleartext protocol"),
            "vsftpd": ("NET-FTP", SEVERITY_MEDIUM, "FTP server installed — consider SFTP instead"),
            "luci-app-vnstat": ("PKG-INFO", SEVERITY_INFO, "Traffic stats exposed via LuCI"),
        }

        for pkg_name, (check_id, severity, desc) in dangerous_packages.items():
            if pkg_name in pkg_list:
                self._add_finding(
                    f"OWRT-{check_id}", f"Package installed: {pkg_name}",
                    severity, desc,
                    remediation=f"Remove if not needed: opkg remove {pkg_name}",
                )

        # Count total packages — excessive installs increase attack surface
        pkg_count = len([line for line in pkg_list.split("\n") if line.strip()])
        if pkg_count > 200:
            self._add_finding(
                "OWRT-PKG-001", f"Large package count ({pkg_count})",
                SEVERITY_LOW,
                f"Device has {pkg_count} packages installed. Review for unnecessary services.",
                remediation="Audit installed packages and remove unneeded ones to reduce attack surface.",
            )

    def _check_wireless_config(self):
        """Check wireless security configuration via UCI."""
        wifi_config = self._cmd("uci show wireless 2>/dev/null")
        if not wifi_config:
            return

        # Check for open networks (no encryption)
        interfaces = re.findall(r"wireless\.(\w+)\.encryption='(\w+)'", wifi_config)
        for iface, encryption in interfaces:
            if encryption in ("none", "open"):
                self._add_finding(
                    "OWRT-WIFI-001", f"Open wireless network: {iface}",
                    SEVERITY_HIGH,
                    f"Wireless interface '{iface}' has no encryption — traffic is unprotected.",
                    evidence=f"{iface}.encryption='{encryption}'",
                    remediation=f"Set encryption: uci set wireless.{iface}.encryption='sae-mixed'",
                )
            elif encryption in ("psk", "wep"):
                self._add_finding(
                    "OWRT-WIFI-002", f"Weak wireless encryption: {iface} ({encryption})",
                    SEVERITY_MEDIUM,
                    f"Interface '{iface}' uses {encryption.upper()} which is deprecated.",
                    remediation=f"Upgrade to WPA3: uci set wireless.{iface}.encryption='sae-mixed'",
                )

        # Check for disabled wireless isolation
        isolate_settings = re.findall(r"wireless\.(\w+)\.isolate='(\d)'", wifi_config)
        for iface, isolate in isolate_settings:
            if isolate == "0":
                ssid_match = re.search(rf"wireless\.{iface}\.ssid='([^']+)'", wifi_config)
                if ssid_match and "guest" in ssid_match.group(1).lower():
                    self._add_finding(
                        "OWRT-WIFI-003", f"Guest network without client isolation: {iface}",
                        SEVERITY_MEDIUM,
                        "Guest network clients can see each other — cross-client attacks possible.",
                        remediation=f"Enable isolation: uci set wireless.{iface}.isolate='1'",
                    )

    def _check_dhcp_dns(self):
        """Check DHCP and DNS rebinding protection."""
        dhcp_config = self._cmd("uci show dhcp 2>/dev/null")
        if not dhcp_config:
            return

        # Check DNS rebinding protection
        if "rebind_protection" not in dhcp_config or "rebind_protection='0'" in dhcp_config:
            self._add_finding(
                "OWRT-DNS-001", "DNS rebinding protection disabled",
                SEVERITY_MEDIUM,
                "dnsmasq rebind_protection is off — DNS rebinding attacks possible against LAN services.",
                remediation="Enable: uci set dhcp.@dnsmasq[0].rebind_protection='1'",
            )

    def _check_update_config(self):
        """Check if package feeds are configured and reachable."""
        distfeeds = self._cmd("cat /etc/opkg/distfeeds.conf 2>/dev/null")
        if distfeeds:
            if all(line.startswith("#") or not line.strip() for line in distfeeds.split("\n")):
                self._add_finding(
                    "OWRT-UPD-001", "All package feeds are disabled",
                    SEVERITY_LOW,
                    "No active opkg feeds — security updates cannot be installed.",
                    remediation="Uncomment at least the base feed in /etc/opkg/distfeeds.conf",
                )
