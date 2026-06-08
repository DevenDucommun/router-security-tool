"""
SSH Assessment Engine
Performs live security assessment of a connected device over SSH.
Runs categorized checks and emits findings progressively.
"""

import logging
import re
from typing import Dict, List, Optional, Callable

from connections.manager import ConnectionManager

logger = logging.getLogger(__name__)

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"


class Finding:
    """A single security finding from an assessment check."""

    def __init__(
        self,
        check_id: str,
        title: str,
        severity: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
    ):
        self.check_id = check_id
        self.title = title
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.remediation = remediation

    def to_dict(self) -> Dict:
        return {
            "id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "type": "SSH Assessment",
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "affected_component": "Device Configuration",
        }


class SSHAssessor:
    """Runs security checks against a live SSH connection."""

    def __init__(self, connection: ConnectionManager):
        self.conn = connection
        self.device_info: Dict = {}
        self.findings: List[Finding] = []

    def run_assessment(
        self, progress_callback: Optional[Callable[[str], None]] = None
    ) -> Dict:
        """Run full assessment. Returns structured results."""
        if not self.conn.is_connected():
            raise ConnectionError("No active SSH connection")

        self.findings = []

        def emit(msg: str):
            if progress_callback:
                progress_callback(msg)
            logger.info(msg)

        emit("Gathering device information...")
        self.device_info = self._gather_device_info()

        checks = [
            ("Checking SSH configuration...", self._check_ssh_config),
            ("Checking for default credentials...", self._check_default_credentials),
            ("Enumerating listening services...", self._check_listening_services),
            ("Auditing file permissions...", self._check_file_permissions),
            ("Checking firewall rules...", self._check_firewall),
            ("Scanning for sensitive files...", self._check_sensitive_files),
            ("Analyzing running processes...", self._check_processes),
            ("Checking system hardening...", self._check_system_hardening),
        ]

        for message, check_fn in checks:
            emit(message)
            try:
                check_fn()
            except Exception as e:
                logger.warning(f"Check failed: {check_fn.__name__}: {e}")

        emit(f"Assessment complete. {len(self.findings)} findings.")

        return {
            "device_info": self.device_info,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "severity_summary": self._severity_summary(),
        }

    def _cmd(self, command: str) -> str:
        """Execute a command and return output, empty string on failure."""
        result = self.conn.send_command(command)
        return result.strip() if result else ""

    def _severity_summary(self) -> Dict[str, int]:
        counts = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0, SEVERITY_INFO: 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _gather_device_info(self) -> Dict:
        """Collect basic device information."""
        info: Dict = {}

        uname = self._cmd("uname -a")
        if uname:
            info["uname"] = uname

        hostname = self._cmd("hostname")
        if hostname:
            info["hostname"] = hostname

        os_release = self._cmd("cat /etc/os-release 2>/dev/null || cat /etc/version 2>/dev/null")
        if os_release:
            info["os_release"] = os_release

        uptime = self._cmd("uptime")
        if uptime:
            info["uptime"] = uptime

        # Try to get firmware version (common on routers)
        fw_version = self._cmd(
            "cat /etc/fw_version 2>/dev/null || "
            "cat /etc/openwrt_release 2>/dev/null || "
            "cat /tmp/firmware_version 2>/dev/null || "
            "echo ''"
        )
        if fw_version:
            info["firmware_version"] = fw_version

        return info

    def _check_ssh_config(self):
        """Check SSH daemon configuration for security issues."""
        sshd_config = self._cmd("cat /etc/ssh/sshd_config 2>/dev/null")
        if not sshd_config:
            # Try dropbear (common on embedded/OpenWrt)
            dropbear = self._cmd("cat /etc/config/dropbear 2>/dev/null")
            if dropbear:
                if "option RootPasswordAuth 'on'" in dropbear or "option PasswordAuth 'on'" in dropbear:
                    self.findings.append(Finding(
                        "SSH-001", "Dropbear allows password authentication",
                        SEVERITY_MEDIUM,
                        "Password-based SSH authentication is enabled. Key-based auth is more secure.",
                        evidence=dropbear[:200],
                        remediation="Set 'option PasswordAuth off' in /etc/config/dropbear and use key-based authentication.",
                    ))
                if "option RootLogin '1'" in dropbear:
                    self.findings.append(Finding(
                        "SSH-002", "Root login enabled via SSH",
                        SEVERITY_MEDIUM,
                        "Direct root SSH login is allowed.",
                        remediation="Disable root login and use a regular user with sudo.",
                    ))
            return

        # OpenSSH checks
        if re.search(r"^\s*PermitRootLogin\s+(yes|without-password)", sshd_config, re.MULTILINE):
            self.findings.append(Finding(
                "SSH-001", "Root login permitted via SSH",
                SEVERITY_MEDIUM,
                "sshd_config allows root login.",
                evidence="PermitRootLogin yes",
                remediation="Set 'PermitRootLogin no' in sshd_config.",
            ))

        if re.search(r"^\s*PasswordAuthentication\s+yes", sshd_config, re.MULTILINE):
            self.findings.append(Finding(
                "SSH-002", "Password authentication enabled",
                SEVERITY_LOW,
                "Password-based SSH authentication is enabled alongside key-based auth.",
                remediation="Set 'PasswordAuthentication no' if key-based auth is configured.",
            ))

        if re.search(r"^\s*Protocol\s+1", sshd_config, re.MULTILINE):
            self.findings.append(Finding(
                "SSH-003", "SSH Protocol 1 enabled",
                SEVERITY_CRITICAL,
                "SSH Protocol 1 is cryptographically broken and must not be used.",
                remediation="Remove 'Protocol 1' from sshd_config.",
            ))

        if not re.search(r"^\s*MaxAuthTries\s+[1-4]$", sshd_config, re.MULTILINE):
            self.findings.append(Finding(
                "SSH-004", "SSH MaxAuthTries not restricted",
                SEVERITY_LOW,
                "MaxAuthTries is not set to a low value, making brute-force easier.",
                remediation="Set 'MaxAuthTries 3' in sshd_config.",
            ))

    def _check_default_credentials(self):
        """Check for indicators of default or weak credentials."""
        # Check /etc/shadow for accounts without passwords or known hashes
        shadow = self._cmd("cat /etc/shadow 2>/dev/null")
        if shadow:
            for line in shadow.split("\n"):
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                user, hash_field = parts[0], parts[1]
                if hash_field in ("", "!", "*", "!!"):
                    continue
                # Empty password hash (just the algorithm prefix with no actual hash)
                if hash_field in ("$1$$", "$5$$", "$6$$"):
                    self.findings.append(Finding(
                        "CRED-001", f"Empty password for user '{user}'",
                        SEVERITY_CRITICAL,
                        f"User '{user}' has an empty password hash in /etc/shadow.",
                        remediation=f"Set a strong password for '{user}' or disable the account.",
                    ))

        # Check passwd for UID 0 accounts beyond root
        passwd = self._cmd("cat /etc/passwd 2>/dev/null")
        if passwd:
            uid0_users = []
            for line in passwd.split("\n"):
                parts = line.split(":")
                if len(parts) >= 4 and parts[2] == "0" and parts[0] != "root":
                    uid0_users.append(parts[0])
            if uid0_users:
                self.findings.append(Finding(
                    "CRED-002", "Non-root users with UID 0",
                    SEVERITY_HIGH,
                    f"Users with UID 0 (root equivalent): {', '.join(uid0_users)}",
                    remediation="Remove UID 0 from non-root accounts unless explicitly required.",
                ))

    def _check_listening_services(self):
        """Enumerate services listening on network ports."""
        netstat = self._cmd("netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null")
        if not netstat:
            return

        # Look for services bound to 0.0.0.0 (all interfaces)
        exposed_services = []
        for line in netstat.split("\n"):
            if "0.0.0.0:" in line or ":::*" in line or ":::" in line:
                exposed_services.append(line.strip())

        if exposed_services:
            self.findings.append(Finding(
                "NET-001", f"{len(exposed_services)} services exposed on all interfaces",
                SEVERITY_MEDIUM,
                "Services are bound to 0.0.0.0, making them accessible from any network interface.",
                evidence="\n".join(exposed_services[:10]),
                remediation="Bind management services to localhost or LAN-only interfaces where possible.",
            ))

        # Check for known dangerous services
        dangerous_ports = {"23": "Telnet", "69": "TFTP", "21": "FTP", "513": "rlogin"}
        for port, name in dangerous_ports.items():
            if f":{port} " in netstat or f":{port}\t" in netstat:
                self.findings.append(Finding(
                    f"NET-{port}", f"Insecure service running: {name} (port {port})",
                    SEVERITY_HIGH,
                    f"{name} transmits data in plaintext and should not be used.",
                    remediation=f"Disable {name} and use encrypted alternatives (SSH/SFTP/HTTPS).",
                ))

    def _check_file_permissions(self):
        """Check critical file permissions."""
        checks = [
            ("/etc/shadow", "0640", "PERM-001", "Shadow file permissions too open"),
            ("/etc/passwd", "0644", "PERM-002", "Passwd file permissions too open"),
            ("/etc/ssh/sshd_config", "0600", "PERM-003", "SSH config permissions too open"),
        ]

        for filepath, expected_max, check_id, title in checks:
            stat_out = self._cmd(f"stat -c '%a' {filepath} 2>/dev/null || stat -f '%Lp' {filepath} 2>/dev/null")
            if not stat_out:
                continue
            try:
                actual_perms = int(stat_out.strip(), 8)
                max_perms = int(expected_max, 8)
                if actual_perms > max_perms:
                    self.findings.append(Finding(
                        check_id, title,
                        SEVERITY_MEDIUM,
                        f"{filepath} has permissions {oct(actual_perms)} (expected at most {expected_max}).",
                        remediation=f"Run: chmod {expected_max} {filepath}",
                    ))
            except ValueError:
                pass

        # Check for world-writable directories in PATH
        path_dirs = self._cmd("echo $PATH").split(":")
        for d in path_dirs:
            stat_out = self._cmd(f"stat -c '%a' {d} 2>/dev/null")
            if stat_out:
                try:
                    perms = int(stat_out.strip(), 8)
                    if perms & 0o002:  # World-writable
                        self.findings.append(Finding(
                            "PERM-004", f"World-writable directory in PATH: {d}",
                            SEVERITY_HIGH,
                            f"{d} is world-writable, allowing any user to place malicious binaries.",
                            remediation=f"Run: chmod o-w {d}",
                        ))
                except ValueError:
                    pass

    def _check_firewall(self):
        """Check firewall configuration."""
        # Try iptables first, then nftables, then UCI (OpenWrt)
        iptables = self._cmd("iptables -L -n 2>/dev/null | head -30")
        if iptables and "Chain" in iptables:
            if "ACCEPT" in iptables and "DROP" not in iptables and "REJECT" not in iptables:
                self.findings.append(Finding(
                    "FW-001", "Firewall has no DROP/REJECT rules",
                    SEVERITY_HIGH,
                    "iptables shows only ACCEPT rules — firewall may not be filtering traffic.",
                    evidence=iptables[:300],
                    remediation="Configure DROP policy on INPUT/FORWARD chains and allow only required traffic.",
                ))
            return

        # Check for UCI firewall (OpenWrt)
        uci_fw = self._cmd("uci show firewall 2>/dev/null | head -20")
        if uci_fw:
            if "firewall.@zone" not in uci_fw:
                self.findings.append(Finding(
                    "FW-002", "No firewall zones configured",
                    SEVERITY_HIGH,
                    "UCI firewall has no zone definitions.",
                    remediation="Configure WAN/LAN zones with appropriate forwarding rules.",
                ))
            return

        # No firewall found at all
        self.findings.append(Finding(
            "FW-003", "No firewall detected",
            SEVERITY_CRITICAL,
            "Could not detect iptables, nftables, or UCI firewall configuration.",
            remediation="Install and configure a firewall (iptables/nftables/fw4).",
        ))

    def _check_sensitive_files(self):
        """Look for sensitive data in common locations."""
        # Check for private keys with weak permissions
        key_files = self._cmd(
            "find /etc/ssh/ /root/.ssh/ /home/ -name '*.key' -o -name 'id_*' -o -name '*.pem' 2>/dev/null"
        )
        if key_files:
            for keyfile in key_files.split("\n"):
                keyfile = keyfile.strip()
                if not keyfile:
                    continue
                perms = self._cmd(f"stat -c '%a' {keyfile} 2>/dev/null")
                if perms:
                    try:
                        if int(perms.strip(), 8) > 0o600:
                            self.findings.append(Finding(
                                "FILE-001", f"Private key with weak permissions: {keyfile}",
                                SEVERITY_HIGH,
                                f"{keyfile} has permissions {perms.strip()} (should be 600 or less).",
                                remediation=f"Run: chmod 600 {keyfile}",
                            ))
                    except ValueError:
                        pass

        # Check for plaintext passwords in config files
        config_grep = self._cmd(
            "grep -ril 'password\\|passwd\\|secret' /etc/ 2>/dev/null | head -10"
        )
        if config_grep:
            files_with_passwords = [f.strip() for f in config_grep.split("\n") if f.strip()]
            if files_with_passwords:
                self.findings.append(Finding(
                    "FILE-002", f"Config files may contain plaintext credentials",
                    SEVERITY_MEDIUM,
                    f"Found password-related strings in: {', '.join(files_with_passwords[:5])}",
                    remediation="Review these files and ensure credentials are stored securely or removed.",
                ))

    def _check_processes(self):
        """Analyze running processes for security concerns."""
        ps_output = self._cmd("ps aux 2>/dev/null || ps -ef 2>/dev/null")
        if not ps_output:
            return

        # Check for processes running as root that shouldn't need to
        root_processes = []
        for line in ps_output.split("\n")[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 11 and parts[0] == "root":
                cmd = " ".join(parts[10:])
                root_processes.append(cmd)

        # Flag if excessive root processes
        if len(root_processes) > 20:
            self.findings.append(Finding(
                "PROC-001", f"{len(root_processes)} processes running as root",
                SEVERITY_LOW,
                "A large number of processes run as root. Consider privilege separation.",
                evidence=f"Sample: {'; '.join(root_processes[:5])}",
                remediation="Run services under dedicated unprivileged accounts where possible.",
            ))

    def _check_system_hardening(self):
        """Check basic system hardening measures."""
        # Check kernel parameters
        sysctl_checks = {
            "net.ipv4.ip_forward": ("1", SEVERITY_INFO, "IP forwarding enabled (expected on routers)"),
            "net.ipv4.conf.all.accept_redirects": ("1", SEVERITY_MEDIUM, "ICMP redirects accepted — can be used for MITM"),
            "net.ipv4.conf.all.accept_source_route": ("1", SEVERITY_MEDIUM, "Source routing accepted — can bypass firewall rules"),
        }

        for param, (bad_value, severity, desc) in sysctl_checks.items():
            value = self._cmd(f"sysctl -n {param} 2>/dev/null")
            if value.strip() == bad_value and severity != SEVERITY_INFO:
                self.findings.append(Finding(
                    f"KERN-{param.split('.')[-1][:8].upper()}",
                    f"Insecure kernel parameter: {param}",
                    severity,
                    desc,
                    evidence=f"{param} = {value.strip()}",
                    remediation=f"Set '{param} = 0' in /etc/sysctl.conf and run sysctl -p.",
                ))

        # Check if automatic updates are configured
        auto_update = self._cmd("cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null")
        if not auto_update:
            # OpenWrt doesn't have auto-updates, so only flag on general Linux
            if "ubuntu" in self.device_info.get("os_release", "").lower() or \
               "debian" in self.device_info.get("os_release", "").lower():
                self.findings.append(Finding(
                    "HARD-001", "Automatic security updates not configured",
                    SEVERITY_MEDIUM,
                    "No automatic update configuration found.",
                    remediation="Install and configure unattended-upgrades.",
                ))
