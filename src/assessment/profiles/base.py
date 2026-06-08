"""
Base class for device-specific security profiles.

Each profile encapsulates vendor/platform-specific knowledge:
which commands to run, what configuration patterns are dangerous,
known default credentials, and platform-specific vulnerabilities.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Callable

from assessment.finding import Finding


class DeviceProfile(ABC):
    """Abstract base for device-specific security assessment profiles."""

    name: str = "generic"
    vendor: str = "unknown"
    description: str = ""

    def __init__(self, cmd_runner: Callable[[str], str], device_info: Dict):
        self._cmd = cmd_runner
        self.device_info = device_info
        self.findings: List[Finding] = []

    @abstractmethod
    def run_checks(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[Finding]:
        """Run all profile-specific checks. Returns list of findings."""

    @classmethod
    @abstractmethod
    def matches(cls, device_info: Dict) -> float:
        """Return confidence score 0.0-1.0 that this profile applies to the device."""

    def _emit(self, msg: str, callback: Optional[Callable[[str], None]] = None):
        if callback:
            callback(f"[{self.name}] {msg}")

    def _add_finding(
        self,
        check_id: str,
        title: str,
        severity: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
    ):
        self.findings.append(Finding(
            check_id=check_id,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            remediation=remediation,
        ))
