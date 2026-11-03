"""
Base class for device-specific security profiles.

Each profile encapsulates vendor/platform-specific knowledge:
which commands to run, what configuration patterns are dangerous,
known default credentials, and platform-specific vulnerabilities.
"""

from abc import ABC, abstractmethod
from typing import Dict, Iterable, List, Optional, Callable, Set, Tuple

from assessment.finding import Finding

# (progress message, method name, finding-ID families the method can emit)
CheckSpec = Tuple[str, str, Tuple[str, ...]]


def finding_family(check_id: str) -> str:
    """Family of a finding ID: the ID without its numeric suffix (OWRT-FW-002 -> OWRT-FW)."""
    head, sep, tail = check_id.rpartition("-")
    return head if sep and tail[:1].isdigit() else check_id


class DeviceProfile(ABC):
    """Abstract base for device-specific security assessment profiles."""

    name: str = "generic"
    vendor: str = "unknown"
    description: str = ""
    CHECKS: List[CheckSpec] = []

    def __init__(self, cmd_runner: Callable[[str], str], device_info: Dict):
        self._cmd = cmd_runner
        self.device_info = device_info
        self.findings: List[Finding] = []

    @classmethod
    def families(cls) -> Set[str]:
        return {family for _, _, fams in cls.CHECKS for family in fams}

    def run_checks(
        self,
        progress_callback: Optional[Callable[[str], None]] = None,
        only_families: Optional[Iterable[str]] = None,
    ) -> List[Finding]:
        """Run profile checks (all, or only those emitting the given families)."""
        self.findings = []
        wanted = set(only_families) if only_families is not None else None

        for msg, method_name, fams in self.CHECKS:
            if wanted is not None and not wanted.intersection(fams):
                continue
            self._emit(msg, progress_callback)
            getattr(self, method_name)()

        return self.findings

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
