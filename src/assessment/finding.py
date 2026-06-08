"""Security finding data class — shared by the assessor and all profiles."""

from typing import Dict

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
