from pydantic import BaseModel, Field, field_validator
from typing import Optional, Any
from enum import Enum


class ScanRequest(BaseModel):
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None


MAX_VERIFY_IDS = 50


class VerifyRequest(BaseModel):
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    check_ids: list[str] = Field(min_length=1, max_length=MAX_VERIFY_IDS)

    @field_validator("check_ids")
    @classmethod
    def clean_ids(cls, ids: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(i.strip() for i in ids if i and i.strip()))
        if not cleaned:
            raise ValueError("check_ids must contain at least one finding ID")
        if any(len(i) > 64 for i in cleaned):
            raise ValueError("finding IDs must be at most 64 characters")
        return cleaned


class VerifyStatus(str, Enum):
    resolved = "resolved"
    still_failing = "still_failing"
    unknown = "unknown"


class VerifyItem(BaseModel):
    id: str
    status: VerifyStatus
    title: str = ""


class Severity(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    info = "Info"


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""


class DeviceInfo(BaseModel):
    hostname: str = ""
    uname: str = ""
    firmware_version: str = ""
    uptime: str = ""
    os_release: str = ""


class ScanResult(BaseModel):
    target: str
    profile: str = "generic"
    device_info: DeviceInfo = Field(default_factory=DeviceInfo)
    findings: list[Finding] = Field(default_factory=list)
    severity_summary: dict[str, int] = Field(default_factory=dict)
    risk_score: float = 0.0
    scan_duration: float = 0.0


class VerifyResult(BaseModel):
    target: str
    profile: Optional[str] = None
    results: list[VerifyItem] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    checks_run: list[str] = Field(default_factory=list)
    scan_duration: float = 0.0


class ScanHistoryEntry(BaseModel):
    id: int
    target: str
    scan_timestamp: str
    risk_score: float
    vulnerability_count: int
    risk_level: str
    device_vendor: str = ""
    device_model: str = ""
    tags: list[str] = Field(default_factory=list)
    notes: str = ""


MAX_TAGS = 10
MAX_TAG_LENGTH = 32
MAX_NOTES_LENGTH = 2000


class ScanAnnotationUpdate(BaseModel):
    """Partial update: omitted fields are left unchanged."""

    tags: Optional[list[str]] = None
    notes: Optional[str] = Field(default=None, max_length=MAX_NOTES_LENGTH)

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, tags: Optional[list[str]]) -> Optional[list[str]]:
        if tags is None:
            return None
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in tags:
            tag = " ".join(raw.split())
            if not tag:
                continue
            if len(tag) > MAX_TAG_LENGTH:
                raise ValueError(f"tags must be at most {MAX_TAG_LENGTH} characters")
            if tag.lower() in seen:
                continue
            seen.add(tag.lower())
            cleaned.append(tag)
        if len(cleaned) > MAX_TAGS:
            raise ValueError(f"at most {MAX_TAGS} tags per scan")
        return cleaned


class HistoryStats(BaseModel):
    total_scans: int = 0
    unique_targets: int = 0
    total_vulnerabilities: int = 0
    avg_risk_score: float = 0.0
    risk_distribution: dict[str, int] = Field(default_factory=dict)


class DiffFinding(BaseModel):
    id: str = ""
    title: str = ""
    severity: str = "Info"
    category: str = ""
    remediation: str = ""
    previous_severity: Optional[str] = None
    severity_changed: bool = False


class DiffScanRef(BaseModel):
    id: Optional[int] = None
    target: str = ""
    scan_timestamp: str = ""
    risk_score: float = 0.0
    finding_count: int = 0


class DiffSummary(BaseModel):
    new: int = 0
    resolved: int = 0
    persisting: int = 0
    severity_changed: int = 0
    new_by_severity: dict[str, int] = Field(default_factory=dict)
    resolved_by_severity: dict[str, int] = Field(default_factory=dict)


class ScanDiff(BaseModel):
    base: DiffScanRef
    head: DiffScanRef
    risk_delta: float = 0.0
    new: list[DiffFinding] = Field(default_factory=list)
    resolved: list[DiffFinding] = Field(default_factory=list)
    persisting: list[DiffFinding] = Field(default_factory=list)
    summary: DiffSummary = Field(default_factory=DiffSummary)


class DiscoveredDevice(BaseModel):
    ip: str = ""
    port: int = 22
    type: str = "network"
    description: str = ""
    device: str = ""
    likely_router: bool = False


class DeviceDiscovery(BaseModel):
    devices: list[DiscoveredDevice] = Field(default_factory=list)


class FilesystemRequest(BaseModel):
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None


class FilesystemResult(BaseModel):
    file_structure: dict[str, Any] = Field(default_factory=dict)
    interesting_files: list[dict[str, Any]] = Field(default_factory=list)
    security_findings: list[dict[str, Any]] = Field(default_factory=list)
