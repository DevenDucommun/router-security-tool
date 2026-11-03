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


SCHEDULE_PRESETS = {"hourly": 60, "daily": 24 * 60, "weekly": 7 * 24 * 60}


def _validate_schedule_tags(tags):
    if tags is None:
        return tags
    cleaned = []
    for t in tags:
        t = t.strip()
        if not t:
            continue
        if len(t) > 32:
            raise ValueError("Tags must be 32 characters or fewer")
        if t not in cleaned:
            cleaned.append(t)
    if len(cleaned) > 9:  # the "scheduled" tag is always added
        raise ValueError("At most 9 tags per schedule")
    return cleaned


def _validate_interval(v):
    from database.schedules import MAX_INTERVAL_MINUTES, MIN_INTERVAL_MINUTES

    if v is not None and not (MIN_INTERVAL_MINUTES <= v <= MAX_INTERVAL_MINUTES):
        raise ValueError(
            f"Interval must be between {MIN_INTERVAL_MINUTES} minutes and {MAX_INTERVAL_MINUTES // 1440} days"
        )
    return v


class ScheduleCreate(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="root", min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    interval_minutes: int = 24 * 60
    name: str = Field(default="", max_length=80)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    run_immediately: bool = False

    @field_validator("target")
    @classmethod
    def _target(cls, v: str) -> str:
        v = v.strip()
        if not v or any(c.isspace() for c in v) or "/" in v:
            raise ValueError("Target must be a single host name or IP address")
        return v

    @field_validator("tags")
    @classmethod
    def _tags(cls, v):
        return _validate_schedule_tags(v)

    @field_validator("interval_minutes")
    @classmethod
    def _interval(cls, v):
        return _validate_interval(v)


class ScheduleUpdate(BaseModel):
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = Field(default=None, min_length=1, max_length=64)
    password: Optional[str] = Field(default=None, min_length=1, max_length=256)
    interval_minutes: Optional[int] = None
    name: Optional[str] = Field(default=None, max_length=80)
    tags: Optional[list[str]] = None
    enabled: Optional[bool] = None

    @field_validator("tags")
    @classmethod
    def _tags(cls, v):
        return _validate_schedule_tags(v)

    @field_validator("interval_minutes")
    @classmethod
    def _interval(cls, v):
        return _validate_interval(v)


class ScheduleOut(BaseModel):
    """A schedule as returned by the API. The password is never included."""

    id: int
    name: str = ""
    target: str
    port: int
    username: str
    interval_minutes: int
    enabled: bool
    tags: list[str] = Field(default_factory=list)
    next_run_at: str
    last_run_at: Optional[str] = None
    last_status: str = "never"  # never | running | ok | error
    last_scan_id: Optional[int] = None
    last_error: Optional[str] = None
    last_risk_score: Optional[float] = None
    running: bool = False
    created_at: str
    has_credential: bool = True


class SchedulerStatus(BaseModel):
    enabled: bool
    running: bool
    poll_seconds: float
    key_source: str  # env | file | not_created
    schedules: list[ScheduleOut] = Field(default_factory=list)
