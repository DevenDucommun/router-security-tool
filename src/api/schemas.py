from pydantic import BaseModel, Field
from typing import Optional, Any
from enum import Enum


class ScanRequest(BaseModel):
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None


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


class ScanHistoryEntry(BaseModel):
    id: int
    target: str
    scan_timestamp: str
    risk_score: float
    vulnerability_count: int
    risk_level: str
    device_vendor: str = ""
    device_model: str = ""


class HistoryStats(BaseModel):
    total_scans: int = 0
    unique_targets: int = 0
    total_vulnerabilities: int = 0
    avg_risk_score: float = 0.0
    risk_distribution: dict[str, int] = Field(default_factory=dict)


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
