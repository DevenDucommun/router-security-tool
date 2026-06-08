export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence: string;
  remediation: string;
}

export interface DeviceInfo {
  hostname: string;
  uname: string;
  firmware_version: string;
  uptime: string;
  os_release: string;
}

export interface ScanResult {
  target: string;
  profile: string;
  device_info: DeviceInfo;
  findings: Finding[];
  severity_summary: Record<string, number>;
  risk_score: number;
  scan_duration: number;
}

export interface ScanHistoryEntry {
  id: number;
  target: string;
  scan_timestamp: string;
  risk_score: number;
  vulnerability_count: number;
  risk_level: string;
  device_vendor: string;
  device_model: string;
}

export interface HistoryStats {
  total_scans: number;
  unique_targets: number;
  total_vulnerabilities: number;
  avg_risk_score: number;
  risk_distribution: Record<string, number>;
}

export interface DiscoveredDevice {
  ip: string;
  port: number;
  type: string;
  description: string;
  device: string;
  likely_router: boolean;
}

export interface FilesystemResult {
  file_structure: Record<string, unknown[]>;
  interesting_files: Array<{ path: string; reason: string }>;
  security_findings: Array<{ severity: string; description: string; file?: string }>;
}

export interface WSMessage {
  type: "progress" | "result" | "error";
  message?: string;
  data?: ScanResult;
}
