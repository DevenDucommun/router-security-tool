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
  dropbear_version?: string;
  busybox_version?: string;
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

export type VerifyStatus = "resolved" | "still_failing" | "unknown";

export interface VerifyItem {
  id: string;
  status: VerifyStatus;
  title: string;
}

export interface VerifyResult {
  target: string;
  profile: string | null;
  results: VerifyItem[];
  findings: Finding[];
  checks_run: string[];
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
  tags: string[];
  notes: string;
}

export interface ScanAnnotationUpdate {
  tags?: string[];
  notes?: string;
}

export interface HistoryStats {
  total_scans: number;
  unique_targets: number;
  total_vulnerabilities: number;
  avg_risk_score: number;
  risk_distribution: Record<string, number>;
}

export interface DiffFinding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  remediation: string;
  previous_severity: Severity | null;
  severity_changed: boolean;
}

export interface DiffScanRef {
  id: number | null;
  target: string;
  scan_timestamp: string;
  risk_score: number;
  finding_count: number;
}

export interface ScanDiff {
  base: DiffScanRef;
  head: DiffScanRef;
  risk_delta: number;
  new: DiffFinding[];
  resolved: DiffFinding[];
  persisting: DiffFinding[];
  summary: {
    new: number;
    resolved: number;
    persisting: number;
    severity_changed: number;
    new_by_severity: Record<string, number>;
    resolved_by_severity: Record<string, number>;
  };
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

export interface TargetPreview {
  targets: string[];
  errors: string[];
  count: number;
  max_targets: number;
}

export type BatchTargetStatus = "queued" | "running" | "done" | "error";

export interface BatchTarget {
  target: string;
  status: BatchTargetStatus;
  lastMessage?: string;
  result?: ScanResult;
  scanId?: number | null;
  error?: string;
}

export interface BatchSummary {
  total: number;
  succeeded: number;
  failed: number;
  risk_levels: Record<string, number>;
  highest_risk: Array<{ target: string; risk_score: number; risk_level: string; finding_count: number }>;
  common_findings: Array<{ id: string; title: string; severity: Severity; devices: number }>;
}

export interface WSMessage {
  type: "progress" | "result" | "error";
  message?: string;
  data?: ScanResult;
  scan_id?: number | null;
}

export interface KnownCve {
  id: string;
  score: number | null;
  severity: string;
  published: string;
  description: string;
  known_exploited: boolean;
  url: string;
}

export interface CveComponent {
  key: string;
  name: string;
  vendor: string;
  product: string;
  version: string;
  source: string;
  cpe: string;
  critical_only: boolean;
  looked_up: boolean;
  stale: boolean;
  fetched_at: string | null;
  total: number;
  critical: number;
  high: number;
  known_exploited: number;
  max_score: number | null;
  cves: KnownCve[];
}

export interface CveReport {
  scan_id: number;
  target: string;
  status: "ok" | "partial" | "unavailable" | "no_components";
  components: CveComponent[];
  summary: {
    total: number;
    critical: number;
    high: number;
    known_exploited: number;
    max_score: number | null;
    unpatched_critical: boolean;
  };
  errors: string[];
  checked_at: string;
  kernel_available: boolean;
  kernel_included: boolean;
}

export type ScheduleStatus = "never" | "running" | "ok" | "error";

export interface Schedule {
  id: number;
  name: string;
  target: string;
  port: number;
  username: string;
  interval_minutes: number;
  enabled: boolean;
  tags: string[];
  next_run_at: string;
  last_run_at: string | null;
  last_status: ScheduleStatus;
  last_scan_id: number | null;
  last_error: string | null;
  last_risk_score: number | null;
  running: boolean;
  created_at: string;
  has_credential: boolean;
}

export interface SchedulerStatus {
  enabled: boolean;
  running: boolean;
  poll_seconds: number;
  key_source: "env" | "file" | "not_created";
  schedules: Schedule[];
}

export interface ScheduleCreate {
  target: string;
  port: number;
  username: string;
  password: string;
  interval_minutes: number;
  name?: string;
  tags?: string[];
  enabled?: boolean;
  run_immediately?: boolean;
}

export type ScheduleUpdate = Partial<Omit<ScheduleCreate, "target" | "run_immediately">>;
