import type {
  ScanResult,
  ScanHistoryEntry,
  HistoryStats,
  DiscoveredDevice,
  FilesystemResult,
  ScanDiff,
  ScanAnnotationUpdate,
  VerifyResult,
  TargetPreview,
  Schedule,
  SchedulerStatus,
  ScheduleCreate,
  ScheduleUpdate,
} from "../types";

const BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    // Validation errors (422) arrive as a list of {loc, msg}.
    const detail = Array.isArray(error.detail)
      ? error.detail
          .map((d: { loc?: unknown[]; msg?: string }) => {
            const field = d.loc?.slice(1).join(".");
            return field ? `${field}: ${d.msg}` : d.msg;
          })
          .join("; ")
      : error.detail;
    throw new Error(detail || `Request failed: ${response.status}`);
  }

  return response.json();
}

export const api = {
  health: () => request<{ status: string; version: string }>("/health"),

  scan: (host: string, username: string, password: string, port = 22) =>
    request<ScanResult>("/scan", {
      method: "POST",
      body: JSON.stringify({ host, port, username, password }),
    }),

  verify: (host: string, username: string, password: string, port: number, checkIds: string[]) =>
    request<VerifyResult>("/scan/verify", {
      method: "POST",
      body: JSON.stringify({ host, port, username, password, check_ids: checkIds }),
    }),

  previewTargets: (targets: string) =>
    request<TargetPreview>("/targets/parse", { method: "POST", body: JSON.stringify({ targets }) }),

  devices: () =>
    request<{ devices: DiscoveredDevice[] }>("/devices"),

  history: (limit = 50, target?: string, riskLevel?: string, tag?: string) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (target) params.set("target", target);
    if (riskLevel) params.set("risk_level", riskLevel);
    if (tag) params.set("tag", tag);
    return request<ScanHistoryEntry[]>(`/history?${params}`);
  },

  historyStats: () => request<HistoryStats>("/history/stats"),

  historyTags: () => request<string[]>("/history/tags"),

  updateAnnotations: (id: number, update: ScanAnnotationUpdate) =>
    request<ScanHistoryEntry>(`/history/${id}`, {
      method: "PATCH",
      body: JSON.stringify(update),
    }),

  getScan: (id: number) => request<ScanResult>(`/history/${id}`),

  schedules: () => request<SchedulerStatus>("/schedules"),

  createSchedule: (body: ScheduleCreate) =>
    request<Schedule>("/schedules", { method: "POST", body: JSON.stringify(body) }),

  updateSchedule: (id: number, body: ScheduleUpdate) =>
    request<Schedule>(`/schedules/${id}`, { method: "PATCH", body: JSON.stringify(body) }),

  deleteSchedule: (id: number) =>
    request<{ status: string }>(`/schedules/${id}`, { method: "DELETE" }),

  runSchedule: (id: number) =>
    request<Schedule>(`/schedules/${id}/run`, { method: "POST" }),

  diffScans: (base: number, head: number) =>
    request<ScanDiff>(`/history/diff?base=${base}&head=${head}`),

  deleteScan: (id: number) =>
    request<{ status: string }>(`/history/${id}`, { method: "DELETE" }),

  exportScan: (format: "json" | "html" | "pdf", scanId?: number) => {
    const params = scanId ? `?scan_id=${scanId}` : "";
    return fetch(`${BASE}/export/${format}${params}`, { method: "POST" });
  },

  filesystem: (host: string, username: string, password: string, port = 22) =>
    request<FilesystemResult>("/filesystem", {
      method: "POST",
      body: JSON.stringify({ host, port, username, password }),
    }),
};
