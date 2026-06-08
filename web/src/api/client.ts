import type {
  ScanResult,
  ScanHistoryEntry,
  HistoryStats,
  DiscoveredDevice,
  FilesystemResult,
} from "../types";

const BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || `Request failed: ${response.status}`);
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

  devices: () =>
    request<{ devices: DiscoveredDevice[] }>("/devices"),

  history: (limit = 50, target?: string, riskLevel?: string) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (target) params.set("target", target);
    if (riskLevel) params.set("risk_level", riskLevel);
    return request<ScanHistoryEntry[]>(`/history?${params}`);
  },

  historyStats: () => request<HistoryStats>("/history/stats"),

  getScan: (id: number) => request<ScanResult>(`/history/${id}`),

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
