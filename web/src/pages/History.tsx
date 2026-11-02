import { Fragment, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Trash2, Download, BarChart3, GitCompare, Tag, StickyNote } from "lucide-react";
import { api } from "../api/client";
import { RiskTrend } from "../components/charts/RiskTrend";
import { AnnotationEditor } from "../components/history/AnnotationEditor";
import type { ScanHistoryEntry, HistoryStats, ScanAnnotationUpdate } from "../types";

export function History() {
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [stats, setStats] = useState<HistoryStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [targetFilter, setTargetFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [tagFilter, setTagFilter] = useState("");
  const [allTags, setAllTags] = useState<string[]>([]);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [showStats, setShowStats] = useState(false);
  const [selected, setSelected] = useState<number[]>([]);
  const navigate = useNavigate();

  const selectedScans = history.filter((s) => selected.includes(s.id));
  const sameTarget =
    selectedScans.length === 2 && selectedScans[0].target === selectedScans[1].target;

  const toggleSelected = (id: number) => {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id].slice(-2),
    );
  };

  const handleCompare = () => {
    if (!sameTarget) return;
    const [older, newer] = [...selectedScans].sort(
      (a, b) => new Date(a.scan_timestamp).getTime() - new Date(b.scan_timestamp).getTime(),
    );
    navigate(`/history/compare?base=${older.id}&head=${newer.id}`);
  };

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      api.history(100, targetFilter || undefined, riskFilter || undefined, tagFilter || undefined),
      api.historyStats(),
      api.historyTags(),
    ])
      .then(([h, s, t]) => {
        if (cancelled) return;
        setHistory(h);
        setStats(s);
        setAllTags(t);
      })
      .catch(() => {
        // silent
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [targetFilter, riskFilter, tagFilter]);

  const handleSaveAnnotations = async (id: number, update: ScanAnnotationUpdate) => {
    const updated = await api.updateAnnotations(id, update);
    setHistory((prev) => prev.map((s) => (s.id === id ? updated : s)));
    setAllTags((prev) =>
      [...new Set([...prev, ...updated.tags])].sort((a, b) => a.localeCompare(b)),
    );
    setEditingId(null);
  };

  const handleDelete = async (id: number) => {
    if (!confirm(`Delete scan #${id}?`)) return;
    try {
      await api.deleteScan(id);
      setHistory((prev) => prev.filter((s) => s.id !== id));
    } catch {
      // silent
    }
  };

  const handleExport = async (id: number, format: "json" | "html" | "pdf") => {
    const res = await api.exportScan(format, id);
    if (res.ok) {
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan_${id}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const uniqueTargets = [...new Set(history.map((s) => s.target))];
  const uniqueRiskLevels = [...new Set(history.map((s) => s.risk_level))].filter(Boolean);

  return (
    <div className="space-y-6 max-w-6xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Scan History</h1>
          <p className="text-sm text-gray-500">
            {stats?.total_scans || 0} scans across {stats?.unique_targets || 0} targets
          </p>
        </div>
        <button
          onClick={() => setShowStats(!showStats)}
          className="flex items-center gap-2 px-3 py-1.5 text-xs text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 rounded-md transition-colors"
        >
          <BarChart3 className="w-3 h-3" />
          {showStats ? "Hide" : "Show"} Trend
        </button>
      </div>

      {showStats && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-sm font-medium text-gray-300 mb-3">Risk Score Over Time</h2>
          <RiskTrend history={history} />
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <select
          value={targetFilter}
          onChange={(e) => setTargetFilter(e.target.value)}
          className="bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:border-emerald-500 focus:outline-none"
        >
          <option value="">All Targets</option>
          {uniqueTargets.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          className="bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:border-emerald-500 focus:outline-none"
        >
          <option value="">All Risk Levels</option>
          {uniqueRiskLevels.map((level) => (
            <option key={level} value={level}>{level}</option>
          ))}
        </select>
        <select
          value={tagFilter}
          onChange={(e) => setTagFilter(e.target.value)}
          className="bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:border-emerald-500 focus:outline-none"
        >
          <option value="">All Tags</option>
          {allTags.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <div className="ml-auto flex items-center gap-3">
          <span className="text-xs text-gray-500">
            {selected.length === 2 && !sameTarget
              ? "Pick two scans of the same target"
              : `${selected.length}/2 selected`}
          </span>
          <button
            onClick={handleCompare}
            disabled={!sameTarget}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors bg-emerald-600 hover:bg-emerald-500 text-white disabled:bg-gray-800 disabled:text-gray-500"
          >
            <GitCompare className="w-3 h-3" />
            Compare
          </button>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <p className="text-gray-500 text-sm">Loading...</p>
      ) : history.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <p className="text-sm">No scan history found.</p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 text-left text-xs uppercase tracking-wider bg-gray-900/80">
                  <th className="p-3 w-8" aria-label="Select" />
                  <th className="p-3">ID</th>
                  <th className="p-3">Date</th>
                  <th className="p-3">Target</th>
                  <th className="p-3">Device</th>
                  <th className="p-3">Risk Score</th>
                  <th className="p-3">Level</th>
                  <th className="p-3">Findings</th>
                  <th className="p-3">Tags</th>
                  <th className="p-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {history.map((scan) => (
                  <Fragment key={scan.id}>
                  <tr className="text-gray-300 hover:bg-gray-800/50">
                    <td className="p-3">
                      <input
                        type="checkbox"
                        checked={selected.includes(scan.id)}
                        onChange={() => toggleSelected(scan.id)}
                        aria-label={`Select scan #${scan.id} for comparison`}
                        className="accent-emerald-500"
                      />
                    </td>
                    <td className="p-3 font-mono text-xs text-gray-500">#{scan.id}</td>
                    <td className="p-3 text-xs">
                      {new Date(scan.scan_timestamp).toLocaleString()}
                    </td>
                    <td className="p-3 font-mono text-xs">{scan.target}</td>
                    <td className="p-3 text-xs text-gray-500">
                      {scan.device_vendor} {scan.device_model}
                    </td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-medium ${
                          scan.risk_score >= 7
                            ? "bg-red-500/10 text-red-400"
                            : scan.risk_score >= 4
                              ? "bg-amber-500/10 text-amber-400"
                              : "bg-emerald-500/10 text-emerald-400"
                        }`}
                      >
                        {scan.risk_score.toFixed(1)}
                      </span>
                    </td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                          scan.risk_level === "CRITICAL"
                            ? "bg-red-500/10 text-red-400"
                            : scan.risk_level === "HIGH"
                              ? "bg-orange-500/10 text-orange-400"
                              : scan.risk_level === "MEDIUM"
                                ? "bg-amber-500/10 text-amber-400"
                                : "bg-emerald-500/10 text-emerald-400"
                        }`}
                      >
                        {scan.risk_level}
                      </span>
                    </td>
                    <td className="p-3 text-xs">{scan.vulnerability_count}</td>
                    <td className="p-3">
                      <div className="flex flex-wrap items-center gap-1 max-w-[14rem]">
                        {scan.tags.map((t) => (
                          <button
                            key={t}
                            onClick={() => setTagFilter(t)}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-sky-500/10 text-sky-300 hover:bg-sky-500/20"
                            title={`Filter by "${t}"`}
                          >
                            {t}
                          </button>
                        ))}
                        {scan.notes && (
                          <span title={scan.notes} className="text-gray-500">
                            <StickyNote className="w-3 h-3" aria-label="Has notes" />
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => setEditingId(editingId === scan.id ? null : scan.id)}
                          className="p-1 text-gray-500 hover:text-sky-400 rounded"
                          title="Edit tags & notes"
                        >
                          <Tag className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => handleExport(scan.id, "json")}
                          className="p-1 text-gray-500 hover:text-emerald-400 rounded"
                          title="Export JSON"
                        >
                          <Download className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => handleDelete(scan.id)}
                          className="p-1 text-gray-500 hover:text-red-400 rounded"
                          title="Delete"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                  {editingId === scan.id && (
                    <tr className="bg-gray-950/60">
                      <td colSpan={11} className="p-3">
                        <AnnotationEditor
                          scan={scan}
                          onSave={(update) => handleSaveAnnotations(scan.id, update)}
                          onCancel={() => setEditingId(null)}
                        />
                      </td>
                    </tr>
                  )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
