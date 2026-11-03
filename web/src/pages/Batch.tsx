import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Layers, Upload, AlertTriangle, CheckCircle2, Loader2, Clock } from "lucide-react";
import { api } from "../api/client";
import { useBatchWebSocket } from "../api/batchWs";
import type { BatchTarget, Severity, TargetPreview } from "../types";

const SEVERITY_BADGES: Record<Severity, string> = {
  Critical: "bg-red-500/20 text-red-400",
  High: "bg-orange-500/20 text-orange-400",
  Medium: "bg-amber-500/20 text-amber-400",
  Low: "bg-emerald-500/20 text-emerald-400",
  Info: "bg-gray-500/20 text-gray-400",
};

function riskStyle(score: number) {
  if (score >= 7) return "text-red-400";
  if (score >= 4) return "text-amber-400";
  return "text-emerald-400";
}

export function Batch() {
  const [targetsText, setTargetsText] = useState("");
  const [port, setPort] = useState("22");
  const [username, setUsername] = useState("root");
  const [password, setPassword] = useState("");
  const [concurrency, setConcurrency] = useState("4");
  const [preview, setPreview] = useState<TargetPreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const { start, targets, summary, duration, error, isRunning } = useBatchWebSocket();

  // Debounced preview of how the target list expands.
  useEffect(() => {
    const text = targetsText;
    const timer = setTimeout(() => {
      if (!text.trim()) {
        setPreview(null);
        setPreviewError(null);
        return;
      }
      api
        .previewTargets(text)
        .then((p) => {
          setPreview(p);
          setPreviewError(null);
        })
        .catch((e: Error) => {
          setPreview(null);
          setPreviewError(e.message);
        });
    }, 300);
    return () => clearTimeout(timer);
  }, [targetsText]);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    const text = await file.text();
    setTargetsText((prev) => (prev.trim() ? `${prev.trim()}\n${text}` : text));
  };

  const canStart =
    !isRunning && !!password && !!preview && preview.count > 0 && preview.errors.length === 0 && !previewError;

  const handleStart = () => {
    if (!canStart) return;
    start({
      targets: targetsText,
      username,
      password,
      port: parseInt(port),
      concurrency: parseInt(concurrency),
    });
  };

  const completed = targets.filter((t) => t.status === "done" || t.status === "error").length;

  return (
    <div className="space-y-6 max-w-6xl">
      <div>
        <h1 className="text-xl font-semibold text-white">Batch Scan</h1>
        <p className="text-sm text-gray-500">Assess many devices in parallel with shared credentials</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3 lg:col-span-2">
          <div className="flex items-center justify-between">
            <label htmlFor="batch-targets" className="text-[11px] text-gray-500 uppercase tracking-wide">
              Targets
            </label>
            <label className="flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300 cursor-pointer">
              <Upload className="w-3 h-3" />
              Load file
              <input
                type="file"
                accept=".txt,.csv,text/plain"
                className="hidden"
                onChange={(e) => handleFile(e.target.files?.[0])}
              />
            </label>
          </div>
          <textarea
            id="batch-targets"
            value={targetsText}
            onChange={(e) => setTargetsText(e.target.value)}
            rows={6}
            placeholder={"192.168.1.1, 192.168.1.2\n10.0.0.0/29\n192.168.1.10-20\n# comments are ignored"}
            className="w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm font-mono text-white focus:border-emerald-500 focus:outline-none"
          />
          <div className="text-xs min-h-[1rem]">
            {previewError && <span className="text-red-400">{previewError}</span>}
            {preview && (
              <span className={preview.errors.length ? "text-amber-400" : "text-gray-400"}>
                {preview.count} host{preview.count === 1 ? "" : "s"} (max {preview.max_targets})
                {preview.errors.length > 0 && ` · ${preview.errors.join("; ")}`}
              </span>
            )}
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[11px] text-gray-500 uppercase tracking-wide">Port</label>
              <input
                type="text"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="text-[11px] text-gray-500 uppercase tracking-wide">Parallel</label>
              <select
                value={concurrency}
                onChange={(e) => setConcurrency(e.target.value)}
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
              >
                {[1, 2, 4, 6, 8].map((n) => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="text-[11px] text-gray-500 uppercase tracking-wide">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="text-[11px] text-gray-500 uppercase tracking-wide">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Shared by all targets"
              className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <button
            onClick={handleStart}
            disabled={!canStart}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-md transition-colors"
          >
            <Layers className="w-4 h-4" />
            {isRunning ? `Scanning ${completed}/${targets.length}...` : `Scan ${preview?.count ?? 0} devices`}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-md p-3 text-sm text-red-400">{error}</div>
      )}

      {targets.length > 0 && (
        <div className="h-1.5 bg-gray-800 rounded overflow-hidden">
          <div
            className="h-full bg-emerald-500 transition-all"
            style={{ width: `${(completed / targets.length) * 100}%` }}
          />
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <p className="text-[11px] text-gray-500 uppercase tracking-wide">Fleet</p>
            <p className="text-2xl font-semibold text-white mt-1">
              {summary.succeeded}/{summary.total} <span className="text-sm text-gray-500 font-normal">scanned</span>
            </p>
            {summary.failed > 0 && <p className="text-xs text-red-400 mt-1">{summary.failed} unreachable or failed</p>}
            {duration !== null && <p className="text-xs text-gray-500 mt-1">{duration.toFixed(1)}s total</p>}
            <div className="flex flex-wrap gap-1 mt-3">
              {Object.entries(summary.risk_levels).map(([level, count]) => (
                <span key={level} className="px-2 py-0.5 rounded text-[10px] bg-gray-800 text-gray-300">
                  {level}: {count}
                </span>
              ))}
            </div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 lg:col-span-2">
            <p className="text-[11px] text-gray-500 uppercase tracking-wide mb-2">Most common findings</p>
            {summary.succeeded === 0 ? (
              <p className="text-sm text-gray-500">No devices were scanned, so there are no findings to compare.</p>
            ) : summary.common_findings.length === 0 ? (
              <p className="text-sm text-emerald-400">No findings across the scanned devices.</p>
            ) : (
              <ul className="space-y-1">
                {summary.common_findings.map((f) => (
                  <li key={f.id} className="flex items-center gap-2 text-sm">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${SEVERITY_BADGES[f.severity]}`}>
                      {f.severity}
                    </span>
                    <span className="text-gray-200 flex-1 truncate">{f.title}</span>
                    <span className="text-xs text-gray-400 whitespace-nowrap">
                      {f.devices}/{summary.succeeded} devices
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {targets.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {targets.map((t) => (
            <TargetCard key={t.target} target={t} />
          ))}
        </div>
      )}

      {summary && summary.succeeded > 0 && (
        <p className="text-xs text-gray-500">
          Each device scan was saved — compare, tag, or export them from{" "}
          <Link to="/history" className="text-emerald-400 hover:text-emerald-300">History</Link>.
        </p>
      )}
    </div>
  );
}

function TargetCard({ target }: { target: BatchTarget }) {
  const icon = {
    queued: <Clock className="w-4 h-4 text-gray-500" />,
    running: <Loader2 className="w-4 h-4 text-sky-400 animate-spin" />,
    done: <CheckCircle2 className="w-4 h-4 text-emerald-400" />,
    error: <AlertTriangle className="w-4 h-4 text-red-400" />,
  }[target.status];

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-3 space-y-1">
      <div className="flex items-center gap-2">
        {icon}
        <span className="font-mono text-sm text-white flex-1 truncate">{target.target}</span>
        {target.result && (
          <span className={`text-sm font-semibold ${riskStyle(target.result.risk_score)}`}>
            {target.result.risk_score.toFixed(1)}
          </span>
        )}
      </div>
      {target.status === "queued" && <p className="text-xs text-gray-500">Queued</p>}
      {target.status === "running" && <p className="text-xs text-gray-400 truncate">{target.lastMessage}</p>}
      {target.status === "error" && <p className="text-xs text-red-400 break-words">{target.error}</p>}
      {target.result && (
        <p className="text-xs text-gray-400">
          {target.result.findings.length} finding{target.result.findings.length === 1 ? "" : "s"} ·{" "}
          {target.result.profile} profile
          {target.result.device_info.hostname && ` · ${target.result.device_info.hostname}`}
        </p>
      )}
    </div>
  );
}
