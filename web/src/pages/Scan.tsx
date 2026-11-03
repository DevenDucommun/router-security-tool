import { useState } from "react";
import { Scan as ScanIcon, Download, Wifi, RefreshCw } from "lucide-react";
import { useScanWebSocket } from "../api/ws";
import { api } from "../api/client";
import { FindingCard, type VerifyState } from "../components/scan/FindingCard";
import { ProgressFeed } from "../components/scan/ProgressFeed";
import { KnownCves } from "../components/scan/KnownCves";
import { RiskGauge } from "../components/charts/RiskGauge";
import { SeverityChart } from "../components/charts/SeverityChart";
import type { ScanResult, DiscoveredDevice } from "../types";

export function Scan() {
  const [host, setHost] = useState("192.168.1.1");
  const [port, setPort] = useState("22");
  const [username, setUsername] = useState("root");
  const [password, setPassword] = useState("");
  const [devices, setDevices] = useState<DiscoveredDevice[]>([]);
  const [discovering, setDiscovering] = useState(false);

  const { connect, messages, result, scanId, error, isRunning } = useScanWebSocket();
  // Credentials of the scan whose results are shown, so "Verify fix" re-checks the
  // same device even if the form is edited afterwards.
  const [scanned, setScanned] = useState<{ host: string; username: string; password: string; port: number } | null>(null);
  const [verify, setVerify] = useState<Record<string, VerifyState>>({});
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const handleScan = () => {
    if (!host || !password) return;
    const target = { host, username, password, port: parseInt(port) };
    setScanned(target);
    setVerify({});
    setVerifyError(null);
    connect(target.host, target.username, target.password, target.port);
  };

  const handleVerify = async (ids: string[]) => {
    if (!scanned || ids.length === 0) return;
    setVerifyError(null);
    setVerify((prev) => ({ ...prev, ...Object.fromEntries(ids.map((id) => [id, "checking" as const])) }));
    try {
      const res = await api.verify(scanned.host, scanned.username, scanned.password, scanned.port, ids);
      setVerify((prev) => ({ ...prev, ...Object.fromEntries(res.results.map((r) => [r.id, r.status])) }));
    } catch (e) {
      setVerify((prev) => {
        const next = { ...prev };
        for (const id of ids) delete next[id];
        return next;
      });
      setVerifyError(e instanceof Error ? e.message : "Verification failed");
    }
  };

  const handleDiscover = async () => {
    setDiscovering(true);
    try {
      const res = await api.devices();
      setDevices(res.devices);
    } catch {
      // silently fail
    } finally {
      setDiscovering(false);
    }
  };

  const handleExport = async (format: "json" | "html" | "pdf") => {
    const res = await api.exportScan(format);
    if (res.ok) {
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `security_report.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-xl font-semibold text-white">Security Scan</h1>
        <p className="text-sm text-gray-500">Connect to a device and run a security assessment</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Form + Discovery */}
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-medium text-gray-300">Target Device</h2>

            <div>
              <label className="text-[11px] text-gray-500 uppercase tracking-wide">Host</label>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
                placeholder="192.168.1.1"
              />
            </div>

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
                <label className="text-[11px] text-gray-500 uppercase tracking-wide">Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="text-[11px] text-gray-500 uppercase tracking-wide">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
                placeholder="Enter password"
              />
            </div>

            <button
              onClick={handleScan}
              disabled={isRunning || !host || !password}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-md transition-colors"
            >
              <ScanIcon className="w-4 h-4" />
              {isRunning ? "Scanning..." : "Run Assessment"}
            </button>
          </div>

          {/* Device Discovery */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-gray-300">Discovered Devices</h2>
              <button
                onClick={handleDiscover}
                disabled={discovering}
                className="text-xs text-emerald-400 hover:text-emerald-300"
              >
                {discovering ? "Scanning..." : "Refresh"}
              </button>
            </div>

            {devices.length === 0 ? (
              <button
                onClick={handleDiscover}
                className="w-full flex items-center justify-center gap-2 py-3 text-xs text-gray-500 hover:text-gray-300 border border-dashed border-gray-700 rounded-md"
              >
                <Wifi className="w-3 h-3" />
                Scan network for devices
              </button>
            ) : (
              <div className="space-y-1">
                {devices.map((device, i) => (
                  <button
                    key={i}
                    onClick={() => {
                      setHost(device.ip);
                      setPort(String(device.port));
                    }}
                    className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-gray-400 hover:text-white hover:bg-gray-800 rounded"
                  >
                    <div
                      className={`w-2 h-2 rounded-full ${device.likely_router ? "bg-emerald-400" : "bg-gray-600"}`}
                    />
                    <span className="font-mono">{device.ip}:{device.port}</span>
                    <span className="text-gray-600 ml-auto">{device.description}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: Results */}
        <div className="lg:col-span-2 space-y-4">
          <ProgressFeed messages={messages} isRunning={isRunning} />

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-md p-3 text-sm text-red-400">
              {error}
            </div>
          )}

          {verifyError && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-md p-3 text-sm text-red-400">
              Verify fix: {verifyError}
            </div>
          )}

          {result && (
            <ScanResults
              result={result}
              onExport={handleExport}
              verify={verify}
              onVerify={scanned && !isRunning ? handleVerify : undefined}
            />
          )}

          {result && scanId !== null && <KnownCves key={scanId} scanId={scanId} />}
        </div>
      </div>
    </div>
  );
}

function ScanResults({
  result,
  onExport,
  verify,
  onVerify,
}: {
  result: ScanResult;
  onExport: (format: "json" | "html" | "pdf") => void;
  verify: Record<string, VerifyState>;
  onVerify?: (ids: string[]) => void;
}) {
  const severities = ["Critical", "High", "Medium", "Low", "Info"] as const;
  const anyChecking = Object.values(verify).includes("checking");
  const resolvedCount = Object.values(verify).filter((s) => s === "resolved").length;

  return (
    <div className="space-y-4">
      {/* Summary row */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col items-center relative">
          <RiskGauge score={result.risk_score} />
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <p className="text-[11px] text-gray-500 uppercase tracking-wide mb-1">Device</p>
          <p className="text-sm text-white font-medium">{result.device_info.hostname || result.target}</p>
          <p className="text-xs text-gray-500 mt-1">{result.device_info.firmware_version}</p>
          <p className="text-xs text-gray-500">{result.profile} profile</p>
          <p className="text-xs text-gray-500 mt-1">{result.scan_duration.toFixed(1)}s scan time</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <SeverityChart data={result.severity_summary} />
        </div>
      </div>

      {/* Export bar */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-gray-500 mr-2">Export:</span>
        {(["json", "html", "pdf"] as const).map((fmt) => (
          <button
            key={fmt}
            onClick={() => onExport(fmt)}
            className="flex items-center gap-1 px-2 py-1 text-xs text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 rounded transition-colors"
          >
            <Download className="w-3 h-3" />
            {fmt.toUpperCase()}
          </button>
        ))}
        {onVerify && result.findings.length > 0 && (
          <div className="ml-auto flex items-center gap-2">
            {resolvedCount > 0 && (
              <span className="text-xs text-emerald-400">
                {resolvedCount}/{result.findings.length} resolved
              </span>
            )}
            <button
              onClick={() => onVerify([...new Set(result.findings.map((f) => f.id))])}
              disabled={anyChecking}
              title="Re-run only the checks behind these findings"
              className="flex items-center gap-1 px-2 py-1 text-xs text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded transition-colors"
            >
              <RefreshCw className={`w-3 h-3 ${anyChecking ? "animate-spin" : ""}`} />
              Re-check all
            </button>
          </div>
        )}
      </div>

      {/* Findings */}
      <div className="space-y-2">
        <h2 className="text-sm font-medium text-gray-300">
          Findings ({result.findings.length})
        </h2>
        {severities.map((sev) => {
          const findings = result.findings.filter((f) => f.severity === sev);
          if (findings.length === 0) return null;
          return (
            <div key={sev} className="space-y-1">
              {findings.map((f) => (
                <FindingCard
                  key={f.id}
                  finding={f}
                  verifyState={verify[f.id]}
                  onVerify={onVerify ? () => onVerify([f.id]) : undefined}
                />
              ))}
            </div>
          );
        })}
        {result.findings.length === 0 && (
          <p className="text-sm text-emerald-400 py-4 text-center">
            No security issues found!
          </p>
        )}
      </div>
    </div>
  );
}
