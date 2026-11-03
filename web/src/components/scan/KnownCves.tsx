import { useState } from "react";
import { ShieldAlert, RefreshCw, ExternalLink, ChevronDown, ChevronRight } from "lucide-react";
import { api } from "../../api/client";
import type { CveComponent, CveReport, KnownCve } from "../../types";

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-500/10 text-red-400",
  HIGH: "bg-orange-500/10 text-orange-400",
  MEDIUM: "bg-amber-500/10 text-amber-400",
  LOW: "bg-sky-500/10 text-sky-400",
};

function SeverityPill({ severity, score }: { severity: string; score: number | null }) {
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium whitespace-nowrap ${SEVERITY_STYLE[severity] ?? "bg-gray-800 text-gray-400"}`}>
      {severity} {score !== null ? score.toFixed(1) : ""}
    </span>
  );
}

function CveRow({ cve }: { cve: KnownCve }) {
  return (
    <li className="flex items-start gap-2 py-1.5">
      <SeverityPill severity={cve.severity} score={cve.score} />
      <div className="min-w-0 flex-1">
        <a
          href={cve.url}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 font-mono text-xs text-sky-300 hover:text-sky-200"
        >
          {cve.id}
          <ExternalLink className="w-3 h-3" />
        </a>
        {cve.known_exploited && (
          <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-600/20 text-red-300">
            Known exploited (CISA KEV)
          </span>
        )}
        <span className="ml-2 text-[10px] text-gray-600">{cve.published}</span>
        <p className="text-xs text-gray-400 mt-0.5 break-words">{cve.description}</p>
      </div>
    </li>
  );
}

function ComponentBlock({ comp }: { comp: CveComponent }) {
  const [open, setOpen] = useState(comp.critical > 0 || comp.known_exploited > 0);
  const shown = comp.cves.length;

  return (
    <div className="border border-gray-800 rounded-md">
      <button
        onClick={() => setOpen(!open)}
        disabled={!comp.looked_up || comp.total === 0}
        className="w-full flex items-center gap-2 px-3 py-2 text-left disabled:cursor-default"
      >
        {comp.total > 0 ? (
          open ? <ChevronDown className="w-3 h-3 text-gray-500" /> : <ChevronRight className="w-3 h-3 text-gray-500" />
        ) : (
          <span className="w-3" />
        )}
        <span className="text-sm text-white">{comp.name}</span>
        <span className="font-mono text-xs text-gray-500">{comp.version}</span>
        <span className="ml-auto flex items-center gap-2 text-xs">
          {!comp.looked_up ? (
            <span className="text-gray-500">not checked</span>
          ) : comp.total === 0 ? (
            <span className="text-emerald-400">no known CVEs{comp.critical_only ? " (critical)" : ""}</span>
          ) : (
            <>
              {comp.critical > 0 && <span className="text-red-400">{comp.critical} critical</span>}
              {comp.high > 0 && <span className="text-orange-400">{comp.high} high</span>}
              <span className="text-gray-400">
                {comp.total} {comp.critical_only ? "critical " : ""}total
              </span>
            </>
          )}
          {comp.stale && <span className="text-amber-400" title="Served from an older cached lookup">cached</span>}
        </span>
      </button>
      {open && comp.total > 0 && (
        <div className="px-3 pb-2 border-t border-gray-800">
          <ul className="divide-y divide-gray-800/60">
            {comp.cves.map((cve) => (
              <CveRow key={cve.id} cve={cve} />
            ))}
          </ul>
          {comp.total > shown && (
            <p className="text-[11px] text-gray-500 pt-1">
              Showing the {shown} most severe of {comp.total}. CPE: <code className="text-gray-400">{comp.cpe}</code>
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/** Known-CVE lookup for a saved scan. Lookups are on demand: they call NIST NVD. */
export function KnownCves({ scanId }: { scanId: number }) {
  const [report, setReport] = useState<CveReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [kernel, setKernel] = useState(false);

  const load = async (opts: { refresh?: boolean; kernel?: boolean } = {}) => {
    setLoading(true);
    setError(null);
    try {
      setReport(await api.scanCves(scanId, { refresh: opts.refresh, kernel: opts.kernel ?? kernel }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "CVE lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const s = report?.summary;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
      <div className="flex items-center gap-2">
        <ShieldAlert className="w-4 h-4 text-gray-400" />
        <h2 className="text-sm font-medium text-gray-300">Known CVEs</h2>
        <div className="ml-auto flex items-center gap-3">
          {report?.kernel_available && (
            <label className="flex items-center gap-1 text-xs text-gray-400" title="Adds critical Linux kernel CVEs (the kernel matches thousands overall)">
              <input
                type="checkbox"
                checked={kernel}
                onChange={(e) => {
                  setKernel(e.target.checked);
                  void load({ kernel: e.target.checked });
                }}
                disabled={loading}
                className="accent-emerald-500"
              />
              Include kernel
            </label>
          )}
          <button
            onClick={() => load({ refresh: report !== null })}
            disabled={loading}
            className="flex items-center gap-1 px-2 py-1 text-xs text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded transition-colors"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Checking NVD..." : report ? "Refresh" : "Check NVD"}
          </button>
        </div>
      </div>

      {!report && !loading && !error && (
        <p className="text-xs text-gray-500">
          Looks up the detected software versions (OpenWrt, Cisco IOS, Dropbear, BusyBox) in the NIST
          National Vulnerability Database. Only product names and versions are sent. The first lookup can
          take up to a minute without an <code className="text-gray-400">NVD_API_KEY</code>; results are cached for 24 hours.
        </p>
      )}

      {error && <p className="text-xs text-red-400">{error}</p>}

      {report && (
        <>
          {report.status === "no_components" ? (
            <p className="text-xs text-gray-500">
              No software with a recognizable version was recorded for this scan. Scans made before v1.2 only
              record the firmware string; re-scan the device to check Dropbear and BusyBox too.
            </p>
          ) : (
            <>
              {s?.unpatched_critical && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-md p-2 text-xs text-red-300">
                  This device runs software with {s.critical} unpatched critical CVE{s.critical === 1 ? "" : "s"}
                  {s.known_exploited > 0 ? `, ${s.known_exploited} known to be exploited in the wild` : ""}.
                  Update the firmware.
                </div>
              )}
              {s && !s.unpatched_critical && s.total === 0 && report.status === "ok" && (
                <p className="text-xs text-emerald-400">No known CVEs for the detected versions.</p>
              )}
              <div className="space-y-2">
                {report.components.map((c) => (
                  <ComponentBlock key={c.key} comp={c} />
                ))}
              </div>
            </>
          )}
          {report.errors.length > 0 && (
            <ul className="text-[11px] text-amber-400 space-y-0.5">
              {report.errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          )}
          <p className="text-[10px] text-gray-600">
            Source: NIST NVD · checked {new Date(report.checked_at).toLocaleString()}
          </p>
        </>
      )}
    </div>
  );
}
