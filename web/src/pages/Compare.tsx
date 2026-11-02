import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowLeft, ArrowRight, Minus, Plus, Equal } from "lucide-react";
import { api } from "../api/client";
import type { DiffFinding, ScanDiff, Severity } from "../types";

const severityStyle: Record<Severity, string> = {
  Critical: "bg-red-500/10 text-red-400",
  High: "bg-orange-500/10 text-orange-400",
  Medium: "bg-amber-500/10 text-amber-400",
  Low: "bg-sky-500/10 text-sky-400",
  Info: "bg-gray-500/10 text-gray-400",
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${severityStyle[severity]}`}>
      {severity}
    </span>
  );
}

function FindingRow({ finding, showChange }: { finding: DiffFinding; showChange?: boolean }) {
  return (
    <div className="flex items-start gap-3 px-3 py-2 text-sm">
      <div className="flex items-center gap-1 shrink-0 pt-0.5">
        {showChange && finding.severity_changed && finding.previous_severity && (
          <>
            <SeverityBadge severity={finding.previous_severity} />
            <ArrowRight className="w-3 h-3 text-gray-500" />
          </>
        )}
        <SeverityBadge severity={finding.severity} />
      </div>
      <div className="min-w-0">
        <p className="text-gray-200">{finding.title || finding.id}</p>
        {finding.id && <p className="text-[11px] font-mono text-gray-500">{finding.id}</p>}
      </div>
    </div>
  );
}

function Section({
  title,
  icon,
  accent,
  findings,
  empty,
  showChange,
}: {
  title: string;
  icon: React.ReactNode;
  accent: string;
  findings: DiffFinding[];
  empty: string;
  showChange?: boolean;
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      <div className={`flex items-center gap-2 px-3 py-2 border-b border-gray-800 text-sm font-medium ${accent}`}>
        {icon}
        {title} ({findings.length})
      </div>
      {findings.length === 0 ? (
        <p className="px-3 py-4 text-xs text-gray-500">{empty}</p>
      ) : (
        <div className="divide-y divide-gray-800">
          {findings.map((f) => (
            <FindingRow key={`${f.id}-${f.title}`} finding={f} showChange={showChange} />
          ))}
        </div>
      )}
    </div>
  );
}

function ScanCard({ label, scan }: { label: string; scan: ScanDiff["base"] }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <p className="text-[11px] text-gray-500 uppercase tracking-wide">{label}</p>
      <p className="text-sm text-white font-medium mt-1">Scan #{scan.id}</p>
      <p className="text-xs text-gray-500">
        {scan.scan_timestamp ? new Date(scan.scan_timestamp).toLocaleString() : "—"}
      </p>
      <p className="text-xs text-gray-400 mt-2">
        Risk {scan.risk_score.toFixed(1)} · {scan.finding_count} findings
      </p>
    </div>
  );
}

export function Compare() {
  const [params] = useSearchParams();
  const base = Number(params.get("base"));
  const head = Number(params.get("head"));
  const key = `${base}:${head}`;
  const valid = Boolean(base && head);
  const [loaded, setLoaded] = useState<{ key: string; diff?: ScanDiff; error?: string } | null>(null);

  useEffect(() => {
    if (!valid) return;
    let cancelled = false;
    api
      .diffScans(base, head)
      .then((d) => !cancelled && setLoaded({ key, diff: d }))
      .catch((e: Error) => !cancelled && setLoaded({ key, error: e.message }));
    return () => {
      cancelled = true;
    };
  }, [base, head, key, valid]);

  const current = loaded?.key === key ? loaded : null;
  const diff = current?.diff ?? null;
  const error = !valid
    ? "Select two scans of the same target on the History page to compare."
    : current?.error ?? null;

  const delta = diff?.risk_delta ?? 0;
  const deltaStyle =
    delta > 0 ? "text-red-400" : delta < 0 ? "text-emerald-400" : "text-gray-400";

  return (
    <div className="space-y-6 max-w-6xl">
      <div>
        <Link to="/history" className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300">
          <ArrowLeft className="w-3 h-3" /> Back to history
        </Link>
        <h1 className="text-xl font-semibold text-white mt-2">Compare Scans</h1>
        {diff && <p className="text-sm text-gray-500 font-mono">{diff.head.target}</p>}
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-md p-3 text-sm text-red-400">{error}</div>
      )}

      {!diff && !error && <p className="text-gray-500 text-sm">Loading...</p>}

      {diff && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <ScanCard label="Baseline" scan={diff.base} />
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col items-center justify-center">
              <p className="text-[11px] text-gray-500 uppercase tracking-wide">Risk change</p>
              <p className={`text-3xl font-semibold mt-1 ${deltaStyle}`}>
                {delta > 0 ? "+" : ""}
                {delta.toFixed(1)}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                {diff.summary.new} new · {diff.summary.resolved} resolved · {diff.summary.severity_changed} changed
              </p>
            </div>
            <ScanCard label="Latest" scan={diff.head} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Section
              title="New findings"
              icon={<Plus className="w-4 h-4" />}
              accent="text-red-400"
              findings={diff.new}
              empty="No new findings since the baseline."
            />
            <Section
              title="Resolved"
              icon={<Minus className="w-4 h-4" />}
              accent="text-emerald-400"
              findings={diff.resolved}
              empty="Nothing from the baseline has been fixed yet."
            />
          </div>

          <Section
            title="Still open"
            icon={<Equal className="w-4 h-4" />}
            accent="text-gray-300"
            findings={diff.persisting}
            empty="No findings carried over."
            showChange
          />
        </>
      )}
    </div>
  );
}
