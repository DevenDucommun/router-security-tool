import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { Finding } from "../../types";

const SEVERITY_STYLES = {
  Critical: "border-red-500/30 bg-red-500/5",
  High: "border-orange-500/30 bg-orange-500/5",
  Medium: "border-amber-500/30 bg-amber-500/5",
  Low: "border-emerald-500/30 bg-emerald-500/5",
  Info: "border-gray-500/30 bg-gray-500/5",
};

const SEVERITY_BADGES = {
  Critical: "bg-red-500/20 text-red-400",
  High: "bg-orange-500/20 text-orange-400",
  Medium: "bg-amber-500/20 text-amber-400",
  Low: "bg-emerald-500/20 text-emerald-400",
  Info: "bg-gray-500/20 text-gray-400",
};

interface Props {
  finding: Finding;
}

export function FindingCard({ finding }: Props) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className={`border rounded-md ${SEVERITY_STYLES[finding.severity]} transition-all`}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-3 text-left"
      >
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" />
        )}
        <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${SEVERITY_BADGES[finding.severity]}`}>
          {finding.severity}
        </span>
        <code className="text-[11px] text-gray-500 font-mono">{finding.id}</code>
        <span className="text-sm text-gray-200 flex-1">{finding.title}</span>
      </button>

      {expanded && (
        <div className="px-3 pb-3 pl-10 space-y-2 text-sm">
          {finding.description && (
            <p className="text-gray-400">{finding.description}</p>
          )}
          {finding.evidence && (
            <div>
              <p className="text-[11px] text-gray-500 uppercase tracking-wide mb-1">Evidence</p>
              <pre className="bg-gray-950 border border-gray-800 rounded p-2 text-xs text-gray-300 overflow-x-auto">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.remediation && (
            <div>
              <p className="text-[11px] text-gray-500 uppercase tracking-wide mb-1">Remediation</p>
              <p className="text-gray-300 text-xs">{finding.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
