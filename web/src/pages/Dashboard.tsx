import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, AlertTriangle, Target, Clock, Scan } from "lucide-react";
import { api } from "../api/client";
import { SeverityChart } from "../components/charts/SeverityChart";
import { RiskTrend } from "../components/charts/RiskTrend";
import type { HistoryStats, ScanHistoryEntry } from "../types";

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: typeof Shield;
  label: string;
  value: string | number;
  color: string;
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <div className="flex items-center gap-3">
        <div className={`p-2 rounded-md ${color}`}>
          <Icon className="w-4 h-4" />
        </div>
        <div>
          <p className="text-[11px] text-gray-500 uppercase tracking-wide">{label}</p>
          <p className="text-lg font-semibold text-white">{value}</p>
        </div>
      </div>
    </div>
  );
}

export function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<HistoryStats | null>(null);
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.historyStats(), api.history(20)])
      .then(([s, h]) => {
        setStats(s);
        setHistory(h);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const latestScan = history[0];
  const severityData = latestScan
    ? history.reduce(
        (acc, scan) => {
          const level = scan.risk_level;
          if (level === "CRITICAL") acc.Critical += scan.vulnerability_count;
          else if (level === "HIGH") acc.High += scan.vulnerability_count;
          else if (level === "MEDIUM") acc.Medium += scan.vulnerability_count;
          else acc.Low += scan.vulnerability_count;
          return acc;
        },
        { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
      )
    : stats?.risk_distribution
      ? {
          Critical: stats.risk_distribution["CRITICAL"] || 0,
          High: stats.risk_distribution["HIGH"] || 0,
          Medium: stats.risk_distribution["MEDIUM"] || 0,
          Low: stats.risk_distribution["LOW"] || 0,
          Info: 0,
        }
      : { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        Loading dashboard...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Dashboard</h1>
          <p className="text-sm text-gray-500">Security assessment overview</p>
        </div>
        <button
          onClick={() => navigate("/scan")}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-md transition-colors"
        >
          <Scan className="w-4 h-4" />
          New Scan
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={Shield}
          label="Total Scans"
          value={stats?.total_scans || 0}
          color="bg-emerald-500/10 text-emerald-400"
        />
        <StatCard
          icon={Target}
          label="Devices Scanned"
          value={stats?.unique_targets || 0}
          color="bg-blue-500/10 text-blue-400"
        />
        <StatCard
          icon={AlertTriangle}
          label="Total Findings"
          value={stats?.total_vulnerabilities || 0}
          color="bg-amber-500/10 text-amber-400"
        />
        <StatCard
          icon={Clock}
          label="Avg Risk Score"
          value={stats?.avg_risk_score?.toFixed(1) || "0.0"}
          color="bg-red-500/10 text-red-400"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-sm font-medium text-gray-300 mb-3">Severity Distribution</h2>
          <SeverityChart data={severityData} />
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-sm font-medium text-gray-300 mb-3">Risk Score Trend</h2>
          <RiskTrend history={history} />
        </div>
      </div>

      {/* Recent scans */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h2 className="text-sm font-medium text-gray-300 mb-3">Recent Scans</h2>
        {history.length === 0 ? (
          <p className="text-sm text-gray-500 py-4 text-center">
            No scans yet. Run your first scan to see results here.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 text-left text-xs uppercase tracking-wider">
                  <th className="pb-2 pr-4">Target</th>
                  <th className="pb-2 pr-4">Date</th>
                  <th className="pb-2 pr-4">Risk</th>
                  <th className="pb-2 pr-4">Findings</th>
                  <th className="pb-2">Device</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {history.slice(0, 5).map((scan) => (
                  <tr key={scan.id} className="text-gray-300">
                    <td className="py-2 pr-4 font-mono text-xs">{scan.target}</td>
                    <td className="py-2 pr-4 text-xs text-gray-500">
                      {new Date(scan.scan_timestamp).toLocaleString()}
                    </td>
                    <td className="py-2 pr-4">
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
                    <td className="py-2 pr-4 text-xs">{scan.vulnerability_count}</td>
                    <td className="py-2 text-xs text-gray-500">
                      {scan.device_vendor} {scan.device_model}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
