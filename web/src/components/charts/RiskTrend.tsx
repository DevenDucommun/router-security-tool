import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import type { ScanHistoryEntry } from "../../types";

interface Props {
  history: ScanHistoryEntry[];
}

export function RiskTrend({ history }: Props) {
  const data = [...history]
    .reverse()
    .map((entry) => ({
      date: new Date(entry.scan_timestamp).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
      }),
      risk: entry.risk_score,
      target: entry.target,
    }));

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-500 text-sm">
        No scan history available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }} style={{ cursor: "default" }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
        <XAxis dataKey="date" stroke="#6b7280" fontSize={11} />
        <YAxis domain={[0, 10]} stroke="#6b7280" fontSize={11} />
        <Tooltip
          contentStyle={{ background: "#1f2937", border: "1px solid #374151", borderRadius: "6px" }}
          labelStyle={{ color: "#e5e7eb" }}
          itemStyle={{ color: "#e5e7eb" }}
        />
        <ReferenceLine y={7} stroke="#ef4444" strokeDasharray="3 3" />
        <ReferenceLine y={4} stroke="#eab308" strokeDasharray="3 3" />
        <Line
          type="monotone"
          dataKey="risk"
          stroke="#10b981"
          strokeWidth={2}
          dot={{ fill: "#10b981", r: 3 }}
          activeDot={false}
          isAnimationActive={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
