import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";
import type { Severity } from "../../types";

const COLORS: Record<Severity, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
  Info: "#6b7280",
};

interface Props {
  data: Record<string, number>;
}

export function SeverityChart({ data }: Props) {
  const chartData = Object.entries(data)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name, value }));

  if (chartData.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-500 text-sm">
        No findings to display
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart style={{ cursor: "default" }}>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={50}
          outerRadius={80}
          dataKey="value"
          stroke="none"
          isAnimationActive={false}
          style={{ cursor: "default" }}
        >
          {chartData.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name as Severity] || "#6b7280"} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: "#1f2937", border: "1px solid #374151", borderRadius: "6px" }}
          labelStyle={{ color: "#e5e7eb" }}
          itemStyle={{ color: "#e5e7eb" }}
        />
        <Legend
          verticalAlign="bottom"
          height={36}
          formatter={(value) => <span className="text-xs text-gray-300">{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
