interface Props {
  score: number;
  size?: "sm" | "lg";
}

export function RiskGauge({ score, size = "lg" }: Props) {
  const percentage = (score / 10) * 100;
  const radius = size === "lg" ? 60 : 36;
  const stroke = size === "lg" ? 8 : 5;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (percentage / 100) * circumference;

  const color =
    score >= 7 ? "#ef4444" : score >= 4 ? "#eab308" : score > 0 ? "#22c55e" : "#6b7280";

  const level =
    score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : score > 0 ? "LOW" : "NONE";

  const dim = (radius + stroke) * 2;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={dim} height={dim} className="transform -rotate-90">
        <circle
          cx={radius + stroke}
          cy={radius + stroke}
          r={radius}
          fill="none"
          stroke="#1f2937"
          strokeWidth={stroke}
        />
        <circle
          cx={radius + stroke}
          cy={radius + stroke}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute flex flex-col items-center" style={{ marginTop: size === "lg" ? 35 : 18 }}>
        <span className={`font-bold ${size === "lg" ? "text-2xl" : "text-sm"}`} style={{ color }}>
          {score.toFixed(1)}
        </span>
        {size === "lg" && <span className="text-[10px] text-gray-500">/10.0</span>}
      </div>
      <span className="text-[10px] font-medium mt-1" style={{ color }}>
        {level}
      </span>
    </div>
  );
}
