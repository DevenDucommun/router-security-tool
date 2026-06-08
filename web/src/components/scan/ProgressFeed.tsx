import { Loader2 } from "lucide-react";

interface Props {
  messages: string[];
  isRunning: boolean;
}

export function ProgressFeed({ messages, isRunning }: Props) {
  if (messages.length === 0) return null;

  return (
    <div className="bg-gray-950 border border-gray-800 rounded-md p-3 max-h-40 overflow-y-auto">
      <div className="space-y-1">
        {messages.map((msg, i) => (
          <div key={i} className="flex items-center gap-2 text-xs text-gray-400">
            <span className="text-gray-600 font-mono w-6">{String(i + 1).padStart(2, "0")}</span>
            <span>{msg}</span>
          </div>
        ))}
        {isRunning && (
          <div className="flex items-center gap-2 text-xs text-emerald-400">
            <Loader2 className="w-3 h-3 animate-spin" />
            <span>Scanning...</span>
          </div>
        )}
      </div>
    </div>
  );
}
