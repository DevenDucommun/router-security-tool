import { Fragment, useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CalendarClock, Play, Pause, Trash2, KeyRound, Plus, AlertTriangle } from "lucide-react";
import { api } from "../api/client";
import type { Schedule, SchedulerStatus } from "../types";

const PRESETS = [
  { label: "Hourly", minutes: 60 },
  { label: "Every 6 hours", minutes: 360 },
  { label: "Daily", minutes: 1440 },
  { label: "Weekly", minutes: 10080 },
];

const inputClass =
  "mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none";

function intervalLabel(minutes: number) {
  const preset = PRESETS.find((p) => p.minutes === minutes);
  if (preset) return preset.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hours`;
  return `Every ${minutes} min`;
}

function relative(iso: string | null) {
  if (!iso) return "—";
  const diff = new Date(iso).getTime() - Date.now();
  const abs = Math.abs(diff);
  const mins = Math.round(abs / 60000);
  const text =
    mins < 1 ? "now" : mins < 60 ? `${mins} min` : mins < 2880 ? `${Math.round(mins / 60)} h` : `${Math.round(mins / 1440)} d`;
  if (text === "now") return "now";
  return diff >= 0 ? `in ${text}` : `${text} ago`;
}

function StatusBadge({ s }: { s: Schedule }) {
  const map: Record<string, string> = {
    never: "bg-gray-800 text-gray-400",
    running: "bg-sky-500/10 text-sky-300",
    ok: "bg-emerald-500/10 text-emerald-400",
    error: "bg-red-500/10 text-red-400",
  };
  const label = s.running ? "running" : s.last_status;
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${map[label] ?? map.never}`} title={s.last_error ?? ""}>
      {label === "never" ? "not run yet" : label}
    </span>
  );
}

function NewScheduleForm({ onCreated }: { onCreated: () => void }) {
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("22");
  const [username, setUsername] = useState("root");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [intervalMinutes, setIntervalMinutes] = useState(1440);
  const [tags, setTags] = useState("");
  const [runNow, setRunNow] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.createSchedule({
        target: target.trim(),
        port: parseInt(port) || 22,
        username,
        password,
        name: name.trim(),
        interval_minutes: intervalMinutes,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        run_immediately: runNow,
      });
      setTarget("");
      setPassword("");
      setName("");
      setTags("");
      onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create schedule");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
      <h2 className="text-sm font-medium text-gray-300 flex items-center gap-2">
        <Plus className="w-4 h-4" /> New schedule
      </h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div>
          <label className="text-[11px] text-gray-500 uppercase tracking-wide">Host</label>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="192.168.1.1" className={inputClass} />
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="text-[11px] text-gray-500 uppercase tracking-wide">Port</label>
            <input value={port} onChange={(e) => setPort(e.target.value)} className={inputClass} />
          </div>
          <div>
            <label className="text-[11px] text-gray-500 uppercase tracking-wide">User</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} className={inputClass} />
          </div>
        </div>
        <div>
          <label className="text-[11px] text-gray-500 uppercase tracking-wide">Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={inputClass} placeholder="Stored encrypted" />
        </div>
        <div>
          <label className="text-[11px] text-gray-500 uppercase tracking-wide">Frequency</label>
          <select value={intervalMinutes} onChange={(e) => setIntervalMinutes(parseInt(e.target.value))} className={inputClass}>
            {PRESETS.map((p) => (
              <option key={p.minutes} value={p.minutes}>{p.label}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-[11px] text-gray-500 uppercase tracking-wide">Name (optional)</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Home router" className={inputClass} />
        </div>
        <div className="sm:col-span-2">
          <label className="text-[11px] text-gray-500 uppercase tracking-wide">Tags (comma-separated)</label>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="home, nightly" className={inputClass} />
        </div>
        <div className="flex items-end gap-3">
          <label className="flex items-center gap-2 text-xs text-gray-400 pb-2">
            <input type="checkbox" checked={runNow} onChange={(e) => setRunNow(e.target.checked)} className="accent-emerald-500" />
            Run first scan now
          </label>
        </div>
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      <button
        onClick={submit}
        disabled={saving || !target.trim() || !password}
        className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-md transition-colors"
      >
        <CalendarClock className="w-4 h-4" />
        {saving ? "Saving..." : "Create schedule"}
      </button>
    </div>
  );
}

function PasswordEditor({ schedule, onDone }: { schedule: Schedule; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const save = async () => {
    try {
      await api.updateSchedule(schedule.id, { password });
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not update password");
    }
  };
  return (
    <div className="flex items-center gap-2">
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder={`New password for ${schedule.username}@${schedule.target}`}
        className="flex-1 bg-gray-950 border border-gray-700 rounded px-3 py-1.5 text-xs text-white focus:border-emerald-500 focus:outline-none"
      />
      <button onClick={save} disabled={!password} className="px-3 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 text-white rounded">
        Save
      </button>
      <button onClick={onDone} className="px-3 py-1.5 text-xs text-gray-400 hover:text-white">Cancel</button>
      {error && <span className="text-xs text-red-400">{error}</span>}
    </div>
  );
}

export function Schedules() {
  const [status, setStatus] = useState<SchedulerStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pwFor, setPwFor] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      setStatus(await api.schedules());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load schedules");
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    api
      .schedules()
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "Could not load schedules");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Poll while something is running so status and "last scan" update.
  const anyRunning = status?.schedules.some((s) => s.running) ?? false;
  useEffect(() => {
    if (!anyRunning) return;
    const t = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(t);
  }, [anyRunning, load]);

  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    }
    await load();
  };

  return (
    <div className="space-y-6 max-w-6xl">
      <div>
        <h1 className="text-xl font-semibold text-white">Scheduled Scans</h1>
        <p className="text-sm text-gray-500">
          Re-scan devices automatically. Results land in History tagged <code className="text-gray-400">scheduled</code>.
        </p>
      </div>

      {status && !status.enabled && (
        <div className="flex items-start gap-2 bg-amber-500/10 border border-amber-500/30 rounded-md p-3 text-xs text-amber-300">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          The scheduler is turned off (<code>ROUTER_SECURITY_SCHEDULER=0</code>). Schedules are saved but only run with "Run now".
        </div>
      )}
      {status?.key_source === "file" && (
        <p className="text-[11px] text-gray-500">
          Passwords are encrypted with a key file next to the database. Set <code className="text-gray-400">ROUTER_SECURITY_SECRET_KEY</code> to keep the key separate from the data.
        </p>
      )}

      <NewScheduleForm onCreated={load} />

      {error && <div className="bg-red-500/10 border border-red-500/30 rounded-md p-3 text-sm text-red-400">{error}</div>}

      {status && status.schedules.length === 0 ? (
        <p className="text-sm text-gray-500 text-center py-8">No schedules yet.</p>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 text-left text-xs uppercase tracking-wider">
                  <th className="p-3">Device</th>
                  <th className="p-3">Frequency</th>
                  <th className="p-3">Next run</th>
                  <th className="p-3">Last run</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Last risk</th>
                  <th className="p-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {status?.schedules.map((s) => (
                  <Fragment key={s.id}>
                    <tr className={`text-gray-300 ${s.enabled ? "" : "opacity-50"}`}>
                      <td className="p-3">
                        <div className="text-white text-sm">{s.name || s.target}</div>
                        <div className="font-mono text-[11px] text-gray-500">
                          {s.username}@{s.target}:{s.port}
                        </div>
                        {s.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {s.tags.map((t) => (
                              <span key={t} className="px-1.5 py-0.5 rounded text-[10px] bg-sky-500/10 text-sky-300">{t}</span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="p-3 text-xs">
                        <select
                          value={s.interval_minutes}
                          onChange={(e) => act(() => api.updateSchedule(s.id, { interval_minutes: parseInt(e.target.value) }))}
                          className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-xs"
                        >
                          {!PRESETS.some((p) => p.minutes === s.interval_minutes) && (
                            <option value={s.interval_minutes}>{intervalLabel(s.interval_minutes)}</option>
                          )}
                          {PRESETS.map((p) => (
                            <option key={p.minutes} value={p.minutes}>{p.label}</option>
                          ))}
                        </select>
                      </td>
                      <td className="p-3 text-xs" title={new Date(s.next_run_at).toLocaleString()}>
                        {s.enabled ? relative(s.next_run_at) : "paused"}
                      </td>
                      <td className="p-3 text-xs">
                        {s.last_scan_id ? (
                          <Link to="/history" className="text-sky-400 hover:text-sky-300" title={s.last_run_at ? new Date(s.last_run_at).toLocaleString() : ""}>
                            #{s.last_scan_id} · {relative(s.last_run_at)}
                          </Link>
                        ) : (
                          relative(s.last_run_at)
                        )}
                      </td>
                      <td className="p-3">
                        <StatusBadge s={s} />
                        {s.last_status === "error" && !s.running && s.last_error && (
                          <p className="text-[11px] text-red-400/80 mt-1 max-w-[16rem] break-words">{s.last_error}</p>
                        )}
                      </td>
                      <td className="p-3 text-xs">{s.last_risk_score !== null ? s.last_risk_score.toFixed(1) : "—"}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => act(() => api.runSchedule(s.id))}
                            disabled={s.running}
                            className="p-1 text-gray-500 hover:text-emerald-400 disabled:opacity-40 rounded"
                            title="Run now"
                          >
                            <Play className="w-3 h-3" />
                          </button>
                          <button
                            onClick={() => act(() => api.updateSchedule(s.id, { enabled: !s.enabled }))}
                            className="p-1 text-gray-500 hover:text-amber-400 rounded"
                            title={s.enabled ? "Pause" : "Resume"}
                          >
                            {s.enabled ? <Pause className="w-3 h-3" /> : <CalendarClock className="w-3 h-3" />}
                          </button>
                          <button
                            onClick={() => setPwFor(pwFor === s.id ? null : s.id)}
                            className="p-1 text-gray-500 hover:text-sky-400 rounded"
                            title="Change password"
                          >
                            <KeyRound className="w-3 h-3" />
                          </button>
                          <button
                            onClick={() => {
                              if (confirm(`Delete the schedule for ${s.name || s.target}? Past scans stay in History.`)) {
                                void act(() => api.deleteSchedule(s.id));
                              }
                            }}
                            className="p-1 text-gray-500 hover:text-red-400 rounded"
                            title="Delete"
                          >
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </div>
                      </td>
                    </tr>
                    {pwFor === s.id && (
                      <tr className="bg-gray-950/60">
                        <td colSpan={7} className="p-3">
                          <PasswordEditor
                            schedule={s}
                            onDone={() => {
                              setPwFor(null);
                              void load();
                            }}
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
