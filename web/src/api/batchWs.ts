import { useCallback, useRef, useState } from "react";
import type { BatchSummary, BatchTarget, ScanResult } from "../types";

interface BatchRequest {
  targets: string;
  username: string;
  password: string;
  port: number;
  concurrency: number;
}

type BatchMessage =
  | { type: "batch_started"; targets: string[]; concurrency: number }
  | { type: "target_started"; target: string }
  | { type: "target_progress"; target: string; message: string }
  | { type: "target_result"; target: string; scan_id: number | null; data: ScanResult }
  | { type: "target_error"; target: string; message: string }
  | { type: "batch_complete"; summary: BatchSummary; duration: number }
  | { type: "error"; message: string };

export function useBatchWebSocket() {
  const ws = useRef<WebSocket | null>(null);
  const finished = useRef(false);
  const [targets, setTargets] = useState<BatchTarget[]>([]);
  const [summary, setSummary] = useState<BatchSummary | null>(null);
  const [duration, setDuration] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  const update = (target: string, patch: Partial<BatchTarget>) =>
    setTargets((prev) => prev.map((t) => (t.target === target ? { ...t, ...patch } : t)));

  const start = useCallback((req: BatchRequest) => {
    setTargets([]);
    setSummary(null);
    setDuration(null);
    setError(null);
    setIsRunning(true);
    finished.current = false;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${window.location.host}/ws/batch`);
    ws.current = socket;

    socket.onopen = () => socket.send(JSON.stringify(req));

    socket.onmessage = (event) => {
      const msg: BatchMessage = JSON.parse(event.data);
      switch (msg.type) {
        case "batch_started":
          setTargets(msg.targets.map((target) => ({ target, status: "queued" })));
          break;
        case "target_started":
          update(msg.target, { status: "running", lastMessage: "Connecting..." });
          break;
        case "target_progress":
          update(msg.target, { lastMessage: msg.message });
          break;
        case "target_result":
          update(msg.target, { status: "done", result: msg.data, scanId: msg.scan_id, lastMessage: undefined });
          break;
        case "target_error":
          update(msg.target, { status: "error", error: msg.message, lastMessage: undefined });
          break;
        case "batch_complete":
          finished.current = true;
          setSummary(msg.summary);
          setDuration(msg.duration);
          setIsRunning(false);
          socket.close();
          break;
        case "error":
          finished.current = true;
          setError(msg.message);
          setIsRunning(false);
          break;
      }
    };

    socket.onerror = () => {
      finished.current = true;
      setError("WebSocket connection failed");
      setIsRunning(false);
    };

    socket.onclose = () => {
      if (!finished.current) setError("Connection closed before the batch finished. Check server logs.");
      setIsRunning(false);
    };
  }, []);

  return { start, targets, summary, duration, error, isRunning };
}
