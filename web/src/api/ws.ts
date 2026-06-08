import { useCallback, useRef, useState } from "react";
import type { WSMessage, ScanResult } from "../types";

interface UseScanWebSocketReturn {
  connect: (host: string, username: string, password: string, port?: number) => void;
  disconnect: () => void;
  messages: string[];
  result: ScanResult | null;
  error: string | null;
  isRunning: boolean;
}

export function useScanWebSocket(): UseScanWebSocketReturn {
  const ws = useRef<WebSocket | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  const gotResult = useRef(false);
  const gotError = useRef(false);

  const disconnect = useCallback(() => {
    if (ws.current) {
      ws.current.close();
      ws.current = null;
    }
    setIsRunning(false);
  }, []);

  const connect = useCallback(
    (host: string, username: string, password: string, port = 22) => {
      setMessages([]);
      setResult(null);
      setError(null);
      setIsRunning(true);
      gotResult.current = false;
      gotError.current = false;

      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws/scan`;

      const socket = new WebSocket(wsUrl);
      ws.current = socket;

      socket.onopen = () => {
        socket.send(JSON.stringify({ host, port, username, password }));
      };

      socket.onmessage = (event) => {
        const msg: WSMessage = JSON.parse(event.data);

        if (msg.type === "progress") {
          setMessages((prev) => [...prev, msg.message || ""]);
        } else if (msg.type === "result") {
          gotResult.current = true;
          setResult(msg.data || null);
          setIsRunning(false);
        } else if (msg.type === "error") {
          gotError.current = true;
          setError(msg.message || "Unknown error");
          setIsRunning(false);
        }
      };

      socket.onerror = () => {
        gotError.current = true;
        setError("WebSocket connection failed");
        setIsRunning(false);
      };

      socket.onclose = () => {
        if (!gotResult.current && !gotError.current) {
          setError("Connection closed before results were received. Check server logs.");
        }
        setIsRunning(false);
      };
    },
    []
  );

  return { connect, disconnect, messages, result, error, isRunning };
}
