import { useEffect, useRef, useState } from "react";
import type { Alert } from "./types";

const MAX_BUFFER = 500;

/**
 * Live alert feed over WebSocket with automatic reconnect.
 *
 * Buffer is bounded and de-duplicated by alert_id: the server replays a snapshot
 * on connect, so a naive append would double-count on every reconnect.
 */
export function useAlertStream(enabled = true) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [status, setStatus] = useState<"connecting" | "open" | "closed">("connecting");
  const [dropped, setDropped] = useState(0);
  const socketRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(1000);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    let timer: number | undefined;

    const connect = () => {
      if (cancelled) return;
      setStatus("connecting");
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${window.location.host}/ws/alerts`);
      socketRef.current = ws;

      ws.onopen = () => {
        retryRef.current = 1000;
        setStatus("open");
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "snapshot") {
            setAlerts((prev) => mergeAlerts(msg.alerts ?? [], prev));
          } else if (msg.type === "alert") {
            setAlerts((prev) => mergeAlerts([msg.alert], prev));
          }
        } catch {
          /* malformed frame: keep the stream alive */
        }
      };

      ws.onclose = () => {
        setStatus("closed");
        if (cancelled) return;
        timer = window.setTimeout(connect, retryRef.current);
        retryRef.current = Math.min(retryRef.current * 2, 30000);
      };

      ws.onerror = () => ws.close();
    };

    connect();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
      socketRef.current?.close();
    };
  }, [enabled]);

  const merge = (incoming: Alert[], prev: Alert[]): [Alert[], number] => {
    const seen = new Set(prev.map((a) => a.alert_id));
    const fresh = incoming.filter((a) => !seen.has(a.alert_id));
    if (fresh.length === 0) return [prev, 0];
    const next = [...fresh, ...prev].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    const overflow = Math.max(0, next.length - MAX_BUFFER);
    return [next.slice(0, MAX_BUFFER), overflow];
  };

  function mergeAlerts(incoming: Alert[], prev: Alert[]): Alert[] {
    const [next, overflow] = merge(incoming, prev);
    if (overflow > 0) setDropped((d) => d + overflow);
    return next;
  }

  return { alerts, status, dropped };
}
