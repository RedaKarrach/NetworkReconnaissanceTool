import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";
const WS_BASE = process.env.REACT_APP_WS_URL || "ws://localhost:8000";

function upsertByAgent(items, incoming) {
  const map = new Map(items.map((i) => [i.agent_id, i]));
  map.set(incoming.agent_id, { ...map.get(incoming.agent_id), ...incoming });
  return Array.from(map.values());
}

export function useInventory() {
  const [items, setItems] = useState([]);
  const [status, setStatus] = useState("disconnected");
  const [error, setError] = useState(null);
  const wsRef = useRef(null);

  const refresh = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch(`${API_BASE}/api/agents/inventory/latest/?limit=100`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setItems(data.items || []);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    setStatus("connecting");
    const ws = new WebSocket(`${WS_BASE}/ws/scan/inventory/`);
    wsRef.current = ws;

    ws.onopen = () => setStatus("connected");
    ws.onclose = () => setStatus("disconnected");
    ws.onerror = () => setStatus("error");

    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.event_type === "inventory" && data.agent_id) {
          setItems((prev) => upsertByAgent(prev, data));
        }
      } catch {
        // ignore malformed payloads
      }
    };

    return () => ws.close();
  }, []);

  const sorted = useMemo(() => {
    return [...items].sort((a, b) => {
      const ta = Date.parse(a.last_seen || 0);
      const tb = Date.parse(b.last_seen || 0);
      return tb - ta;
    });
  }, [items]);

  return { items: sorted, status, error, refresh };
}
