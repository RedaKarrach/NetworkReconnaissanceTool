import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ADMIN_TOKEN, API_BASE, WS_BASE } from "../lib/runtimeConfig";

function normalizeTimestamp(value) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (!trimmed) return trimmed;
  // Backend emits UTC without timezone suffix (e.g. 2026-04-27T12:00:00.123456).
  // JS treats that as local time, causing false "disconnected" states.
  if (/[zZ]$/.test(trimmed) || /[+-]\d{2}:\d{2}$/.test(trimmed)) return trimmed;
  return `${trimmed}Z`;
}

function normalizeInventoryItem(item) {
  if (!item || typeof item !== "object") return item;
  return {
    ...item,
    last_seen: normalizeTimestamp(item.last_seen),
  };
}

function upsertByAgent(items, incoming) {
  const normalizedIncoming = normalizeInventoryItem(incoming);
  const map = new Map(items.map((i) => [i.agent_id, i]));
  map.set(normalizedIncoming.agent_id, { ...map.get(normalizedIncoming.agent_id), ...normalizedIncoming });
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
      setItems((data.items || []).map(normalizeInventoryItem));
      setStatus("connected");
    } catch (e) {
      setError(e.message);
      setStatus("error");
    }
  }, []);

  const deleteInventoryItem = useCallback(async (payload) => {
    try {
      setError(null);
      const res = await fetch(`${API_BASE}/api/agents/inventory/`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          ...(ADMIN_TOKEN ? { "X-AGENT-TOKEN": ADMIN_TOKEN } : {}),
        },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      await refresh();
      return true;
    } catch (e) {
      setError(e.message);
      return false;
    }
  }, [refresh]);

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
          setItems((prev) => upsertByAgent(prev, normalizeInventoryItem(data)));
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

  return { items: sorted, status, error, refresh, deleteInventoryItem };
}
