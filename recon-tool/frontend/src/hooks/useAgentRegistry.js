import { useCallback, useEffect, useState } from "react";
import { API_BASE } from "../lib/runtimeConfig";

export function useAgentRegistry() {
  const [items, setItems] = useState([]);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch(`${API_BASE}/api/agents/registry/`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setItems(data.items || []);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  const addAgent = useCallback(async (payload) => {
    try {
      setError(null);
      const res = await fetch(`${API_BASE}/api/agents/registry/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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

  const deleteAgent = useCallback(async (payload) => {
    try {
      setError(null);
      const res = await fetch(`${API_BASE}/api/agents/registry/`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
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
    const timer = setInterval(refresh, 10000);
    return () => clearInterval(timer);
  }, [refresh]);

  return { items, error, refresh, addAgent, deleteAgent };
}
