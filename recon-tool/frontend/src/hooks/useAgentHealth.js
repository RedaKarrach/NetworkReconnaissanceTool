import { useCallback, useEffect, useState } from "react";
import { API_BASE } from "../lib/runtimeConfig";

export function useAgentHealth() {
  const [items, setItems] = useState([]);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch(`${API_BASE}/api/agents/health/?limit=200`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setItems(data.items || []);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 10000);
    return () => clearInterval(timer);
  }, [refresh]);

  return { items, error, refresh };
}