/**
 * hooks/useWebSocket.js
 * ---------------------
 * Connects to the Django Channels WebSocket for a scan session and
 * delivers live packet events to the component.
 *
 * Events are segregated by type so components can subscribe to only
 * what they need (packets, alerts, host discoveries, port results, etc.)
 */
import { useState, useEffect, useRef, useCallback } from "react";

const WS_BASE = process.env.REACT_APP_WS_URL || "ws://localhost:8000";

export function useWebSocket(sessionId) {
  const [packets, setPackets]         = useState([]);
  const [alerts, setAlerts]           = useState([]);
  const [hosts, setHosts]             = useState([]);
  const [portResults, setPortResults] = useState([]);
  const [osResults, setOsResults]     = useState([]);
  const [status, setStatus]           = useState("disconnected");
  const [pps, setPps]                 = useState(0);   // packets per second counter

  const wsRef        = useRef(null);
  const pktCountRef  = useRef(0);
  const ppsTimerRef  = useRef(null);

  // Calculate packets-per-second every second
  useEffect(() => {
    ppsTimerRef.current = setInterval(() => {
      setPps(pktCountRef.current);
      pktCountRef.current = 0;
    }, 1000);
    return () => clearInterval(ppsTimerRef.current);
  }, []);

  useEffect(() => {
    if (!sessionId) return;

    setStatus("connecting");
    const url = `${WS_BASE}/ws/scan/${sessionId}/`;
    const ws  = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setStatus("connected");

    ws.onmessage = (e) => {
      const data = JSON.parse(e.data);
      pktCountRef.current += 1;

      switch (data.event_type) {
        case "packet":
          setPackets((prev) => [data, ...prev].slice(0, 500));
          break;
        case "alert":
          setAlerts((prev) => [data, ...prev]);
          break;
        case "host_found":
          setHosts((prev) => [...prev, data]);
          break;
        case "port_result":
          setPortResults((prev) => [...prev, data]);
          break;
        case "os_result":
          setOsResults((prev) => [...prev, data]);
          break;
        case "status":
          setStatus(data.status);
          break;
        default:
          // Treat unknown events as generic packets
          setPackets((prev) => [data, ...prev].slice(0, 500));
      }
    };

    ws.onclose  = () => setStatus("disconnected");
    ws.onerror  = () => setStatus("error");

    return () => ws.close();
  }, [sessionId]);

  const send = useCallback((msg) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  return {
    packets, alerts, hosts, portResults, osResults,
    status, pps, send,
    // Convenience: combined raw event stream
    allEvents: packets,
  };
}
