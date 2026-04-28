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
import { API_BASE, WS_BASE } from "../lib/runtimeConfig";

const MAX_PACKET_BUFFER = 500;
const MAX_ALERT_BUFFER = 300;

function isRealAlert(event) {
  const type = String(event?.type || "").toLowerCase();
  const message = String(event?.message || "").toLowerCase();

  if (!type && !message) return false;
  return true;
}

function alertKey(event) {
  return [
    String(event?.type || ""),
    String(event?.src_ip || ""),
    String(event?.dst_ip || ""),
    String(event?.message || ""),
    String(event?.timestamp || ""),
  ].join("|");
}

function upsertHostByIp(items, incoming) {
  const ip = String(incoming?.ip || "").trim();
  if (!ip) return items;

  const index = items.findIndex((item) => String(item?.ip || "").trim() === ip);
  if (index === -1) return [incoming, ...items].slice(0, 300);

  const next = [...items];
  next[index] = { ...next[index], ...incoming };
  return next;
}

function upsertOsResultByIp(items, incoming) {
  const ip = String(incoming?.ip || "").trim();
  if (!ip) return items;

  const index = items.findIndex((item) => String(item?.ip || "").trim() === ip);
  if (index === -1) return [incoming, ...items].slice(0, 300);

  const next = [...items];
  next[index] = { ...next[index], ...incoming };
  return next;
}

function appendUniquePortResult(items, incoming) {
  const ip = String(incoming?.ip || "").trim();
  const protocol = String(incoming?.protocol || "tcp").toLowerCase();
  const status = String(incoming?.status || "").toLowerCase();
  const port = Number(incoming?.port);
  const key = `${ip}|${protocol}|${status}|${port}`;

  const seen = new Set(items.map((item) => {
    const iIp = String(item?.ip || "").trim();
    const iProto = String(item?.protocol || "tcp").toLowerCase();
    const iStatus = String(item?.status || "").toLowerCase();
    const iPort = Number(item?.port);
    return `${iIp}|${iProto}|${iStatus}|${iPort}`;
  }));

  if (seen.has(key)) {
    return items;
  }

  return [incoming, ...items].slice(0, 500);
}

function isRealPacket(event) {
  const protocol = String(event?.protocol || "").trim();
  const srcIp = String(event?.src_ip || event?.src || "").trim();
  const dstIp = String(event?.dst_ip || event?.dst || "").trim();
  if (!protocol) return false;
  if (!srcIp || !dstIp) return false;
  return true;
}

function hasSynFlag(event) {
  const flags = String(event?.flags || "")
    .toUpperCase()
    .split(/[\s,|/]+/)
    .filter(Boolean);

  return flags.includes("SYN") || flags.includes("S") || flags.includes("SYN-FLOOD");
}

export function useWebSocket(sessionId) {
  const [packets, setPackets]         = useState([]);
  const [alerts, setAlerts]           = useState([]);
  const [hosts, setHosts]             = useState([]);
  const [portResults, setPortResults] = useState([]);
  const [osResults, setOsResults]     = useState([]);
  const [status, setStatus]           = useState("disconnected");
  const [pps, setPps]                 = useState(0);   // packets per second counter
  const [synPps, setSynPps]           = useState(0);

  const wsRef        = useRef(null);
  const pktCountRef  = useRef(0);
  const synCountRef  = useRef(0);
  const ppsTimerRef  = useRef(null);
  const alertSeenRef = useRef(new Set());

  // Calculate packets-per-second every second
  useEffect(() => {
    ppsTimerRef.current = setInterval(() => {
      setPps(pktCountRef.current);
      setSynPps(synCountRef.current);
      pktCountRef.current = 0;
      synCountRef.current = 0;
    }, 1000);
    return () => clearInterval(ppsTimerRef.current);
  }, []);

  useEffect(() => {
    if (!sessionId) return;

    setStatus("connecting");
    setPackets([]);
    setAlerts([]);
    setHosts([]);
    setPortResults([]);
    setOsResults([]);
    setPps(0);
    setSynPps(0);
    pktCountRef.current = 0;
    synCountRef.current = 0;
    alertSeenRef.current = new Set();
    const url = `${WS_BASE}/ws/scan/${sessionId}/`;
    const ws  = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setStatus("connected");

    ws.onmessage = (e) => {
      let data;
      try {
        data = JSON.parse(e.data);
      } catch {
        // Ignore malformed frames so one bad message cannot crash the app.
        return;
      }

      if (!data || typeof data !== "object") return;

      switch (data.event_type) {
        case "packet":
          if (!isRealPacket(data)) break;
          pktCountRef.current += 1;
          if (hasSynFlag(data)) {
            synCountRef.current += 1;
          }
          setPackets((prev) => [data, ...prev].slice(0, MAX_PACKET_BUFFER));
          break;
        case "alert":
          if (!isRealAlert(data)) break;

          {
            const key = alertKey(data);
            if (alertSeenRef.current.has(key)) break;
            alertSeenRef.current.add(key);
          }

          setAlerts((prev) => [data, ...prev].slice(0, MAX_ALERT_BUFFER));
          break;
        case "host_found":
          setHosts((prev) => upsertHostByIp(prev, data));
          break;
        case "port_result":
          setPortResults((prev) => appendUniquePortResult(prev, data));
          break;
        case "os_result":
          setOsResults((prev) => upsertOsResultByIp(prev, data));
          break;
        case "status":
          setStatus(data.status);
          break;
        default:
          // Ignore non-packet control/heartbeat events.
          break;
      }
    };

    ws.onclose  = () => setStatus("disconnected");
    ws.onerror  = () => setStatus("error");

    return () => ws.close();
  }, [sessionId]);

  useEffect(() => {
    if (!sessionId) return;

    const controller = new AbortController();

    async function loadHistory() {
      try {
        const [packetsRes, alertsRes] = await Promise.all([
          fetch(`${API_BASE}/api/packets/history/${sessionId}/?limit=${MAX_PACKET_BUFFER}`, { signal: controller.signal }),
          fetch(`${API_BASE}/api/alerts/history/${sessionId}/?limit=${MAX_ALERT_BUFFER}`, { signal: controller.signal }),
        ]);

        if (packetsRes.ok) {
          const packetsData = await packetsRes.json();
          const items = Array.isArray(packetsData?.items) ? packetsData.items : [];
          setPackets(items.slice(0, MAX_PACKET_BUFFER));
        }

        if (alertsRes.ok) {
          const alertsData = await alertsRes.json();
          const items = Array.isArray(alertsData?.items) ? alertsData.items : [];
          setAlerts(items.filter(isRealAlert).slice(0, MAX_ALERT_BUFFER));
          alertSeenRef.current = new Set(items.map(alertKey));
        }
      } catch {
        // Ignore history failures; live stream can still populate.
      }
    }

    loadHistory();
    return () => controller.abort();
  }, [sessionId]);

  const send = useCallback((msg) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  return {
    packets, alerts, hosts, portResults, osResults,
    status, pps, synPps, send,
    // Convenience: combined raw event stream
    allEvents: packets,
  };
}
