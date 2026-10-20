/**
 * hooks/useScan.js
 * ----------------
 * Encapsulates all REST API calls to the Django backend.
 * Returns action functions and loading/error state.
 */
import { useState, useCallback, useMemo } from "react";
import { API_BASE } from "../lib/runtimeConfig";

async function apiPost(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

async function apiGet(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export function useScan() {
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(null);

  const call = useCallback(async (fn) => {
    setLoading(true);
    setError(null);
    try {
      const result = await fn();
      return result;
    } catch (e) {
      setError(e.message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const startHostDiscovery = useCallback((subnet) => call(() => apiPost("/api/scan/host-discovery/", { subnet })), [call]);
  const startPortScan = useCallback((ip, ports, proto) => call(() => apiPost("/api/scan/port-scan/", { ip, ports, protocol: proto })), [call]);
  const startOsFingerprint = useCallback((ip) => call(() => apiPost("/api/scan/os-fingerprint/", { ip })), [call]);
  const startArpSpoof = useCallback((target_ip, gateway_ip) => call(() => apiPost("/api/attack/arp-spoof/", { target_ip, gateway_ip })), [call]);
  const startSynFlood = useCallback((target_ip, target_port) => call(() => apiPost("/api/attack/syn-flood/", { target_ip, target_port })), [call]);
  const startIcmpRedirect = useCallback(
    (target_ip, spoofed_gateway, attacker_ip, destination_ip) =>
      call(() => apiPost("/api/attack/icmp-redirect/", { target_ip, spoofed_gateway, attacker_ip, destination_ip })),
    [call],
  );
  const stopThread = useCallback((thread_id) => call(() => apiPost("/api/attack/stop/", { thread_id })), [call]);
  const getThreads = useCallback(() => call(() => apiGet("/api/threads/")), [call]);
  const getThreadStatus = useCallback((thread_id) => call(() => apiGet(`/api/threads/${thread_id}/`)), [call]);
  const getResults = useCallback((session_id) => call(() => apiGet(`/api/results/${session_id}/`)), [call]);

  return useMemo(() => ({
    loading,
    error,
    startHostDiscovery,
    startPortScan,
    startOsFingerprint,
    startArpSpoof,
    startSynFlood,
    startIcmpRedirect,
    stopThread,
    getThreads,
    getThreadStatus,
    getResults,
    getPdfUrl: (session_id) => `${API_BASE}/api/report/${session_id}/pdf/`,
  }), [
    loading,
    error,
    startHostDiscovery,
    startPortScan,
    startOsFingerprint,
    startArpSpoof,
    startSynFlood,
    startIcmpRedirect,
    stopThread,
    getThreads,
    getThreadStatus,
    getResults,
  ]);
}
