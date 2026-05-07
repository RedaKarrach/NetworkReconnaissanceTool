import React, { useCallback, useEffect, useMemo, useState } from "react";
import NetworkMap from "../components/NetworkMap";
import PortMatrix from "../components/PortMatrix";
import OSFingerprintPanel from "../components/OSFingerprintPanel";
import PacketInspector from "../components/PacketInspector";
import { useScan } from "../hooks/useScan";
import { useWebSocket } from "../hooks/useWebSocket";
import { useInventory } from "../hooks/useInventory";
import { useAgentRegistry } from "../hooks/useAgentRegistry";

function RadarIcon({ className = "h-5 w-5" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="4" />
      <path d="m12 12 5.6-3.2" />
    </svg>
  );
}

function PortsIcon({ className = "h-5 w-5" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <rect x="4" y="4" width="6" height="6" rx="1" />
      <rect x="14" y="4" width="6" height="6" rx="1" />
      <rect x="4" y="14" width="6" height="6" rx="1" />
      <rect x="14" y="14" width="6" height="6" rx="1" />
    </svg>
  );
}

function FingerprintIcon({ className = "h-5 w-5" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M12 4a6 6 0 0 0-6 6" />
      <path d="M18 10a6 6 0 0 0-6-6" />
      <path d="M8 14c0 4-1 6-3 8" />
      <path d="M12 10c0 6-1 9-4 12" />
      <path d="M16 14c0 4 1 6 3 8" />
      <path d="M12 14c0 4 1 7 3 10" />
    </svg>
  );
}

function SpinnerIcon() {
  return <span className="h-4 w-4 animate-spin rounded-full border-2 border-text-primary border-t-transparent" />;
}

const TABS = [
  { id: "map", label: "Network Map" },
  { id: "ports", label: "Port Matrix" },
  { id: "os", label: "OS Fingerprints" },
  { id: "pkts", label: "Packet Inspector" },
];

const RISKY_PORTS = {
  21: { severity: "medium", title: "FTP Service Exposed", cve: "CWE-200", cvss: 5.3 },
  23: { severity: "high", title: "Telnet Service Exposed", cve: "CWE-319", cvss: 7.5 },
  445: { severity: "high", title: "SMB Service Exposed", cve: "CVE-2017-0144", cvss: 8.1 },
  3389: { severity: "medium", title: "RDP Service Exposed", cve: "CWE-284", cvss: 6.5 },
  6379: { severity: "high", title: "Redis Service Exposed", cve: "CWE-306", cvss: 7.5 },
};

const SEVERITY_BADGE = {
  critical: "bg-threat-critical/20 border-threat-critical/40 text-threat-critical",
  high: "bg-threat-high/20 border-threat-high/40 text-threat-high",
  medium: "bg-threat-medium/20 border-threat-medium/40 text-threat-medium",
  low: "bg-threat-low/20 border-threat-low/40 text-threat-low",
  info: "bg-bg-elevated border-border-default text-text-tertiary",
};

function asIsoTime(value) {
  if (!value) return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return null;
  return new Date(parsed).toISOString();
}

function formatClock(value) {
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return "--:--:--";
  return new Date(parsed).toLocaleTimeString();
}

function normalizeIp(value) {
  return String(value || "").trim();
}

function isUsableEndpointIp(value) {
  const ip = normalizeIp(value);
  if (!ip) return false;
  if (ip.includes(":")) return false;
  if (ip.startsWith("127.")) return false;
  if (ip.startsWith("169.254.")) return false;
  if (ip === "0.0.0.0") return false;

  const parts = ip.split(".").map((n) => Number(n));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  return true;
}

function endpointIpRank(ip) {
  if (ip.startsWith("192.168.")) return 3;
  if (ip.startsWith("10.")) return 2;
  if (ip.startsWith("172.")) {
    const secondOctet = Number(ip.split(".")[1]);
    if (Number.isInteger(secondOctet) && secondOctet >= 16 && secondOctet <= 31) return 2;
  }
  return 1;
}

function pickPrimaryEndpointIp(ips) {
  if (!Array.isArray(ips)) return "";
  const usable = ips.map((raw) => normalizeIp(raw)).filter((ip) => isUsableEndpointIp(ip));
  if (!usable.length) return "";
  return [...usable].sort((a, b) => endpointIpRank(b) - endpointIpRank(a))[0];
}

function normalizeToken(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeSeverity(value) {
  const sev = String(value || "low").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(sev)) return sev;
  return "low";
}

function toUnitConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  if (numeric > 1) return Math.max(0, Math.min(1, numeric / 100));
  return Math.max(0, Math.min(1, numeric));
}

function inferVulnMetadataFromAlert(alert) {
  const msg = String(alert?.message || alert?.type || "").toLowerCase();
  if (msg.includes("eternalblue") || msg.includes("smbv1")) {
    return { title: "SMBv1 Enabled - EternalBlue", cve: "CVE-2017-0144", cvss: 8.1 };
  }
  if (msg.includes("path traversal") || msg.includes("apache")) {
    return { title: "Apache HTTP Server Path Traversal", cve: "CVE-2021-41773", cvss: 9.8 };
  }
  if (msg.includes("redis") && msg.includes("auth")) {
    return { title: "Redis No Authentication", cve: "CWE-306", cvss: 7.5 };
  }
  if (msg.includes("ssh") && msg.includes("key")) {
    return { title: "Weak SSH Host Key", cve: "CWE-326", cvss: 5.3 };
  }
  return {
    title: alert?.message || alert?.type || "Security Finding",
    cve: "CWE-200",
    cvss: normalizeSeverity(alert?.severity) === "critical" ? 9.0 : 6.0,
  };
}

function buildVulnerabilityLog(alerts, portResults) {
  const entries = [];
  const seen = new Set();

  (alerts || []).forEach((alert, idx) => {
    const host = alert?.src_ip && alert.src_ip !== "scanner" ? alert.src_ip : alert?.dst_ip || "unknown";
    const base = inferVulnMetadataFromAlert(alert);
    const key = `${host}-${alert?.type || "alert"}-${alert?.timestamp || idx}`;
    if (seen.has(key)) return;
    seen.add(key);
    entries.push({
      id: key,
      source: "alert",
      severity: normalizeSeverity(alert?.severity),
      title: base.title,
      cve: base.cve,
      cvss: Number(base.cvss || 0),
      host,
      port: "--",
      timestamp: asIsoTime(alert?.timestamp) || new Date().toISOString(),
    });
  });

  (portResults || []).forEach((result, idx) => {
    if (String(result?.status || "").toLowerCase() !== "open") return;
    const port = Number(result?.port);
    if (!Number.isInteger(port) || !RISKY_PORTS[port]) return;
    const meta = RISKY_PORTS[port];
    const host = result?.ip || "unknown";
    const key = `${host}-${port}-${result?.timestamp || idx}`;
    if (seen.has(key)) return;
    seen.add(key);
    entries.push({
      id: key,
      source: "port_result",
      severity: meta.severity,
      title: meta.title,
      cve: meta.cve,
      cvss: meta.cvss,
      host,
      port,
      timestamp: asIsoTime(result?.timestamp) || new Date().toISOString(),
    });
  });

  return entries.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
}

function parsePorts(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) return [];

  const unique = new Set();
  value.split(",").forEach((chunk) => {
    const part = chunk.trim();
    if (!part) return;

    if (part.includes("-")) {
      const [a, b] = part.split("-").map((n) => Number(n.trim()));
      if (!Number.isInteger(a) || !Number.isInteger(b)) return;
      const start = Math.max(1, Math.min(a, b));
      const end = Math.min(65535, Math.max(a, b));
      for (let p = start; p <= end; p += 1) {
        unique.add(p);
      }
      return;
    }

    const single = Number(part);
    if (Number.isInteger(single) && single >= 1 && single <= 65535) {
      unique.add(single);
    }
  });

  return Array.from(unique).sort((a, b) => a - b);
}

function getScanStatus(type, runningType, completedType) {
  if (runningType === type) return "Running";
  if (completedType === type) return "Complete";
  return "Idle";
}

function statusBadgeClass(status) {
  if (status === "Running") {
    return "bg-threat-critical-bg border border-threat-critical-border text-threat-critical-text";
  }
  if (status === "Complete") {
    return "bg-status-success/20 border border-status-success text-status-success";
  }
  return "bg-bg-elevated border border-border-default text-text-tertiary";
}

function ScanCard({
  title,
  Icon,
  iconClass,
  topAccentClass,
  status,
  description,
  children,
  idleButtonClass,
  onLaunch,
  onStop,
  disabled,
  hint,
  busyLabel,
}) {
  return (
    <div className="group/card card-premium-interactive overflow-hidden flex flex-col transition-all duration-300 animate-slide-in-bottom hover:elevation-3">
      {/* Top accent stripe */}
      <div className={`${topAccentClass} h-0.5 w-full transition-all duration-300 group-hover/card:h-1`} />

      {/* Content */}
      <div className="flex-1 p-6 flex flex-col">
        {/* Header */}
        <div className="mb-5 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className={`flex-shrink-0 p-2 rounded-lg ${
              topAccentClass === "bg-status-success" ? "bg-status-success/20" :
              topAccentClass === "bg-accent-primary" ? "bg-accent-primary/20" :
              "bg-os-macos/20"
            }`}>
              <Icon className={iconClass} />
            </div>
            <div className="min-w-0">
              <h3 className="text-lg font-bold text-text-primary group-hover/card:text-accent-primary transition-colors duration-200">{title}</h3>
              <p className="text-xs font-medium text-text-tertiary mt-0.5">{description}</p>
            </div>
          </div>

          {/* Status badge */}
          <div className={`badge-premium flex-shrink-0 ${
            status === "Running" ? "badge-premium-critical" :
            status === "Complete" ? "badge-premium-success" :
            "bg-bg-elevated border-border-default text-text-secondary"
          }`}>
            {status === "Running" && (
              <>
                <span className="relative flex h-1.5 w-1.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-threat-critical opacity-75" />
                  <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-threat-critical" />
                </span>
              </>
            )}
            {status === "Complete" && (
              <svg className="h-3 w-3" viewBox="0 0 24 24" fill="currentColor">
                <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
              </svg>
            )}
            <span className="text-xs font-semibold">{status}</span>
          </div>
        </div>

        {/* Form fields */}
        <div className="space-y-4 mb-6 flex-1">
          {children}
        </div>

        {/* Action button */}
        {status === "Running" ? (
          <button
            type="button"
            onClick={onStop}
            className="group/btn relative mt-auto w-full overflow-hidden rounded-lg px-4 py-3 text-sm font-semibold text-bg-app transition-all duration-300 active:scale-95"
          >
            <div className="absolute inset-0 bg-gradient-to-r from-threat-critical to-threat-high" />
            <div className="absolute inset-0 opacity-0 group-hover/btn:opacity-100 transition-opacity duration-300"
              style={{
                boxShadow: "0 0 20px rgba(239, 68, 68, 0.4), inset 0 0 10px rgba(255, 255, 255, 0.1)",
              }}
            />
            <span className="relative flex items-center justify-center gap-2">
              <span className="h-2 w-2 rounded-full bg-white animate-pulse" />
              Stop Scan
            </span>
          </button>
        ) : status === "Complete" ? (
          <div className="mt-auto w-full rounded-lg border border-status-success/50 bg-status-success/10 py-3 text-center text-sm font-semibold text-status-success">
            ✓ Scan Complete
          </div>
        ) : (
          <button
            type="button"
            onClick={onLaunch}
            disabled={disabled}
            className={`group/btn relative mt-auto w-full overflow-hidden rounded-lg px-4 py-3 text-sm font-semibold transition-all duration-300 active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {/* Button background - uses provided class for color */}
            <div className={`absolute inset-0 ${idleButtonClass} transition-all duration-300`} />

            {/* Glow on hover */}
            <div className="absolute inset-0 opacity-0 group-hover/btn:opacity-100 transition-opacity duration-300"
              style={{
                boxShadow: "0 0 20px rgba(0, 212, 255, 0.4), inset 0 0 10px rgba(255, 255, 255, 0.1)",
              }}
            />

            <span className="relative flex items-center justify-center gap-2 text-text-primary">
              {busyLabel || "Launch Scan"}
              <svg className="h-4 w-4 transition-transform duration-300 group-hover/btn:translate-x-1" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
            </span>
          </button>
        )}

        {hint ? (
          <div className="mt-3 rounded-md border border-border-default/60 bg-bg-elevated/60 px-3 py-2 text-xs text-text-tertiary">
            {hint}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default function Dashboard({ onSessionStart }) {
  const { startHostDiscovery, startPortScan, startOsFingerprint, stopThread, getThreads, loading, error } = useScan();
  const { items: inventoryItems } = useInventory();
  const { items: registryItems } = useAgentRegistry();

  const [sessionId, setSessionId] = useState(null);
  const [threadId, setThreadId] = useState(null);
  const [subnet, setSubnet] = useState("192.168.56.0/24");
  const [scanIp, setScanIp] = useState("192.168.56.20");
  const [ports, setPorts] = useState("22,80,443,3389");
  const [protocol, setProtocol] = useState("tcp");
  const [fpIp, setFpIp] = useState("192.168.56.20");
  const [activeTab, setActiveTab] = useState("map");
  const [selectedEndpointIp, setSelectedEndpointIp] = useState(null);

  const [runningScanType, setRunningScanType] = useState(null);
  const [completedScanType, setCompletedScanType] = useState(null);
  const [launchingType, setLaunchingType] = useState(null);

  useEffect(() => {
    let mounted = true;

    const scanTypeMap = {
      host_discovery: "discovery",
      port_scan: "port",
      os_fingerprint: "fingerprint",
    };

    async function restoreActiveScan() {
      const result = await getThreads();
      const items = Array.isArray(result?.items) ? result.items : [];
      const activeScan = items.find((item) => item?.alive && item?.meta?.kind === "scan");
      if (!mounted || !activeScan) return;

      const restoredType = scanTypeMap[activeScan.meta.scan_type] || null;
      if (!restoredType) return;

      setSessionId(activeScan.meta.session_id || null);
      setThreadId(activeScan.thread_id || null);
      setRunningScanType(restoredType);
      if (onSessionStart && activeScan.meta.session_id) {
        onSessionStart(activeScan.meta.session_id);
      }
    }

    restoreActiveScan();
    return () => {
      mounted = false;
    };
  }, [getThreads, onSessionStart]);

  const ws = useWebSocket(sessionId);

  const endpointHosts = useMemo(() => {
    const byKey = new Map();
    const byIp = new Map();
    const cloneIdentity = new Set();
    const hasRegistry = Array.isArray(registryItems) && registryItems.length > 0;

    const addEndpoint = (endpoint) => {
      const key = normalizeToken(endpoint.agent_id || endpoint.hostname || endpoint.ip);
      if (key && byKey.has(key)) return byKey.get(key);

      if (key) byKey.set(key, endpoint);
      if (!byIp.has(endpoint.ip)) byIp.set(endpoint.ip, []);
      byIp.get(endpoint.ip).push(endpoint);
      return endpoint;
    };

    // Seed with registered endpoints only.
    (registryItems || []).forEach((item) => {
      const ip = normalizeIp(item?.ip);
      if (!isUsableEndpointIp(ip)) return;

      const agentKey = normalizeToken(item?.agent_id || item?.hostname || ip);
      if (agentKey && byKey.has(agentKey)) return;

      const identityKey = `${normalizeToken(item?.hostname)}|${normalizeToken(item?.os_name)}`;
      if (identityKey !== "|" && cloneIdentity.has(identityKey)) return;
      cloneIdentity.add(identityKey);

      const endpoint = addEndpoint({
        ip,
        agent_id: item.agent_id || ip,
        hostname: item.hostname || "--",
        mac: "--",
        os_guess: item.os_name || "unknown",
        confidence: 0,
        open_ports: [],
        open_port_details: [],
        source_tags: new Set(["registry"]),
        last_seen: null,
      });

      if (agentKey) byKey.set(agentKey, endpoint);
    });

    (inventoryItems || []).forEach((item) => {
      const agentKey = normalizeToken(item?.agent_id || item?.hostname);
      let endpoint = agentKey ? byKey.get(agentKey) : null;

      if (!endpoint) {
        const ip = pickPrimaryEndpointIp(item?.ips);
        if (!ip) return;
        const matches = byIp.get(ip) || [];
        endpoint = agentKey ? null : matches[0] || null;

        if (!endpoint) {
          endpoint = addEndpoint({
            ip,
            agent_id: item.agent_id || ip,
            hostname: item.hostname || "--",
            mac: (Array.isArray(item.macs) && item.macs[0]) || "--",
            os_guess: [item.os_name, item.os_version].filter(Boolean).join(" ") || "unknown",
            confidence: 0,
            open_ports: Array.isArray(item.open_ports) ? item.open_ports : [],
            open_port_details: [],
            source_tags: new Set(["inventory"]),
            last_seen: item.last_seen || null,
          });
          if (agentKey) byKey.set(agentKey, endpoint);
        }
      }

      if (!endpoint) return;
      endpoint.hostname = item.hostname || endpoint.hostname;
      endpoint.mac = (Array.isArray(item.macs) && item.macs[0]) || endpoint.mac;
      endpoint.os_guess = [item.os_name, item.os_version].filter(Boolean).join(" ") || endpoint.os_guess;
      endpoint.open_ports = Array.isArray(item.open_ports) ? item.open_ports : endpoint.open_ports;
      endpoint.last_seen = item.last_seen || endpoint.last_seen;
      endpoint.source_tags.add("inventory");
    });

    (ws.hosts || []).forEach((host) => {
      const ip = normalizeIp(host?.ip);
      if (!isUsableEndpointIp(ip)) return;
      const targets = byIp.get(ip) || [];
      targets.forEach((endpoint) => {
        endpoint.hostname = host.hostname || endpoint.hostname;
        endpoint.mac = host.mac || endpoint.mac;
        endpoint.os_guess = host.os_guess || endpoint.os_guess;
        endpoint.source_tags.add("discovery");
      });
    });

    (ws.osResults || []).forEach((result) => {
      const ip = normalizeIp(result?.ip);
      if (!isUsableEndpointIp(ip)) return;
      const targets = byIp.get(ip) || [];
      targets.forEach((endpoint) => {
        endpoint.os_guess = result.os_guess || endpoint.os_guess;
        endpoint.confidence = toUnitConfidence(result.confidence ?? endpoint.confidence);
        endpoint.source_tags.add("fingerprint");
      });
    });

    (ws.portResults || []).forEach((result) => {
      const ip = normalizeIp(result?.ip);
      if (!isUsableEndpointIp(ip)) return;
      const targets = byIp.get(ip) || [];
      if (!targets.length) return;
      const status = String(result?.status || "").toLowerCase();
      targets.forEach((endpoint) => {
        if (status === "open" && Number.isInteger(Number(result.port))) {
          endpoint.open_ports.push(Number(result.port));
          endpoint.open_port_details.push({
            port: Number(result.port),
            protocol: result.protocol || "tcp",
            status,
            banner: result.banner || "",
            timestamp: result.timestamp,
          });
        }
        endpoint.source_tags.add("portscan");
      });
    });

    return Array.from(byKey.values())
      .map((endpoint) => ({
        ...endpoint,
        open_ports: Array.from(new Set(endpoint.open_ports)).sort((a, b) => a - b),
        source_tags: Array.from(endpoint.source_tags),
      }))
      .sort((a, b) => a.ip.localeCompare(b.ip));
  }, [ws.hosts, ws.osResults, ws.portResults, inventoryItems, registryItems]);

  const handleSelectEndpoint = useCallback((host) => {
    if (!host?.ip) return;
    setSelectedEndpointIp(host.ip);
    setScanIp(host.ip);
    setFpIp(host.ip);
  }, []);

  const vulnerabilities = useMemo(() => {
    return buildVulnerabilityLog(ws.alerts, ws.portResults);
  }, [ws.alerts, ws.portResults]);

  const selectedEndpoint = useMemo(() => {
    if (!selectedEndpointIp) return endpointHosts[0] || null;
    return endpointHosts.find((endpoint) => endpoint.ip === selectedEndpointIp) || null;
  }, [endpointHosts, selectedEndpointIp]);

  useEffect(() => {
    if (!endpointHosts.length) {
      setSelectedEndpointIp(null);
      return;
    }
    if (!selectedEndpointIp || !endpointHosts.some((endpoint) => endpoint.ip === selectedEndpointIp)) {
      setSelectedEndpointIp(endpointHosts[0].ip);
    }
  }, [endpointHosts, selectedEndpointIp]);

  const selectedEndpointVulns = useMemo(() => {
    if (!selectedEndpoint?.ip) return vulnerabilities;
    return vulnerabilities.filter((v) => v.host === selectedEndpoint.ip);
  }, [vulnerabilities, selectedEndpoint]);

  useEffect(() => {
    if (!completedScanType) return;
    const timer = setTimeout(() => setCompletedScanType(null), 1200);
    return () => clearTimeout(timer);
  }, [completedScanType]);

  async function launchScan(type, action) {
    if (runningScanType) return;

    setCompletedScanType(null);
    setRunningScanType(type);
    setLaunchingType(type);

    const result = await action();
    if (!result || !result.session_id) {
      setRunningScanType(null);
      setLaunchingType(null);
      return null;
    }

    setSessionId(result.session_id);
    setThreadId(result.thread_id || null);
    if (onSessionStart) onSessionStart(result.session_id);
    setLaunchingType(null);
    return result;
  }

  async function stopAllScans() {
    if (threadId) {
      await stopThread(threadId);
    }

    if (runningScanType) {
      setCompletedScanType(runningScanType);
    }
    setRunningScanType(null);
    setThreadId(null);
    setLaunchingType(null);
  }

  async function handleHostDiscovery() {
    await launchScan("discovery", () => startHostDiscovery(subnet));
  }

  async function handlePortScan() {
    const parsedPorts = parsePorts(ports);
    if (!scanIp || parsedPorts.length === 0) return;
    const result = await launchScan("port", () => startPortScan(scanIp, parsedPorts, protocol));
    if (result) setSelectedEndpointIp(scanIp);
  }

  async function handleFingerprint() {
    if (!fpIp) return;
    const result = await launchScan("fingerprint", () => startOsFingerprint(fpIp));
    if (result) setSelectedEndpointIp(fpIp);
  }

  const sessionPreview = sessionId
    ? `${sessionId.slice(0, 18)}${sessionId.length > 18 ? "…" : ""}`
    : "";

  const isSessionRunning = Boolean(runningScanType && sessionId);

  const scanHint = useMemo(() => {
    if (!error) return "";
    const message = String(error).toLowerCase();
    if (message.includes("ip not in allowed subnet")) {
      return "Target IP is outside the allowed subnet (SCAN_ALLOWED_SUBNET).";
    }
    if (message.includes("ip unreachable")) {
      return "Target did not respond to ping; ensure inventory/registry is online or adjust firewall.";
    }
    if (message.includes("subnet required")) {
      return "Subnet is required (example: 192.168.56.0/24).";
    }
    if (message.includes("ip required")) {
      return "Target IP is required.";
    }
    return "";
  }, [error]);

  return (
    <div className="scene-3d flex h-full min-h-0 flex-col gap-6">
      {/* Scan Controls Grid */}
      <section className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <ScanCard
          title="Host Discovery"
          Icon={RadarIcon}
          iconClass="h-5 w-5 text-status-success"
          topAccentClass="bg-status-success"
          status={getScanStatus("discovery", runningScanType, completedScanType)}
          description="ARP broadcast sweep across subnet"
          idleButtonClass="bg-gradient-to-r from-status-success to-status-online"
          onLaunch={handleHostDiscovery}
          onStop={stopAllScans}
          disabled={Boolean(runningScanType)}
          hint={scanHint}
          busyLabel={launchingType === "discovery" ? "Launching..." : ""}
        >
          <div>
            <label className="mb-2.5 block text-sm font-semibold text-text-primary">Subnet</label>
            <input
              value={subnet}
              onChange={(event) => setSubnet(event.target.value)}
              placeholder="192.168.56.0/24"
              className="w-full rounded-lg border border-border-default bg-bg-input/60 px-4 py-2.5 font-mono text-sm text-text-primary outline-none transition-all duration-200 placeholder:text-text-tertiary focus:border-accent-primary focus:ring-2 focus:ring-accent-muted hover:border-border-elevated"
              style={{ backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}
            />
          </div>
        </ScanCard>

        <ScanCard
          title="Port Scan"
          Icon={PortsIcon}
          iconClass="h-5 w-5 text-accent-primary"
          topAccentClass="bg-accent-primary"
          status={getScanStatus("port", runningScanType, completedScanType)}
          description="SYN stealth scan + banner grabbing"
          idleButtonClass="bg-gradient-to-r from-accent-hover to-accent-primary"
          onLaunch={handlePortScan}
          onStop={stopAllScans}
          disabled={Boolean(runningScanType) || !scanIp}
          hint={scanHint}
          busyLabel={launchingType === "port" ? "Launching..." : ""}
        >
          <div>
            <label className="mb-2.5 block text-sm font-semibold text-text-primary">Target IP</label>
            <input
              value={scanIp}
              onChange={(event) => setScanIp(event.target.value)}
              placeholder="192.168.56.20"
              className="w-full rounded-lg border border-border-default bg-bg-input/60 px-4 py-2.5 font-mono text-sm text-text-primary outline-none transition-all duration-200 placeholder:text-text-tertiary focus:border-accent-primary focus:ring-2 focus:ring-accent-muted hover:border-border-elevated"
              style={{ backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}
            />
          </div>

          <div>
            <label className="mb-2.5 block text-sm font-semibold text-text-primary">Ports</label>
            <input
              value={ports}
              onChange={(event) => setPorts(event.target.value)}
              placeholder="22,80,443,3389"
              className="w-full rounded-lg border border-border-default bg-bg-input/60 px-4 py-2.5 font-mono text-sm text-text-primary outline-none transition-all duration-200 placeholder:text-text-tertiary focus:border-accent-primary focus:ring-2 focus:ring-accent-muted hover:border-border-elevated"
              style={{ backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}
            />
          </div>

          <div>
            <label className="mb-2.5 block text-sm font-semibold text-text-primary">Protocol</label>
            <div className="inline-flex rounded-lg border border-border-default bg-bg-elevated/40 p-1.5" style={{ backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}>
              {["tcp", "udp"].map((proto) => (
                <button
                  key={proto}
                  type="button"
                  onClick={() => setProtocol(proto)}
                  className={`rounded-md px-4 py-1.5 text-sm font-semibold transition-all duration-200 uppercase ${
                    protocol === proto
                      ? "bg-accent-primary text-bg-app shadow-card-glow"
                      : "text-text-tertiary hover:text-text-secondary"
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>
          </div>
        </ScanCard>

        <ScanCard
          title="OS Fingerprint"
          Icon={FingerprintIcon}
          iconClass="h-5 w-5 text-os-macos"
          topAccentClass="bg-os-macos"
          status={getScanStatus("fingerprint", runningScanType, completedScanType)}
          description="Triple-signal passive OS detection"
          idleButtonClass="bg-gradient-to-r from-os-macos to-accent-primary"
          onLaunch={handleFingerprint}
          onStop={stopAllScans}
          disabled={Boolean(runningScanType) || !fpIp}
          hint={scanHint}
          busyLabel={launchingType === "fingerprint" ? "Launching..." : ""}
        >
          <div>
            <label className="mb-2.5 block text-sm font-semibold text-text-primary">Target IP</label>
            <input
              value={fpIp}
              onChange={(event) => setFpIp(event.target.value)}
              placeholder="192.168.56.20"
              className="w-full rounded-lg border border-border-default bg-bg-input/60 px-4 py-2.5 font-mono text-sm text-text-primary outline-none transition-all duration-200 placeholder:text-text-tertiary focus:border-accent-primary focus:ring-2 focus:ring-accent-muted hover:border-border-elevated"
              style={{ backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}
            />
          </div>

          <div className="flex flex-wrap gap-2">
            {["TTL Analysis", "TCP Window", "Xmas Scan"].map((label) => (
              <span key={label} className="rounded-full border border-border-default bg-white/[0.05] px-3 py-1.5 text-xs font-medium text-text-tertiary">
                {label}
              </span>
            ))}
          </div>
        </ScanCard>
      </section>

      {/* Session Status Bar */}
      {isSessionRunning && (
        <section className="group/session card-premium relative overflow-hidden animate-slide-in-bottom tilt-3d">
          {/* Animated background gradient */}
          <div className="absolute inset-0 opacity-0 group-hover/session:opacity-100 transition-opacity duration-500"
            style={{
              background: "linear-gradient(90deg, transparent, rgba(0,212,255,0.05), transparent)",
            }}
          />

          <div className="relative flex items-center gap-4 p-5">
            {/* Status indicator */}
            <div className="flex items-center gap-3">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-status-online opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-status-online" />
              </span>
              <div className="min-w-0">
                <p className="text-sm font-semibold text-text-primary">Session Active</p>
                <p className="truncate font-mono text-xs text-text-tertiary">{sessionPreview}</p>
              </div>
            </div>

            {/* Metrics */}
            <div className="ml-auto flex items-center gap-6">
              <div className="text-right">
                <p className="text-xs font-medium text-text-tertiary uppercase tracking-wide">Traffic Rate</p>
                <p className="font-mono text-xl font-bold text-accent-primary mt-1">{ws.pps} <span className="text-xs text-text-tertiary">pkt/s</span></p>
              </div>

              {/* Stop button */}
              <button
                type="button"
                onClick={stopAllScans}
                className="group/btn relative flex-shrink-0 overflow-hidden rounded-lg px-4 py-2.5 text-sm font-semibold text-text-primary transition-all duration-300 active:scale-95"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-threat-critical to-threat-high" />
                <div className="absolute inset-0 opacity-0 group-hover/btn:opacity-100 transition-opacity duration-300"
                  style={{
                    boxShadow: "0 0 16px rgba(239, 68, 68, 0.4), inset 0 0 8px rgba(255, 255, 255, 0.1)",
                  }}
                />
                <span className="relative flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
                  Stop All
                </span>
              </button>
            </div>
          </div>
        </section>
      )}

      {/* Error Alert */}
      {error && (
        <div className="card-premium border-l-4 border-threat-critical bg-gradient-to-r from-threat-critical-bg to-threat-critical-bg/50 text-threat-critical-text p-4 animate-slide-in-bottom">
          <div className="flex items-start gap-3">
            <svg className="h-5 w-5 flex-shrink-0 mt-0.5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z" />
            </svg>
            <p className="text-sm font-medium">{error}</p>
          </div>
        </div>
      )}

      {/* Visualization Tabs and Content */}
      <section className="flex min-h-0 flex-1 flex-col gap-4">
        {/* Tab Navigation */}
        <div className="flex gap-2 border-b border-border-premium/40 overflow-x-auto">
          {TABS.map((tab, idx) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`relative px-5 py-3.5 text-sm font-semibold transition-all duration-300 whitespace-nowrap stagger-item`}
                style={{ animationDelay: `${idx * 30}ms` }}
              >
                {/* Bottom border indicator */}
                {isActive && (
                  <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-accent-primary to-accent-hover rounded-full" />
                )}

                <span className={isActive ? "text-accent-primary" : "text-text-tertiary hover:text-text-secondary"}>
                  {tab.label}
                </span>
              </button>
            );
          })}
        </div>

        {/* Content Area */}
        <div className="flex min-h-0 flex-1 rounded-xl border border-border-premium overflow-hidden tilt-3d-soft" style={{
          background: "linear-gradient(135deg, rgba(18, 27, 42, 0.5) 0%, rgba(22, 34, 53, 0.4) 100%)",
          backdropFilter: "blur(8px)",
          WebkitBackdropFilter: "blur(8px)",
        }}>
          <div className="h-full w-full overflow-auto">
            {activeTab === "map" && (
              <div className="h-full w-full p-4">
                <div className="grid h-full min-h-[560px] grid-cols-1 gap-4 xl:grid-cols-[1.9fr_1fr]">
                  <div className="panel-premium min-h-[560px] overflow-hidden">
                    <NetworkMap
                      hosts={endpointHosts}
                      selectedHostId={selectedEndpoint?.ip || null}
                      onSelectHost={handleSelectEndpoint}
                    />
                  </div>

                  <div className="flex min-h-[560px] flex-col gap-4">
                    <div className="panel-premium p-4">
                      <div className="mb-3 flex items-center justify-between">
                        <h3 className="text-xs uppercase tracking-widest text-text-tertiary">Endpoint Intel</h3>
                        <span className="orbital-tag">{endpointHosts.length} endpoints</span>
                      </div>

                      {!selectedEndpoint ? (
                        <div className="rounded-md border border-border-default bg-bg-elevated/60 px-3 py-2 text-sm text-text-tertiary">
                          No endpoint selected yet.
                        </div>
                      ) : (
                        <div className="space-y-3">
                          <div className="rounded-lg border border-border-default/70 bg-bg-elevated/60 p-3">
                            <div className="font-mono text-lg font-semibold text-text-primary">{selectedEndpoint.ip}</div>
                            <div className="mt-1 text-sm text-text-secondary">{selectedEndpoint.hostname || "unknown-host"}</div>
                          </div>

                          <div className="grid grid-cols-2 gap-2 text-sm">
                            <div className="rounded-md bg-bg-elevated px-3 py-2">
                              <p className="text-xs text-text-tertiary">MAC</p>
                              <p className="font-mono text-text-primary">{selectedEndpoint.mac || "--"}</p>
                            </div>
                            <div className="rounded-md bg-bg-elevated px-3 py-2">
                              <p className="text-xs text-text-tertiary">OS</p>
                              <p className="text-text-primary">{selectedEndpoint.os_guess || "unknown"}</p>
                            </div>
                          </div>

                          <div>
                            <div className="mb-1 flex items-center justify-between text-xs text-text-tertiary">
                              <span>Fingerprint confidence</span>
                              <span className="font-mono">{Math.round((Number(selectedEndpoint.confidence) || 0) * 100)}%</span>
                            </div>
                            <div className="h-2 rounded-full bg-bg-elevated">
                              <div
                                className="h-full rounded-full bg-gradient-to-r from-accent-primary to-status-success"
                                style={{ width: `${Math.max(4, Math.min(100, Math.round((Number(selectedEndpoint.confidence) || 0) * 100)))}%` }}
                              />
                            </div>
                          </div>

                          <div>
                            <p className="mb-2 text-xs uppercase tracking-widest text-text-tertiary">Open Ports ({selectedEndpoint.open_ports.length})</p>
                            {selectedEndpoint.open_ports.length === 0 ? (
                              <div className="rounded-md bg-bg-elevated px-3 py-2 text-sm text-text-tertiary">No open ports observed yet.</div>
                            ) : (
                              <div className="flex flex-wrap gap-2">
                                {selectedEndpoint.open_ports.map((port) => (
                                  <span key={port} className="orbital-tag font-mono">{port}</span>
                                ))}
                              </div>
                            )}
                          </div>

                          <div className="text-xs text-text-tertiary">
                            Sources: {(selectedEndpoint.source_tags || []).join(" · ") || "none"}
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="panel-premium flex min-h-0 flex-1 flex-col overflow-hidden">
                      <div className="flex items-center justify-between border-b border-border-default/60 px-4 py-3">
                        <h3 className="text-xs uppercase tracking-widest text-text-tertiary">Vulnerabilities Log</h3>
                        <span className="orbital-tag">{selectedEndpointVulns.length} logged</span>
                      </div>

                      <div className="min-h-0 flex-1 overflow-y-auto">
                        {selectedEndpointVulns.length === 0 ? (
                          <div className="px-4 py-4 text-sm text-text-tertiary">No vulnerabilities identified yet.</div>
                        ) : (
                          selectedEndpointVulns.map((vuln) => (
                            <div key={vuln.id} className="endpoint-row border-b border-border-default/40 px-4 py-3">
                              <div className="flex items-start justify-between gap-3">
                                <div>
                                  <div className="text-sm font-semibold text-text-primary">{vuln.title}</div>
                                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-text-tertiary">
                                    <span className="font-mono">{vuln.cve}</span>
                                    <span className="font-mono">host {vuln.host}</span>
                                    <span className="font-mono">port {vuln.port}</span>
                                  </div>
                                </div>
                                <div className="text-right">
                                  <span className={`inline-flex rounded-sm border px-2 py-0.5 text-xs font-medium ${SEVERITY_BADGE[vuln.severity] || SEVERITY_BADGE.low}`}>
                                    {vuln.severity.toUpperCase()}
                                  </span>
                                  <div className="mt-1 font-mono text-xs text-text-tertiary">CVSS {vuln.cvss.toFixed(1)}</div>
                                </div>
                              </div>
                              <div className="mt-1 font-mono text-xs text-text-tertiary">Logged at {formatClock(vuln.timestamp)}</div>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === "ports" && (
              <div className="h-full w-full p-4">
                <PortMatrix portResults={ws.portResults} />
              </div>
            )}

            {activeTab === "os" && (
              <div className="h-full w-full p-4">
                <OSFingerprintPanel osResults={ws.osResults} hosts={endpointHosts} />
              </div>
            )}

            {activeTab === "pkts" && (
              <div className="h-full w-full p-4">
                <PacketInspector packets={ws.packets} pps={ws.pps} wsStatus={ws.status} />
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

