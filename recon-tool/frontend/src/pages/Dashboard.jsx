import React, { useEffect, useMemo, useState } from "react";
import NetworkMap from "../components/NetworkMap";
import PortMatrix from "../components/PortMatrix";
import OSFingerprintPanel from "../components/OSFingerprintPanel";
import PacketInspector from "../components/PacketInspector";
import { useScan } from "../hooks/useScan";
import { useWebSocket } from "../hooks/useWebSocket";

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
}) {
  return (
    <div className="overflow-hidden rounded-lg border border-border-default bg-bg-card shadow-card transition-shadow duration-150 hover:shadow-card-hover">
      <div className={`${topAccentClass} rounded-t-lg`} style={{ height: "3px" }} />

      <div className="p-4">
        <div className="mb-4 flex items-center gap-2">
          <Icon className={iconClass} />
          <h3 className="text-md font-semibold text-text-primary">{title}</h3>
          <span className={`ml-auto rounded-md px-2 py-1 text-sm font-medium ${statusBadgeClass(status)}`}>{status}</span>
        </div>

        <div className="space-y-3">{children}</div>

        <p className="mt-3 text-xs text-text-tertiary">{description}</p>

        {status === "Running" ? (
          <button
            type="button"
            onClick={onStop}
            className="mt-4 flex w-full items-center justify-center gap-2 rounded-md bg-threat-critical py-2.5 text-sm font-semibold text-text-primary transition-all duration-150 active:scale-[0.98]"
          >
            <SpinnerIcon />
            ■ Stop Scan
          </button>
        ) : status === "Complete" ? (
          <button
            type="button"
            disabled
            className="mt-4 w-full rounded-md border border-status-success bg-status-success/20 py-2.5 text-sm font-semibold text-status-success"
          >
            ✓ Complete
          </button>
        ) : (
          <button
            type="button"
            onClick={onLaunch}
            disabled={disabled}
            className={`mt-4 w-full rounded-md py-2.5 text-sm font-semibold text-text-primary transition-all duration-150 active:scale-[0.98] disabled:opacity-60 ${idleButtonClass}`}
          >
            Launch Scan
          </button>
        )}
      </div>
    </div>
  );
}

export default function Dashboard({ onSessionStart }) {
  const { startHostDiscovery, startPortScan, startOsFingerprint, stopThread, loading, error } = useScan();

  const [sessionId, setSessionId] = useState(null);
  const [threadId, setThreadId] = useState(null);
  const [subnet, setSubnet] = useState("192.168.56.0/24");
  const [scanIp, setScanIp] = useState("192.168.56.20");
  const [ports, setPorts] = useState("22,80,443,3389");
  const [protocol, setProtocol] = useState("tcp");
  const [fpIp, setFpIp] = useState("192.168.56.20");
  const [activeTab, setActiveTab] = useState("map");

  const [runningScanType, setRunningScanType] = useState(null);
  const [completedScanType, setCompletedScanType] = useState(null);

  const ws = useWebSocket(sessionId);

  const hosts = useMemo(() => {
    const map = new Map();
    (ws.hosts || []).forEach((host) => {
      if (host?.ip) map.set(host.ip, host);
    });
    return Array.from(map.values());
  }, [ws.hosts]);

  useEffect(() => {
    if (!completedScanType) return;
    const timer = setTimeout(() => setCompletedScanType(null), 1200);
    return () => clearTimeout(timer);
  }, [completedScanType]);

  async function launchScan(type, action) {
    if (runningScanType) return;

    setCompletedScanType(null);
    setRunningScanType(type);

    const result = await action();
    if (!result || !result.session_id) {
      setRunningScanType(null);
      return;
    }

    setSessionId(result.session_id);
    setThreadId(result.thread_id || null);
    if (onSessionStart) onSessionStart(result.session_id);
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
  }

  async function handleHostDiscovery() {
    await launchScan("discovery", () => startHostDiscovery(subnet));
  }

  async function handlePortScan() {
    const parsedPorts = parsePorts(ports);
    if (!scanIp || parsedPorts.length === 0) return;
    await launchScan("port", () => startPortScan(scanIp, parsedPorts, protocol));
  }

  async function handleFingerprint() {
    if (!fpIp) return;
    await launchScan("fingerprint", () => startOsFingerprint(fpIp));
  }

  const sessionPreview = sessionId
    ? `${sessionId.slice(0, 18)}${sessionId.length > 18 ? "…" : ""}`
    : "";

  const isSessionRunning = Boolean(runningScanType && sessionId);

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-3">
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
          disabled={loading || Boolean(runningScanType)}
        >
          <div>
            <label className="mb-1 block text-sm text-text-secondary">Subnet</label>
            <input
              value={subnet}
              onChange={(event) => setSubnet(event.target.value)}
              placeholder="192.168.56.0/24"
              className="w-full rounded-md border border-border-default bg-bg-input px-3 py-2 font-mono text-sm text-text-primary outline-none transition-colors duration-150 placeholder:text-text-tertiary focus:border-accent-border"
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
          disabled={loading || Boolean(runningScanType) || !scanIp}
        >
          <div>
            <label className="mb-1 block text-sm text-text-secondary">Target IP</label>
            <input
              value={scanIp}
              onChange={(event) => setScanIp(event.target.value)}
              placeholder="192.168.56.20"
              className="w-full rounded-md border border-border-default bg-bg-input px-3 py-2 font-mono text-sm text-text-primary outline-none transition-colors duration-150 placeholder:text-text-tertiary focus:border-accent-border"
            />
          </div>

          <div>
            <label className="mb-1 block text-sm text-text-secondary">Ports</label>
            <input
              value={ports}
              onChange={(event) => setPorts(event.target.value)}
              placeholder="22,80,443,3389"
              className="w-full rounded-md border border-border-default bg-bg-input px-3 py-2 font-mono text-sm text-text-primary outline-none transition-colors duration-150 placeholder:text-text-tertiary focus:border-accent-border"
            />
          </div>

          <div>
            <label className="mb-1 block text-sm text-text-secondary">Protocol</label>
            <div className="inline-flex rounded-full border border-border-default bg-bg-elevated p-1">
              <button
                type="button"
                onClick={() => setProtocol("tcp")}
                className={`rounded-full px-3 py-1 text-sm font-medium transition-colors duration-150 ${
                  protocol === "tcp"
                    ? "bg-accent-muted text-accent-primary border border-border-accent"
                    : "text-text-tertiary hover:text-text-secondary"
                }`}
              >
                TCP
              </button>
              <button
                type="button"
                onClick={() => setProtocol("udp")}
                className={`rounded-full px-3 py-1 text-sm font-medium transition-colors duration-150 ${
                  protocol === "udp"
                    ? "bg-accent-muted text-accent-primary border border-border-accent"
                    : "text-text-tertiary hover:text-text-secondary"
                }`}
              >
                UDP
              </button>
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
          disabled={loading || Boolean(runningScanType) || !fpIp}
        >
          <div>
            <label className="mb-1 block text-sm text-text-secondary">Target IP</label>
            <input
              value={fpIp}
              onChange={(event) => setFpIp(event.target.value)}
              placeholder="192.168.56.20"
              className="w-full rounded-md border border-border-default bg-bg-input px-3 py-2 font-mono text-sm text-text-primary outline-none transition-colors duration-150 placeholder:text-text-tertiary focus:border-accent-border"
            />
          </div>

          <div className="flex flex-wrap gap-2">
            <span className="rounded-full border border-border-default bg-bg-elevated px-3 py-1 text-sm text-text-tertiary">TTL Analysis</span>
            <span className="rounded-full border border-border-default bg-bg-elevated px-3 py-1 text-sm text-text-tertiary">TCP Window</span>
            <span className="rounded-full border border-border-default bg-bg-elevated px-3 py-1 text-sm text-text-tertiary">Xmas Scan</span>
          </div>
        </ScanCard>
      </section>

      {isSessionRunning && (
        <section className="flex items-center gap-3 rounded-lg border border-accent-border bg-bg-elevated px-4 py-3">
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-status-success animate-pulse" />
            <span className="text-sm text-text-primary">Session active</span>
            <span className="truncate font-mono text-xs text-text-tertiary">{sessionPreview}</span>
          </div>

          <div className="font-mono text-lg font-bold text-accent-primary">{ws.pps} pkt/s</div>

          <button
            type="button"
            onClick={stopAllScans}
            className="rounded-md border border-border-danger bg-threat-critical/10 px-3 py-1.5 text-sm text-threat-critical transition-colors duration-150 hover:bg-threat-critical-bg"
          >
            ■ Stop All
          </button>
        </section>
      )}

      {error && (
        <div className="rounded-lg border border-border-danger bg-threat-critical-bg px-4 py-3 text-sm text-threat-critical-text">
          {error}
        </div>
      )}

      <section className="flex min-h-0 flex-1 flex-col">
        <div className="border-b border-border-default">
          <div className="flex gap-1">
            {TABS.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`-mb-px border-b-2 px-4 py-2.5 text-sm font-medium transition-colors duration-150 ${
                    isActive
                      ? "border-accent-primary text-accent-primary"
                      : "border-transparent text-text-tertiary hover:border-border-elevated hover:text-text-secondary"
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="mt-3 flex min-h-0 flex-1">
          <div className="flex min-h-0 w-full flex-1 rounded-lg border border-border-default bg-bg-card p-3">
            {activeTab === "map" && (
              <div className="h-full w-full">
                <NetworkMap
                  hosts={hosts}
                  onSelectHost={(host) => {
                    if (host?.ip) {
                      setScanIp(host.ip);
                      setFpIp(host.ip);
                    }
                  }}
                />
              </div>
            )}

            {activeTab === "ports" && (
              <div className="h-full w-full">
                <PortMatrix portResults={ws.portResults} />
              </div>
            )}

            {activeTab === "os" && (
              <div className="h-full w-full">
                <OSFingerprintPanel osResults={ws.osResults} hosts={hosts} />
              </div>
            )}

            {activeTab === "pkts" && (
              <div className="h-full w-full">
                <PacketInspector packets={ws.packets} pps={ws.pps} wsStatus={ws.status} />
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
