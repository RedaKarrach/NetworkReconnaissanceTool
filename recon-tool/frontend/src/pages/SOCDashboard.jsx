import React, { useEffect, useMemo, useRef, useState } from "react";
import { useWebSocket } from "../hooks/useWebSocket";
import { useInventory } from "../hooks/useInventory";
import { useAgentRegistry } from "../hooks/useAgentRegistry";

const LIVE_SESSION = "live";
const MAX_ALERTS = 30;
const BAR_COUNT = 50;

const SEVERITY_STYLE = {
  critical: {
    bar: "bg-threat-critical",
    dot: "bg-threat-critical",
    badgeBg: "bg-threat-critical-bg",
    badgeBorder: "border-threat-critical-border",
    badgeText: "text-threat-critical-text",
    valueText: "text-threat-critical",
    pulse: true,
  },
  high: {
    bar: "bg-threat-high",
    dot: "bg-threat-high",
    badgeBg: "bg-threat-high-bg",
    badgeBorder: "border-threat-high-border",
    badgeText: "text-threat-high-text",
    valueText: "text-threat-high",
    pulse: false,
  },
  medium: {
    bar: "bg-threat-medium",
    dot: "bg-threat-medium",
    badgeBg: "bg-threat-medium-bg",
    badgeBorder: "border-threat-medium-border",
    badgeText: "text-threat-medium-text",
    valueText: "text-threat-medium",
    pulse: false,
  },
  low: {
    bar: "bg-threat-low",
    dot: "bg-threat-low",
    badgeBg: "bg-threat-low-bg",
    badgeBorder: "border-threat-low-border",
    badgeText: "text-threat-low-text",
    valueText: "text-threat-low",
    pulse: false,
  },
};

const RULE_DEFS = [
  { id: "DET-001", key: "syn", name: "SYN flood signature", severity: "critical" },
  { id: "DET-002", key: "arp", name: "ARP spoofing pattern", severity: "high" },
  { id: "DET-003", key: "sweep", name: "Port sweep activity", severity: "medium" },
];

function normalizeSeverity(value) {
  if (typeof value !== "string") return "low";
  const sev = value.toLowerCase();
  if (sev.includes("critical")) return "critical";
  if (sev.includes("high")) return "high";
  if (sev.includes("medium")) return "medium";
  return "low";
}

function normalizeAlert(input) {
  return {
    event_type: input?.event_type || "alert",
    type: input?.type || "unknown_rule",
    src_ip: input?.src_ip || input?.src || "0.0.0.0",
    dst_ip: input?.dst_ip || input?.dst || "192.168.56.20",
    severity: normalizeSeverity(input?.severity),
    message: input?.message || "Suspicious activity detected",
    timestamp: input?.timestamp || new Date().toISOString(),
  };
}

function parseTimestamp(value) {
  if (typeof value === "number") return value;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Date.now() : parsed;
}

function formatTime(value) {
  const date = new Date(parseTimestamp(value));
  const part = (n) => String(n).padStart(2, "0");
  return `${part(date.getHours())}:${part(date.getMinutes())}:${part(date.getSeconds())}`;
}

function mapTypeToRule(type) {
  const t = String(type || "").toLowerCase();
  if (t.includes("arp")) return "arp";
  if (t.includes("sweep") || t.includes("port")) return "sweep";
  return "syn";
}

function severityRank(value) {
  if (value === "critical") return 4;
  if (value === "high") return 3;
  if (value === "medium") return 2;
  return 1;
}

function osEmoji(name) {
  const os = String(name || "unknown").toLowerCase();
  if (os.includes("linux")) return "🐧";
  if (os.includes("windows")) return "🪟";
  if (os.includes("mac")) return "🍎";
  return "❓";
}

function generateDemoAlert() {
  const variants = [
    { type: "syn_flood", severity: "critical", message: "SYN flood threshold breached" },
    { type: "arp_spoof", severity: "high", message: "ARP cache poisoning signature detected" },
    { type: "port_sweep", severity: "medium", message: "Sequential port probing observed" },
    { type: "icmp_redirect", severity: "high", message: "ICMP redirect anomaly observed" },
  ];
  const selected = variants[Math.floor(Math.random() * variants.length)];
  return normalizeAlert({
    ...selected,
    src_ip: `172.21.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`,
    dst_ip: "192.168.56.20",
    timestamp: new Date().toISOString(),
  });
}

function KpiCard({ title, value, subLabel, valueClass, subLabelClass, flash }) {
  return (
    <div className="relative overflow-hidden rounded-lg border border-border-default bg-bg-card p-4">
      {flash && (
        <div
          className="absolute inset-0 bg-accent-muted"
          style={{ animation: "fade-in 220ms ease-out reverse" }}
        />
      )}
      <p className="relative z-10 text-sm text-text-secondary">{title}</p>
      <p className={`relative z-10 mt-2 font-mono font-bold leading-none ${valueClass}`} style={{ fontSize: "28px" }}>
        {value}
      </p>
      <p className={`relative z-10 mt-1 text-sm ${subLabelClass}`}>{subLabel}</p>
    </div>
  );
}

function AlertRow({ alert, isNewest }) {
  const style = SEVERITY_STYLE[alert.severity] || SEVERITY_STYLE.low;
  return (
    <div
      className={`group flex items-stretch gap-3 border-b border-border-default px-3 py-3 transition-colors duration-150 hover:bg-bg-card-hover ${
        isNewest ? "animate-slide-in-top" : ""
      }`}
    >
      <div className={`${style.bar} rounded-full`} style={{ width: "3px" }} />

      <div className={`mt-1 h-2 w-2 rounded-full ${style.dot}`} />

      <div className="flex-1 overflow-hidden">
        <p
          className="font-semibold text-text-primary"
          style={{
            fontSize: "12px",
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
            overflow: "hidden",
          }}
        >
          {alert.message}
        </p>
        <p className="mt-1 text-sm text-text-tertiary">src: {alert.src_ip}</p>
        <p className="text-sm text-text-tertiary">rule: {alert.type}</p>
      </div>

      <div className="ml-2 flex flex-col items-end gap-1">
        <span
          className={`rounded-full border px-2 py-0.5 font-mono text-xs ${style.badgeBg} ${style.badgeBorder} ${style.badgeText} ${
            style.pulse ? "animate-pulse-critical" : ""
          }`}
        >
          {alert.severity.toUpperCase()}
        </span>
        <span className="font-mono text-xs text-text-tertiary">{formatTime(alert.timestamp)}</span>
      </div>
    </div>
  );
}

function AgentStat({ label, value, valueClass }) {
  return (
    <div className="rounded-md bg-bg-elevated p-2">
      <p className="text-xs text-text-secondary">{label}</p>
      <p className={`mt-1 text-md font-semibold ${valueClass}`}>{value}</p>
    </div>
  );
}

export default function SOCDashboard() {
  const ws = useWebSocket(LIVE_SESSION);
  const { items: inventoryItems } = useInventory();
  const { items: registryItems } = useAgentRegistry();
  const isWsConnected = ws.status === "connected";

  const [simAlerts, setSimAlerts] = useState([]);
  const [synPps, setSynPps] = useState(0);
  const [synHistory, setSynHistory] = useState(Array(BAR_COUNT).fill(0));
  const [pktsSent, setPktsSent] = useState(0);
  const [flash, setFlash] = useState({ syn: false, arp: false, alerts: false, agents: false });

  const newestAlertKeyRef = useRef("");
  const [newestAlertKey, setNewestAlertKey] = useState("");
  const prevMetricRef = useRef({ syn: null, arp: null, alerts: null, agents: null });
  const flashTimersRef = useRef([]);

  const liveAgents = useMemo(() => {
    const map = new Map();

    (registryItems || []).forEach((agent) => {
      const key = agent.agent_id || agent.hostname || agent.ip;
      if (!key) return;
      map.set(key, {
        agentId: agent.agent_id || key,
        hostname: agent.hostname || "—",
        ip: agent.ip || "—",
        os: agent.os_name || "unknown",
        lastSeen: null,
      });
    });

    (inventoryItems || []).forEach((inv) => {
      const key = inv.agent_id || inv.hostname || (inv.ips || [])[0];
      if (!key) return;

      const prev = map.get(key) || {
        agentId: inv.agent_id || key,
        hostname: inv.hostname || "—",
        ip: (inv.ips || [])[0] || "—",
        os: inv.os_name || "unknown",
        lastSeen: null,
      };

      map.set(key, {
        ...prev,
        agentId: inv.agent_id || prev.agentId,
        hostname: inv.hostname || prev.hostname,
        ip: (inv.ips || [])[0] || prev.ip,
        os: inv.os_name || prev.os,
        lastSeen: inv.last_seen ? new Date(inv.last_seen) : prev.lastSeen,
      });
    });

    return Array.from(map.values())
      .map((agent) => {
        const online = agent.lastSeen ? Date.now() - agent.lastSeen.getTime() < 120000 : false;
        return { ...agent, online };
      })
      .sort((a, b) => {
        if (a.online !== b.online) return Number(b.online) - Number(a.online);
        const ta = a.lastSeen ? a.lastSeen.getTime() : 0;
        const tb = b.lastSeen ? b.lastSeen.getTime() : 0;
        return tb - ta;
      });
  }, [inventoryItems, registryItems]);

  const onlineAgents = useMemo(() => liveAgents.filter((agent) => agent.online), [liveAgents]);
  const onlineAgentCount = onlineAgents.length;
  const onlineAgentLabel = useMemo(() => {
    if (!onlineAgents.length) return "none";
    return onlineAgents
      .slice(0, 2)
      .map((agent) => (agent.hostname && agent.hostname !== "—" ? agent.hostname : agent.ip))
      .join(" · ");
  }, [onlineAgents]);

  const hotTargets = useMemo(() => {
    const map = new Map();
    alerts.forEach((alert) => {
      const key = alert.dst_ip || "unknown";
      const prev = map.get(key) || { ip: key, count: 0, severity: "low" };
      const severity = severityRank(alert.severity) > severityRank(prev.severity) ? alert.severity : prev.severity;
      map.set(key, {
        ip: key,
        count: prev.count + 1,
        severity,
      });
    });

    return Array.from(map.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [alerts]);

  const liveAlerts = useMemo(() => {
    return (ws.alerts || []).map((entry) => normalizeAlert(entry)).slice(0, MAX_ALERTS);
  }, [ws.alerts]);

  const alerts = isWsConnected ? liveAlerts : simAlerts;

  const arpAnomalies = useMemo(() => {
    return alerts.filter((item) => String(item.type).toLowerCase().includes("arp")).length;
  }, [alerts]);

  const alertsFiredLast60 = useMemo(() => {
    const limit = Date.now() - 60000;
    return alerts.filter((item) => parseTimestamp(item.timestamp) >= limit).length;
  }, [alerts]);

  useEffect(() => {
    if (!alerts.length) return;
    const top = alerts[0];
    const key = `${top.timestamp}-${top.src_ip}-${top.type}`;
    if (key !== newestAlertKeyRef.current) {
      newestAlertKeyRef.current = key;
      setNewestAlertKey(key);
    }
  }, [alerts]);

  useEffect(() => {
    if (!isWsConnected) return;
    const next = Math.max(0, Number(ws.pps) || 0);
    setSynPps(next);
    setSynHistory((prev) => [...prev.slice(1), next]);
    setPktsSent((prev) => prev + next);
  }, [isWsConnected, ws.pps]);

  useEffect(() => {
    if (isWsConnected) return undefined;

    console.log("[DEMO MODE] WebSocket not connected");

    const metricsTimer = setInterval(() => {
      const next = 400 + Math.floor(Math.random() * 600);
      setSynPps(next);
      setSynHistory((prev) => [...prev.slice(1), next]);
      setPktsSent((prev) => prev + next);
    }, 1000);

    const alertsTimer = setInterval(() => {
      const nextAlert = generateDemoAlert();
      setSimAlerts((prev) => [nextAlert, ...prev].slice(0, MAX_ALERTS));
    }, 4000);

    return () => {
      clearInterval(metricsTimer);
      clearInterval(alertsTimer);
    };
  }, [isWsConnected]);

  useEffect(() => {
    const current = {
      syn: synPps,
      arp: arpAnomalies,
      alerts: alertsFiredLast60,
      agents: onlineAgentCount,
    };

    const keys = ["syn", "arp", "alerts", "agents"];
    keys.forEach((key) => {
      if (prevMetricRef.current[key] !== null && prevMetricRef.current[key] !== current[key]) {
        setFlash((prev) => ({ ...prev, [key]: true }));
        const timer = setTimeout(() => {
          setFlash((prev) => ({ ...prev, [key]: false }));
        }, 220);
        flashTimersRef.current.push(timer);
      }
    });

    prevMetricRef.current = current;
  }, [synPps, arpAnomalies, alertsFiredLast60, onlineAgentCount]);

  useEffect(() => {
    return () => {
      flashTimersRef.current.forEach((timer) => clearTimeout(timer));
      flashTimersRef.current = [];
    };
  }, []);

  const maxBar = Math.max(1, ...synHistory);

  const detectionRows = useMemo(() => {
    return RULE_DEFS.map((rule) => {
      const count = alerts.filter((item) => mapTypeToRule(item.type) === rule.key).length;
      const sevStyle = SEVERITY_STYLE[rule.severity] || SEVERITY_STYLE.low;
      const sparkline = Array.from({ length: 8 }, (_, idx) => {
        const value = (count + idx * 3 + (synPps % 9)) % 17;
        return Math.max(2, Math.min(16, value));
      });
      return { ...rule, count, sevStyle, sparkline };
    });
  }, [alerts, synPps]);

  return (
    <div className="flex h-full min-h-0 flex-col gap-3 overflow-hidden bg-bg-app text-text-primary">
      <section className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          title="SYN packets / sec"
          value={synPps}
          subLabel="↑ SYN flood active"
          valueClass="text-threat-critical"
          subLabelClass="text-threat-critical-text"
          flash={flash.syn}
        />
        <KpiCard
          title="ARP anomalies"
          value={arpAnomalies}
          subLabel={`MAC changed × ${arpAnomalies}`}
          valueClass="text-threat-high"
          subLabelClass="text-threat-high-text"
          flash={flash.arp}
        />
        <KpiCard
          title="Alerts fired"
          value={alertsFiredLast60}
          subLabel="Last 60 seconds"
          valueClass="text-threat-critical"
          subLabelClass="text-text-tertiary"
          flash={flash.alerts}
        />
        <KpiCard
          title="Agents online"
          value={onlineAgentCount}
          subLabel={onlineAgentLabel}
          valueClass="text-status-success"
          subLabelClass="text-text-tertiary"
          flash={flash.agents}
        />
      </section>

      <section className="flex min-h-0 flex-1 gap-3">
        <div className="flex min-h-0 flex-1 flex-col rounded-lg border border-border-default bg-bg-card" style={{ flex: 1.6 }}>
          <div className="flex items-center border-b border-border-default px-4 py-3">
            <p className="text-sm font-medium tracking-widest text-text-tertiary">ALERT FEED</p>
            <div className="ml-auto flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-status-danger animate-pulse-critical" />
              <span className="font-mono text-sm text-status-danger">live</span>
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="px-4 py-4 text-sm text-text-tertiary">Waiting for alerts...</div>
            ) : (
              alerts.slice(0, MAX_ALERTS).map((alert) => {
                const key = `${alert.timestamp}-${alert.src_ip}-${alert.type}`;
                return <AlertRow key={key} alert={alert} isNewest={key === newestAlertKey} />;
              })
            )}
          </div>
        </div>

        <div className="flex min-h-0 flex-1 flex-col gap-3" style={{ flex: 1 }}>
          <div className="rounded-lg border border-border-default bg-bg-card p-4 shadow-card">
            <p className="text-sm font-medium tracking-widest text-text-tertiary">LIVE ENDPOINT STATUS</p>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <AgentStat label="Online" value={onlineAgentCount} valueClass="font-mono text-status-success" />
              <AgentStat label="Tracked" value={liveAgents.length} valueClass="font-mono text-accent-primary" />
              <AgentStat label="Alerts / 60s" value={alertsFiredLast60} valueClass="font-mono text-threat-high" />
              <AgentStat label="Packets observed" value={Math.floor(pktsSent).toLocaleString()} valueClass="font-mono text-text-primary" />
            </div>

            <div className="mt-3 space-y-2">
              {liveAgents.length === 0 ? (
                <div className="rounded-md bg-bg-elevated px-3 py-2 text-sm text-text-tertiary">No registered or inventory agents yet.</div>
              ) : (
                liveAgents.slice(0, 5).map((agent) => (
                  <div key={agent.agentId} className="flex items-center gap-2 rounded-md bg-bg-elevated px-3 py-2">
                    <span className={`h-2 w-2 rounded-full ${agent.online ? "bg-status-success" : "bg-status-offline"}`} />
                    <span className="text-sm">{osEmoji(agent.os)}</span>
                    <span className="flex-1 truncate text-sm text-text-primary">
                      {agent.hostname && agent.hostname !== "—" ? agent.hostname : agent.agentId}
                    </span>
                    <span className="font-mono text-xs text-text-tertiary">{agent.ip}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="rounded-lg border border-border-default bg-bg-card p-4 shadow-card">
            <p className="text-sm font-medium tracking-widest text-text-tertiary">HOT TARGETS</p>
            <div className="mt-3 space-y-2">
              {hotTargets.length === 0 ? (
                <div className="rounded-md bg-bg-elevated px-3 py-2 text-sm text-text-tertiary">No alert targets yet.</div>
              ) : (
                hotTargets.map((target) => {
                  const style = SEVERITY_STYLE[target.severity] || SEVERITY_STYLE.low;
                  return (
                    <div key={target.ip} className="flex items-center gap-2 rounded-md bg-bg-elevated px-3 py-2">
                      <span className={`h-2 w-2 rounded-full ${style.dot}`} />
                      <span className="flex-1 font-mono text-sm text-text-primary">{target.ip}</span>
                      <span className={`rounded-sm border px-2 py-0.5 font-mono text-xs ${style.badgeBg} ${style.badgeBorder} ${style.badgeText}`}>
                        {target.severity.toUpperCase()}
                      </span>
                      <span className="font-mono text-md font-semibold text-text-secondary">{target.count}</span>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <div className="rounded-lg border border-border-default bg-bg-card p-4 shadow-card">
            <p className="text-sm font-medium tracking-widest text-text-tertiary">SYN RATE (60S)</p>
            <div className="mt-3 flex h-24 items-end gap-px">
              {synHistory.map((value, index) => {
                const isAttack = value >= 700;
                const height = Math.max(2, Math.round((value / maxBar) * 100));
                return (
                  <div key={`${index}-${value}`} className="flex-1">
                    <div
                      className={`w-full rounded-sm transition-all duration-150 ${isAttack ? "bg-threat-critical/70" : "bg-bg-elevated"}`}
                      style={{ height: `${height}%` }}
                    />
                  </div>
                );
              })}
            </div>
            <div className="mt-2 flex items-center justify-between font-mono text-xs text-text-tertiary">
              <span>-60s</span>
              <span>-45s</span>
              <span>-30s</span>
              <span>-15s</span>
              <span>now</span>
            </div>
          </div>

          <div className="rounded-lg border border-border-default bg-bg-card p-4 shadow-card">
            <p className="text-sm font-medium tracking-widest text-text-tertiary">DETECTION RULES FIRED</p>
            <div className="mt-3 space-y-3">
              {detectionRows.map((row) => (
                <div key={row.id} className="flex items-center gap-2">
                  <span className="rounded-sm bg-bg-elevated px-2 py-0.5 font-mono text-xs text-accent-primary">{row.id}</span>
                  <p className="flex-1 text-sm text-text-secondary">{row.name}</p>
                  <div className="flex items-end gap-px">
                    {row.sparkline.map((v, idx) => (
                      <span
                        key={`${row.id}-${idx}`}
                        className={row.sevStyle.bar}
                        style={{ width: "3px", height: `${v}px` }}
                      />
                    ))}
                  </div>
                  <span className={`font-mono text-md font-bold ${row.sevStyle.valueText}`}>{row.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
