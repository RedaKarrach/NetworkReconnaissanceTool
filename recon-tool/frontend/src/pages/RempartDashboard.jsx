/**
 * pages/RempartDashboard.jsx
 * --------------------------
 * The Rempart SIEM incident dashboard — a bespoke dark-teal SOC view inspired by
 * the "Incidents Management" analytics layout, wired to this project's live data
 * (alerts / events / mitigations / packets / agents) from the "live" session.
 *
 * Self-contained styling (scoped teal palette via inline styles + Tailwind
 * arbitrary values) so it owns its look regardless of the app light/dark theme.
 */
import React, { useMemo } from "react";
import { useWebSocket } from "../hooks/useWebSocket";
import { useInventory } from "../hooks/useInventory";
import { useAgentRegistry } from "../hooks/useAgentRegistry";

// ── Scoped palette ───────────────────────────────────────────────────────────
const C = {
  accent: "#2dd4bf",
  accentSoft: "#5eead4",
  bgFrame: "#08191d",
  panel: "#0b1f24",
  panelAlt: "#0e262c",
  border: "rgba(94,234,212,0.14)",
  borderSoft: "rgba(140,180,176,0.10)",
  text: "#e7f3f1",
  muted: "#8ba6a2",
  faint: "#5d7470",
  crit: "#f87171",
  high: "#fbbf24",
  med: "#fb923c",
  low: "#38bdf8",
  ok: "#34d399",
};

const SEV_COLOR = { critical: C.crit, high: C.high, medium: C.med, low: C.low, info: C.low };

function sevColor(s) {
  return SEV_COLOR[String(s || "").toLowerCase()] || C.low;
}
function normSev(s) {
  const v = String(s || "").toLowerCase();
  if (v.includes("crit")) return "critical";
  if (v.includes("high")) return "high";
  if (v.includes("med")) return "medium";
  return "low";
}
function tsOf(x) {
  const t = Date.parse(x?.timestamp || x?.created_at || "");
  return Number.isNaN(t) ? Date.now() : t;
}
function timeShort(x) {
  const d = new Date(tsOf(x));
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// ── Panel shell ──────────────────────────────────────────────────────────────
function Panel({ title, subtitle, right, children, className = "", bodyClass = "" }) {
  return (
    <div
      className={`flex flex-col rounded-2xl ${className}`}
      style={{ background: C.panel, border: `1px solid ${C.border}`, boxShadow: "0 1px 0 rgba(0,0,0,0.3)" }}
    >
      {(title || right) && (
        <div className="flex items-start justify-between px-4 pt-3.5 pb-2">
          <div>
            {title && <h3 className="text-[15px] font-semibold" style={{ color: C.text }}>{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs" style={{ color: C.faint }}>{subtitle}</p>}
          </div>
          {right}
        </div>
      )}
      <div className={`flex-1 min-h-0 px-4 pb-4 ${bodyClass}`}>{children}</div>
    </div>
  );
}

function Chip({ children, color }) {
  return (
    <span
      className="rounded-md px-2 py-0.5 text-[11px] font-medium"
      style={{ color, background: `${color}1f`, border: `1px solid ${color}44` }}
    >
      {children}
    </span>
  );
}

// ── Semicircle gauge (security health) ───────────────────────────────────────
function Gauge({ value = 0, label }) {
  const v = Math.max(0, Math.min(100, value));
  const R = 80, CX = 100, CY = 100, W = 14;
  const a0 = Math.PI, a1 = 0; // 180° -> 0°
  const ang = a0 + (a1 - a0) * (v / 100);
  const pt = (a, r) => [CX + r * Math.cos(a), CY - r * Math.sin(a)];
  const arc = (from, to, r) => {
    const [x0, y0] = pt(from, r);
    const [x1, y1] = pt(to, r);
    const large = Math.abs(to - from) > Math.PI ? 1 : 0;
    const sweep = to < from ? 1 : 0;
    return `M ${x0} ${y0} A ${r} ${r} 0 ${large} ${sweep} ${x1} ${y1}`;
  };
  const color = v >= 80 ? C.ok : v >= 55 ? C.high : C.crit;
  const grade = v >= 85 ? "Excellent" : v >= 70 ? "Healthy" : v >= 50 ? "At risk" : "Critical";
  return (
    <svg viewBox="0 0 200 118" className="w-full" style={{ maxHeight: 150 }}>
      <path d={arc(a0, a1, R)} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth={W} strokeLinecap="round" />
      <path d={arc(a0, ang, R)} fill="none" stroke={color} strokeWidth={W} strokeLinecap="round" />
      <text x={CX} y={CY - 18} textAnchor="middle" style={{ fill: C.text, fontSize: 30, fontWeight: 700 }} className="font-mono">
        {Math.round(v)}
      </text>
      <text x={CX + 24} y={CY - 20} textAnchor="start" style={{ fill: C.faint, fontSize: 11 }}>/100</text>
      <text x={CX} y={CY + 2} textAnchor="middle" style={{ fill: color, fontSize: 12, fontWeight: 600 }}>{label || grade}</text>
    </svg>
  );
}

// ── Trend area chart (alerts per bucket) ─────────────────────────────────────
function TrendArea({ series, color = C.accent }) {
  const W = 320, H = 110, P = 6;
  const max = Math.max(1, ...series);
  const n = series.length;
  const x = (i) => P + (i * (W - 2 * P)) / Math.max(1, n - 1);
  const y = (val) => H - P - (val / max) * (H - 2 * P - 10);
  const line = series.map((v, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(" ");
  const area = `${line} L ${x(n - 1).toFixed(1)} ${H - P} L ${x(0).toFixed(1)} ${H - P} Z`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: 130 }}>
      <defs>
        <linearGradient id="trendfill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((g) => (
        <line key={g} x1={P} x2={W - P} y1={H - P - g * (H - 2 * P - 10)} y2={H - P - g * (H - 2 * P - 10)} stroke="rgba(255,255,255,0.05)" />
      ))}
      <path d={area} fill="url(#trendfill)" />
      <path d={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
    </svg>
  );
}

// ── Network topology ─────────────────────────────────────────────────────────
function Topology({ attackerIps }) {
  // Representative lab topology; edges to any host flagged as an attacker turn red.
  const nodes = [
    { id: "Internet", x: 60, y: 150, icon: "🌐" },
    { id: "Firewall", x: 150, y: 150, icon: "🛡" },
    { id: "Switch", x: 250, y: 150, icon: "⚙" },
    { id: "WS-002", x: 345, y: 90, icon: "🖥" },
    { id: "WS-001", x: 430, y: 60, icon: "🖥" },
    { id: "DB-Prod", x: 430, y: 150, icon: "🗄" },
    { id: "FIN-SRV", x: 345, y: 215, icon: "⚠", danger: true },
    { id: "WS-003", x: 430, y: 240, icon: "🖥" },
    { id: "Cloud", x: 520, y: 95, icon: "☁" },
  ];
  const map = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const edges = [
    ["Internet", "Firewall", false], ["Firewall", "Switch", false],
    ["Switch", "WS-002", false], ["WS-002", "WS-001", false], ["WS-001", "Cloud", false],
    ["Switch", "DB-Prod", false], ["DB-Prod", "Cloud", false],
    ["Switch", "FIN-SRV", true], ["FIN-SRV", "DB-Prod", true], ["FIN-SRV", "WS-003", true],
  ];
  const hasAttack = (attackerIps || []).length > 0;
  const edge = (a, b, danger) => {
    const p = map[a], q = map[b];
    const mx = (p.x + q.x) / 2;
    const col = danger && hasAttack ? C.crit : C.accent;
    const op = danger && hasAttack ? 0.9 : 0.4;
    return (
      <path key={`${a}-${b}`} d={`M ${p.x} ${p.y} C ${mx} ${p.y} ${mx} ${q.y} ${q.x} ${q.y}`}
        fill="none" stroke={col} strokeWidth={danger && hasAttack ? 2 : 1.4} strokeOpacity={op}
        strokeDasharray={danger && hasAttack ? "0" : "0"} />
    );
  };
  return (
    <svg viewBox="0 0 580 290" className="w-full" style={{ maxHeight: 290 }}>
      {edges.map(([a, b, d]) => edge(a, b, d))}
      {nodes.map((n) => {
        const col = n.danger && hasAttack ? C.crit : C.accent;
        return (
          <g key={n.id}>
            <circle cx={n.x} cy={n.y} r="16" fill={C.panelAlt} stroke={col} strokeWidth="1.5" />
            <text x={n.x} y={n.y + 4} textAnchor="middle" style={{ fontSize: 13 }}>{n.icon}</text>
            <text x={n.x} y={n.y + 30} textAnchor="middle" style={{ fill: C.muted, fontSize: 10 }}>{n.id}</text>
          </g>
        );
      })}
    </svg>
  );
}

function MetricRow({ icon, label, value, color }) {
  return (
    <div className="flex items-center justify-between py-2" style={{ borderBottom: `1px solid ${C.borderSoft}` }}>
      <span className="flex items-center gap-2 text-sm" style={{ color: C.muted }}>
        <span style={{ color: color || C.accent }}>{icon}</span>{label}
      </span>
      <span className="font-mono text-sm font-semibold" style={{ color: C.text }}>{value}</span>
    </div>
  );
}

function StatTile({ icon, label, value, sub, color }) {
  return (
    <div className="rounded-xl p-3" style={{ background: C.panelAlt, border: `1px solid ${C.borderSoft}` }}>
      <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide" style={{ color: C.muted }}>
        <span style={{ color: color || C.accent }}>{icon}</span>{label}
      </div>
      <div className="mt-2 font-mono text-2xl font-bold tabular-nums" style={{ color: C.text }}>{value}</div>
      <div className="mt-0.5 text-[11px]" style={{ color: C.faint }}>{sub}</div>
    </div>
  );
}

// ── Main ─────────────────────────────────────────────────────────────────────
export default function RempartDashboard() {
  const ws = useWebSocket("live");
  const { items: inventory } = useInventory();
  const { items: registry } = useAgentRegistry();

  const alerts = ws?.alerts || [];
  const events = ws?.events || [];
  const mitigations = ws?.mitigations || [];
  const pps = ws?.pps || 0;
  const connected = ws?.status === "connected";

  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach((a) => { c[normSev(a.severity)] += 1; });
    return c;
  }, [alerts]);

  const now = Date.now();
  const last60 = alerts.filter((a) => now - tsOf(a) < 60000).length;
  const mlAlerts = alerts.filter((a) => a.source === "ml" || String(a.type || "").startsWith("ml_"));
  const latestMl = mlAlerts[0];

  const healthScore = useMemo(() => {
    const s = 100 - sevCounts.critical * 10 - sevCounts.high * 4 - sevCounts.medium * 1.5;
    return Math.max(0, Math.min(100, Math.round(s)));
  }, [sevCounts]);

  const attackerIps = useMemo(
    () => [...new Set(alerts.filter((a) => normSev(a.severity) === "critical" || normSev(a.severity) === "high").map((a) => a.src_ip).filter(Boolean))],
    [alerts]
  );

  const agents = useMemo(() => {
    const map = new Map();
    (registry || []).forEach((a) => { const k = a.agent_id || a.ip; if (k) map.set(k, { name: a.hostname || a.agent_id, ip: a.ip, last: a.last_seen }); });
    (inventory || []).forEach((i) => { const k = i.agent_id || (i.ips || [])[0]; if (k) map.set(k, { name: i.hostname || i.agent_id, ip: (i.ips || [])[0], last: i.last_seen }); });
    return [...map.values()];
  }, [registry, inventory]);
  const onlineAgents = agents.filter((a) => a.last && now - Date.parse(a.last) < 300000).length;

  const timeline = useMemo(() => {
    const items = [
      ...mitigations.map((m) => ({ ...m, kind: "mitigation" })),
      ...events.map((e) => ({ ...e, kind: "event" })),
    ].sort((a, b) => tsOf(b) - tsOf(a)).slice(0, 7);
    return items;
  }, [mitigations, events]);

  const trend = useMemo(() => {
    // 12 one-minute buckets of alert counts (most recent on the right).
    const buckets = new Array(12).fill(0);
    alerts.forEach((a) => {
      const age = Math.floor((now - tsOf(a)) / 60000);
      if (age >= 0 && age < 12) buckets[11 - age] += 1;
    });
    return buckets;
  }, [alerts]);

  const radar = alerts.slice(0, 7);

  const chipFor = (it) => {
    if (it.kind === "mitigation") {
      if (it.status === "enforced") return <Chip color={C.crit}>Enforced</Chip>;
      return <Chip color={C.high}>Would block</Chip>;
    }
    return <Chip color={C.accent}>Event</Chip>;
  };

  return (
    <div
      className="min-h-full w-full"
      style={{
        margin: "-24px", padding: "24px",
        background: `radial-gradient(1200px 600px at 70% -10%, #0e3a3f 0%, ${C.bgFrame} 55%, #050f12 100%)`,
      }}
    >
      {/* Framed console */}
      <div className="rounded-3xl p-4" style={{ background: "rgba(5,16,18,0.6)", border: `1px solid ${C.border}`, boxShadow: "0 24px 80px rgba(0,0,0,0.5)" }}>
        {/* Top bar */}
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-2 pr-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg font-bold" style={{ background: C.accent, color: "#042f2a" }}>R</div>
            <div>
              <div className="text-sm font-bold leading-none" style={{ color: C.text }}>Rempart <span style={{ color: C.accent }}>SIEM</span></div>
              <div className="text-[10px] uppercase tracking-wide" style={{ color: C.faint }}>Network SOC</div>
            </div>
          </div>
          {["Team: Lab SOC", "Scope: 192.168.56.0/24", "Range: Live", "Threat: MITRE ATT&CK"].map((f) => (
            <div key={f} className="rounded-lg px-3 py-1.5 text-xs" style={{ background: C.panel, border: `1px solid ${C.borderSoft}`, color: C.muted }}>{f} <span style={{ color: C.faint }}>▾</span></div>
          ))}
          <div className="ml-auto flex items-center gap-2">
            <div className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs" style={{ background: C.panel, border: `1px solid ${C.borderSoft}` }}>
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: connected ? C.ok : C.faint }} />
              <span style={{ color: connected ? C.ok : C.faint }}>{connected ? "LIVE" : "OFFLINE"}</span>
            </div>
          </div>
        </div>

        {/* Title row */}
        <div className="mb-4 flex items-end justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: C.text }}>Incident Management</h1>
            <p className="mt-0.5 text-sm" style={{ color: C.muted }}>Monitor, investigate, prioritize and respond across the lab network.</p>
          </div>
          <div className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium" style={{ background: C.accent, color: "#042f2a" }}>↻ Refresh</div>
        </div>

        {/* Grid */}
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-[320px_minmax(0,1fr)_340px]">
          {/* LEFT */}
          <div className="flex flex-col gap-3">
            <Panel title="Security Health Score" right={<Chip color={connected ? C.ok : C.faint}>{connected ? "Live" : "—"}</Chip>}>
              <Gauge value={healthScore} />
              <div className="mt-2">
                <MetricRow icon="▣" label="Active alerts" value={alerts.length} />
                <MetricRow icon="⚠" label="Critical" value={sevCounts.critical} color={C.crit} />
                <MetricRow icon="◷" label="Alerts / 60s" value={last60} color={C.high} />
                <MetricRow icon="✓" label="Mitigations" value={mitigations.length} color={C.ok} />
              </div>
              <div className="flex items-center justify-between pt-2 text-sm">
                <span style={{ color: C.faint }}>Status</span>
                <span style={{ color: healthScore >= 70 ? C.ok : C.crit }}>● {healthScore >= 70 ? "Operational" : "Degraded"}</span>
              </div>
            </Panel>

            <Panel title="AI Investigation" right={<Chip color={C.accent}>ML</Chip>}>
              <div className="rounded-lg p-3 text-xs leading-relaxed" style={{ background: C.panelAlt, color: C.muted }}>
                <span style={{ color: C.accentSoft }}>AI summary: </span>
                {latestMl
                  ? `${latestMl.label || latestMl.type} from ${latestMl.src_ip} — confidence ${Math.round((latestMl.confidence || 0) * 100)}%, model ${latestMl.model_version || "n/a"}.`
                  : "No ML detections yet. Enable ML_ENABLED and load artifacts to score live flows."}
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div className="flex items-end gap-2" style={{ height: 56 }}>
                  {["critical", "high", "medium", "low"].map((k) => {
                    const max = Math.max(1, ...Object.values(sevCounts));
                    return <div key={k} title={k} style={{ width: 20, height: `${(sevCounts[k] / max) * 56 || 2}px`, background: sevColor(k), borderRadius: 3, opacity: 0.85 }} />;
                  })}
                </div>
                <div className="text-right">
                  <div className="font-mono text-2xl font-bold" style={{ color: C.text }}>{mlAlerts.length}</div>
                  <div className="text-[11px]" style={{ color: C.faint }}>ML alerts</div>
                </div>
              </div>
              <div className="mt-1 text-[10px] uppercase tracking-wide" style={{ color: C.faint }}>Threat attribution · by severity</div>
            </Panel>
          </div>

          {/* CENTER */}
          <div className="flex flex-col gap-3">
            <Panel title="Network Topology" subtitle="Live view of the lab segment; attack paths are highlighted."
              right={<div className="flex items-center gap-3 text-[11px]"><span style={{ color: C.crit }}>● Attack path</span><span style={{ color: C.accent }}>● Normal</span></div>}>
              <Topology attackerIps={attackerIps} />
            </Panel>

            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <StatTile icon="▤" label="Open alerts" value={alerts.length} sub="Current session" color={C.accent} />
              <StatTile icon="⚠" label="Critical" value={sevCounts.critical} sub="Immediate action" color={C.crit} />
              <StatTile icon="✓" label="Mitigations" value={mitigations.length} sub="Recommended/enforced" color={C.ok} />
              <StatTile icon="◷" label="Packets / s" value={pps} sub="Live throughput" color={C.high} />
            </div>

            <Panel title="Global Threat Radar" right={<span className="text-xs" style={{ color: C.accent }}>View all ↗</span>} bodyClass="overflow-x-auto">
              <table className="w-full text-sm" style={{ color: C.muted }}>
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wide" style={{ color: C.faint }}>
                    <th className="pb-2 font-medium">Type</th>
                    <th className="pb-2 font-medium">Source</th>
                    <th className="pb-2 font-medium">Severity</th>
                    <th className="pb-2 font-medium text-right">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {radar.length === 0 ? (
                    <tr><td colSpan={4} className="py-4 text-center" style={{ color: C.faint }}>No alerts yet — trigger a scan or attack on the lab.</td></tr>
                  ) : radar.map((a, i) => (
                    <tr key={i} style={{ borderTop: `1px solid ${C.borderSoft}` }}>
                      <td className="py-2 pr-2" style={{ color: C.text }}>{a.type}</td>
                      <td className="py-2 pr-2 font-mono text-xs">{a.src_ip || "—"}</td>
                      <td className="py-2 pr-2"><Chip color={sevColor(a.severity)}>{normSev(a.severity)}</Chip></td>
                      <td className="py-2 text-right font-mono text-xs">{timeShort(a)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>

          {/* RIGHT */}
          <div className="flex flex-col gap-3">
            <Panel title="Response Timeline" subtitle="Latest events & mitigations">
              <div className="flex flex-col">
                {timeline.length === 0 ? (
                  <div className="py-4 text-sm" style={{ color: C.faint }}>Waiting for activity…</div>
                ) : timeline.map((it, i) => (
                  <div key={i} className="flex items-start gap-3 py-2" style={{ borderBottom: i < timeline.length - 1 ? `1px solid ${C.borderSoft}` : "none" }}>
                    <span className="mt-1 h-2 w-2 flex-shrink-0 rounded-full" style={{ background: it.kind === "mitigation" ? C.high : C.accent }} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm" style={{ color: C.text }}>{it.type || it.action || "event"}</div>
                      <div className="font-mono text-[11px]" style={{ color: C.faint }}>{timeShort(it)}</div>
                    </div>
                    {chipFor(it)}
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title="Alert Volume Trend" subtitle="Alerts per minute · last 12 min"
              right={<div className="flex items-center gap-2 text-[11px]"><span style={{ color: C.accent }}>● Alerts</span></div>}>
              <TrendArea series={trend} />
              <div className="mt-1 flex justify-between font-mono text-[10px]" style={{ color: C.faint }}>
                <span>-12m</span><span>now</span>
              </div>
            </Panel>

            <Panel title="Agents" right={<Chip color={C.ok}>{onlineAgents} online</Chip>}>
              {agents.length === 0 ? (
                <div className="py-2 text-sm" style={{ color: C.faint }}>No agents registered.</div>
              ) : agents.slice(0, 5).map((a, i) => {
                const online = a.last && now - Date.parse(a.last) < 300000;
                return (
                  <div key={i} className="flex items-center gap-2 py-1.5">
                    <span className="h-2 w-2 rounded-full" style={{ background: online ? C.ok : C.faint }} />
                    <span className="flex-1 truncate text-sm" style={{ color: C.text }}>{a.name || "unknown"}</span>
                    <span className="font-mono text-xs" style={{ color: C.faint }}>{a.ip || "—"}</span>
                  </div>
                );
              })}
            </Panel>
          </div>
        </div>
      </div>
    </div>
  );
}
