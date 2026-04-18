/**
 * SOCDashboard.jsx
 * ─────────────────────────────────────────────────────────────
 * Live SOC monitoring view — the page shown in the screenshot.
 * Connects to the Django WebSocket and receives real-time alerts
 * from victim_agent.py running on the Windows VM.
 *
 * WebSocket events consumed:
 *   { event_type: "alert",      type, src_ip, dst_ip, severity, message, timestamp }
 *   { event_type: "status",     status, message }
 *
 * Usage: navigate to /soc in the sidebar (App.jsx already wires this).
 */

import { useMemo, useState } from "react";
import { useWebSocket } from "../hooks/useWebSocket";
import NetworkMap from "../components/NetworkMap";
import PacketInspector from "../components/PacketInspector";
import PortMatrix from "../components/PortMatrix";

// ── Config ────────────────────────────────────────────────────────────────────
const LIVE_SESSION   = "live";   // shared session for all live alerts/packets

// ── Severity helpers ──────────────────────────────────────────────────────────
const SEV_BAR   = { critical:"#ef4444", high:"#f59e0b", medium:"#f97316", low:"#3b82f6" };
const SEV_BG    = { critical:"rgba(239,68,68,.18)", high:"rgba(245,158,11,.18)", medium:"rgba(249,115,22,.18)", low:"rgba(59,130,246,.18)" };
const SEV_TEXT  = { critical:"#ff6b6b", high:"#fbbf24", medium:"#fb923c", low:"#60a5fa" };
const SEV_LABEL = { critical:"CRITICAL", high:"HIGH", medium:"MEDIUM", low:"LOW" };

function normalizeSeverity(value) {
  if (typeof value !== "string") return "low";
  const normalized = value.toLowerCase();
  return SEV_LABEL[normalized] ? normalized : "low";
}

function nowStr() {
  const d = new Date();
  const p = n => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function AlertItem({ alert, isNew }) {
  const severity = normalizeSeverity(alert.severity);
  const bar  = SEV_BAR[severity];
  const bg   = SEV_BG[severity];
  const text = SEV_TEXT[severity];
  const lbl  = SEV_LABEL[severity];

  return (
    <div style={{
      display:"flex", gap:10, padding:"10px 14px",
      borderBottom:"1px solid #1e2535",
      animation: isNew ? "flashIn .5s ease-out" : "none",
      cursor:"pointer",
    }}>
      {/* severity bar */}
      <div style={{ width:4, borderRadius:2, background:bar, flexShrink:0, alignSelf:"stretch" }}/>
      {/* body */}
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ fontSize:12, fontWeight:600, color:"#e2e8f0", marginBottom:3, lineHeight:1.3 }}>
          {alert.message || alert.title}
        </div>
        <div style={{ fontSize:11, color:"#5a6478", lineHeight:1.5 }}>
          src: {alert.src_ip || alert.src}<br/>
          rule: {alert.rule || alert.type}
        </div>
      </div>
      {/* right */}
      <div style={{ display:"flex", flexDirection:"column", alignItems:"flex-end", gap:4, flexShrink:0 }}>
        <div style={{ padding:"2px 7px", borderRadius:4, fontSize:10, fontWeight:700, background:bg, color:text }}>
          {lbl}
        </div>
        <div style={{ fontFamily:"monospace", fontSize:10, color:"#5a6478" }}>{alert.t || alert.timestamp}</div>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function SOCDashboard() {
  const ws = useWebSocket(LIVE_SESSION);
  const [view, setView] = useState("alerts");

  const alerts = useMemo(() => {
    return (ws.alerts || []).map((data) => ({
      ...data,
      severity: normalizeSeverity(data.severity),
      t: data.timestamp ? data.timestamp.slice(11, 19) : nowStr(),
    })).slice(0, 30);
  }, [ws.alerts]);

  const critCount = alerts.filter(a => a.severity === "critical").length;
  const liveHosts = useMemo(() => {
    const map = new Map();
    (ws.hosts || []).forEach((h) => {
      if (h.ip) map.set(h.ip, h);
    });
    return Array.from(map.values()).slice(0, 200);
  }, [ws.hosts]);

  return (
    <div style={{ display:"flex", flex:1, width:"100%", minWidth:0, height:"100%", background:"#0f1117", color:"#e2e8f0", fontFamily:"-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif", fontSize:13 }}>

      {/* ── Sidebar ───────────────────────────────────────────────────── */}
      <div style={{ width:200, minWidth:200, background:"#161b24", borderRight:"1px solid #2a3348", display:"flex", flexDirection:"column" }}>
        <div style={{ padding:"16px 14px 12px", borderBottom:"1px solid #2a3348" }}>
          <div style={{ fontSize:15, fontWeight:700, color:"#e2e8f0" }}>AegisWR SOC</div>
          <div style={{ fontSize:11, color:"#5a6478", marginTop:2 }}>Wassim + Reda Cyber Defense</div>
        </div>

        {[
          ["VIEWS", [
            ["alerts", "!", "Live alerts",  "red"],
            ["map", "◉", "Network map", "blue"],
            ["packets", "≡", "Packet logs", null],
            ["ports", "⊞", "Port matrix", null],
          ]],
          ["DETECTION", [
            ["rules", "🔍", "Rules fired", null],
            ["arp", "🛡", "ARP watch",   null],
          ]],
        ].map(([section, items]) => (
          <div key={section}>
            <div style={{ padding:"14px 10px 4px", fontSize:10, fontWeight:600, color:"#5a6478", textTransform:"uppercase", letterSpacing:".08em" }}>
              {section}
            </div>
            {items.map(([key, icon, label, accent]) => (
              <button
                key={label}
                onClick={() => setView(key)}
                style={{
                  display:"flex", alignItems:"center", gap:9, padding:"8px 12px",
                  borderRadius:7, cursor:"pointer", margin:"1px 6px",
                  width: "calc(100% - 12px)",
                  background: view === key
                    ? "rgba(59,130,246,.18)"
                    : accent === "red"  ? "rgba(239,68,68,.2)"
                    : "transparent",
                  color: view === key
                    ? "#3b82f6"
                    : accent === "red"  ? "#ef4444"
                    : "#8892a4",
                  border: "none",
                  textAlign: "left",
                }}
              >
                <span style={{ width:16, fontSize:13 }}>{icon}</span>
                <span style={{ fontSize:13 }}>{label}</span>
              </button>
            ))}
          </div>
        ))}

        <div style={{ marginTop:"auto", padding:12, borderTop:"1px solid #2a3348" }}>
          <div style={{ fontSize:10, color:"#5a6478", textTransform:"uppercase", letterSpacing:".06em" }}>
            Agents hidden (intruders are anonymous)
          </div>
        </div>
      </div>

      {/* ── Main ──────────────────────────────────────────────────────── */}
      <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden", minWidth:0 }}>

        {/* Topbar */}
        <div style={{ display:"flex", alignItems:"center", padding:"10px 20px", borderBottom:"1px solid #2a3348", gap:12, background:"#161b24", flexShrink:0 }}>
          <div style={{ fontSize:17, fontWeight:600, flex:1 }}>Live Security Dashboard</div>
          <div style={{ padding:"4px 12px", borderRadius:20, fontSize:11, fontWeight:700, background:"rgba(239,68,68,.25)", color:"#ff6b6b", border:"1px solid rgba(239,68,68,.4)" }}>
            {critCount} CRITICAL
          </div>
          <div style={{ fontFamily:"monospace", fontSize:13, color:"#8892a4" }}>{nowStr()}</div>
          {ws.status === "connected" && (
            <div style={{ fontSize:10, color:"#22c55e", display:"flex", alignItems:"center", gap:4 }}>
              <div style={{ width:6, height:6, borderRadius:"50%", background:"#22c55e", animation:"blink 1s infinite" }}/>
              live
            </div>
          )}
        </div>

        {/* Content */}
        <div style={{ flex:1, overflow:"auto", padding:"14px 16px", display:"flex", flexDirection:"column", gap:12 }}>
          <div style={{ background:"#1a2030", border:"1px solid #2a3348", borderRadius:10, display:"flex", flexDirection:"column", minHeight:0, overflow:"hidden" }}>
            <div style={{ padding:"10px 14px", borderBottom:"1px solid #2a3348", display:"flex", alignItems:"center", gap:8, flexShrink:0 }}>
              <div style={{ fontSize:12, fontWeight:600, color:"#8892a4", textTransform:"uppercase", letterSpacing:".06em", flex:1 }}>Alert Feed</div>
              <div style={{ width:7, height:7, borderRadius:"50%", background: ws.status === "connected" ? "#ef4444" : "#5a6478", animation: ws.status === "connected" ? "blink 1s infinite" : "none" }}/>
              <span style={{ fontSize:11, color:"#5a6478" }}>{ws.status}</span>
            </div>
            <div style={{ overflowY:"auto", flex:1 }}>
              {view === "alerts" && (
                alerts.length === 0 ? (
                  <div style={{ padding:16, color:"#5a6478", fontSize:12 }}>
                    No alerts yet — waiting for real-time events from your Windows 10 VM.
                  </div>
                ) : (
                  alerts.map((a, i) => <AlertItem key={a.id || i} alert={a} isNew={i === 0}/>)
                )
              )}
              {view === "rules" && (
                alerts.length === 0 ? (
                  <div style={{ padding:16, color:"#5a6478", fontSize:12 }}>No rules fired yet.</div>
                ) : (
                  alerts.map((a, i) => <AlertItem key={a.id || i} alert={a} isNew={i === 0}/>)
                )
              )}
              {view === "arp" && (
                alerts.filter((a) => a.type === "arp_anomaly" || a.type === "arp_spoof").length === 0 ? (
                  <div style={{ padding:16, color:"#5a6478", fontSize:12 }}>No ARP alerts yet.</div>
                ) : (
                  alerts.filter((a) => a.type === "arp_anomaly" || a.type === "arp_spoof")
                    .map((a, i) => <AlertItem key={a.id || i} alert={a} isNew={i === 0}/>)
                )
              )}
              {view === "map" && (
                <div style={{ padding: 12 }}>
                  <NetworkMap hosts={liveHosts} />
                </div>
              )}
              {view === "packets" && (
                <div style={{ padding: 12 }}>
                  <PacketInspector packets={ws.packets} pps={ws.pps} wsStatus={ws.status} />
                </div>
              )}
              {view === "ports" && (
                <div style={{ padding: 12 }}>
                  <PortMatrix portResults={ws.portResults} />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }
        @keyframes flashIn { from{background:rgba(239,68,68,.25)} to{background:transparent} }
        ::-webkit-scrollbar{width:4px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:#2a3348;border-radius:2px}
      `}</style>
    </div>
  );
}
