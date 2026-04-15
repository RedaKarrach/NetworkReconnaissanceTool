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

import { useState, useEffect, useRef, useCallback } from "react";

// ── Config ────────────────────────────────────────────────────────────────────
const WS_BASE        = process.env.REACT_APP_WS_URL || "ws://localhost:8000";
const LIVE_SESSION   = "live";   // shared session for all agent alerts

// ── Severity helpers ──────────────────────────────────────────────────────────
const SEV_BAR   = { critical:"#ef4444", high:"#f59e0b", medium:"#f97316", low:"#3b82f6" };
const SEV_BG    = { critical:"rgba(239,68,68,.18)", high:"rgba(245,158,11,.18)", medium:"rgba(249,115,22,.18)", low:"rgba(59,130,246,.18)" };
const SEV_TEXT  = { critical:"#ff6b6b", high:"#fbbf24", medium:"#fb923c", low:"#60a5fa" };
const SEV_LABEL = { critical:"CRITICAL", high:"HIGH", medium:"MEDIUM", low:"LOW" };

// ── Tiny hooks ────────────────────────────────────────────────────────────────
function useTick(ms) {
  const [t, setT] = useState(0);
  useEffect(() => { const id = setInterval(() => setT(n => n + 1), ms); return () => clearInterval(id); }, [ms]);
  return t;
}

function nowStr() {
  const d = new Date();
  const p = n => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function MetricCard({ label, value, sub, color }) {
  return (
    <div style={{ background:"#1a2030", border:"1px solid #2a3348", borderRadius:10, padding:"12px 14px" }}>
      <div style={{ fontSize:11, color:"#8892a4", marginBottom:6 }}>{label}</div>
      <div style={{ fontSize:26, fontWeight:700, fontFamily:"monospace", color, lineHeight:1, marginBottom:4 }}>
        {value}
      </div>
      <div style={{ fontSize:11, color }}>{sub}</div>
    </div>
  );
}

function AlertItem({ alert, isNew }) {
  const bar  = SEV_BAR[alert.severity]   || "#3b82f6";
  const bg   = SEV_BG[alert.severity]    || "transparent";
  const text = SEV_TEXT[alert.severity]  || "#60a5fa";
  const lbl  = SEV_LABEL[alert.severity] || alert.severity.toUpperCase();

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

function AgentCard({ name, ip, role, avatarBg, avatarEmoji, statusLabel, statusColor, stats }) {
  return (
    <div style={{ background:"#1a2030", border:"1px solid #2a3348", borderRadius:10, padding:"12px 14px" }}>
      <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10 }}>
        <div style={{ width:34, height:34, borderRadius:9, background:avatarBg, display:"flex", alignItems:"center", justifyContent:"center", fontSize:16, flexShrink:0 }}>
          {avatarEmoji}
        </div>
        <div style={{ flex:1 }}>
          <div style={{ fontSize:13, fontWeight:600, color:"#e2e8f0" }}>{name}</div>
          <div style={{ fontFamily:"monospace", fontSize:11, color:"#5a6478" }}>{ip}</div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:5, fontSize:11, fontWeight:600, color:statusColor }}>
          <div style={{ width:6, height:6, borderRadius:"50%", background:statusColor, animation:"blink 1s infinite" }}/>
          {statusLabel}
        </div>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:6 }}>
        {stats.map((s, i) => (
          <div key={i} style={{ background:"#1e2535", borderRadius:7, padding:"7px 10px" }}>
            <div style={{ fontSize:10, color:"#5a6478", marginBottom:2 }}>{s.label}</div>
            <div style={{ fontSize:13, fontWeight:600, color:s.color || "#e2e8f0" }}>{s.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SynChart({ synPps }) {
  const barsRef = useRef([]);
  const [bars, setBars] = useState(() => {
    const d = [3,4,5,4,6,5,7,6,7,5,6,7,8,10,13,17,24,37,50,65,77,84,87,89,88,86,84,85,86,87,89,90,88,87,89,91,90,88,89,87,88,90,91,89,90,88,87,89,90,92];
    return d.map(v => ({ h: Math.max(3, Math.round(v * 0.75)), attack: v > 40 }));
  });

  useEffect(() => {
    setBars(prev => {
      const next = [...prev.slice(1)];
      const h = Math.max(3, Math.min(68, Math.round(synPps * 0.072)));
      next.push({ h, attack: true });
      return next;
    });
  }, [synPps]);

  return (
    <div style={{ background:"#1a2030", border:"1px solid #2a3348", borderRadius:10, overflow:"hidden", flexShrink:0 }}>
      <div style={{ padding:"8px 12px 0", borderBottom:"none" }}>
        <span style={{ fontSize:11, fontWeight:600, color:"#8892a4", textTransform:"uppercase", letterSpacing:".06em" }}>
          SYN Rate (60s)
        </span>
      </div>
      <div style={{ display:"flex", alignItems:"flex-end", gap:3, padding:"8px 10px 0", height:80 }}>
        {bars.map((b, i) => (
          <div key={i} style={{
            flex:1, borderRadius:"2px 2px 0 0", minHeight:3,
            height: b.h + "px",
            background: b.attack ? "rgba(239,68,68,.75)" : "#2a3a5a",
            transition:"height .3s",
          }}/>
        ))}
      </div>
      <div style={{ display:"flex", justifyContent:"space-between", padding:"4px 10px 8px", fontFamily:"monospace", fontSize:10, color:"#5a6478" }}>
        <span>-60s</span><span>-45s</span><span>-30s</span><span>-15s</span><span>now</span>
      </div>
    </div>
  );
}

function RulesPanel({ synPps, arpCount }) {
  const sparkData = {
    "DET-001": [3,5,8,12,18,22,28,35],
    "DET-002": [1,2,1,3,4,5,7,6],
    "DET-003": [0,0,1,0,1,2,2,1],
  };
  const rules = [
    { id:"DET-001", name:"SYN flood detected",   count:synPps,  color:"#ef4444" },
    { id:"DET-002", name:"ARP cache poisoning",   count:arpCount, color:"#f59e0b" },
    { id:"DET-003", name:"Port sweep >15 ports",  count:3,        color:"#fb923c" },
  ];

  return (
    <div style={{ background:"#1a2030", border:"1px solid #2a3348", borderRadius:10, overflow:"hidden", flex:1 }}>
      <div style={{ padding:"8px 14px", borderBottom:"1px solid #2a3348" }}>
        <span style={{ fontSize:11, fontWeight:600, color:"#8892a4", textTransform:"uppercase", letterSpacing:".06em" }}>
          Detection rules fired
        </span>
      </div>
      {rules.map(rule => {
        const data = sparkData[rule.id] || [];
        const max  = Math.max(...data);
        return (
          <div key={rule.id} style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 14px", borderBottom:"1px solid #1e2535" }}>
            <div style={{ fontFamily:"monospace", fontSize:10, color:"#3b82f6", width:56, flexShrink:0 }}>{rule.id}</div>
            <div style={{ fontSize:11, color:"#8892a4", flex:1 }}>{rule.name}</div>
            {/* sparkline */}
            <div style={{ display:"flex", alignItems:"flex-end", gap:1, height:16 }}>
              {data.map((v, i) => (
                <div key={i} style={{ width:3, borderRadius:"1px 1px 0 0", background:rule.color, opacity:.7, height: Math.max(2, Math.round(v/max*14)) + "px" }}/>
              ))}
            </div>
            <div style={{ fontFamily:"monospace", fontSize:11, fontWeight:700, color:rule.color, width:36, textAlign:"right" }}>
              {rule.count}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function SOCDashboard() {
  const tick = useTick(1200);

  // Live metrics state
  const [synPps,    setSynPps]    = useState(978);
  const [arpCount,  setArpCount]  = useState(38);
  const [alertCount,setAlertCount]= useState(208);
  const [pktsSent,  setPktsSent]  = useState(213207);
  const [synRecv,   setSynRecv]   = useState(5049);
  const [cpuVal,    setCpuVal]    = useState(99);
  const [alerts,    setAlerts]    = useState([]);
  const [wsStatus,  setWsStatus]  = useState("connecting");
  const newIdxRef = useRef(0);

  // Seed initial alerts
  useEffect(() => {
    const seed = [
      { severity:"medium",   message:"ICMP redirect probe from 192.168.56.10",    src_ip:"192.168.56.10 (kali)", type:"DET-007", t:"14:13:36", id:1 },
      { severity:"critical", message:"TCP backlog 100% full on port :80",           src_ip:"192.168.56.101",        type:"DET-001", t:"14:13:31", id:2 },
      { severity:"high",     message:"ARP table change detected on win-victim",     src_ip:"192.168.56.10 (kali)", type:"DET-002", t:"14:13:26", id:3 },
      { severity:"critical", message:"SYN flood — 200 SYNs/10s threshold hit",      src_ip:"192.168.56.10 (kali)", type:"DET-001", t:"14:13:18", id:4 },
      { severity:"high",     message:"TCP SYN_RECV backlog exhausted on :80",       src_ip:"192.168.56.101",        type:"DET-001", t:"14:13:10", id:5 },
      { severity:"high",     message:"Port sweep >15 ports from 192.168.56.10",     src_ip:"192.168.56.10 (kali)", type:"DET-003", t:"14:12:58", id:6 },
      { severity:"medium",   message:"Xmas scan probe received (FIN+PSH+URG)",      src_ip:"192.168.56.10 (kali)", type:"DET-004", t:"14:12:51", id:7 },
      { severity:"low",      message:"OS fingerprint probe (TTL=64 SYN-ACK)",       src_ip:"192.168.56.10 (kali)", type:"DET-005", t:"14:12:35", id:8 },
    ];
    setAlerts(seed);
  }, []);

  // Try WebSocket connection to Django backend
  useEffect(() => {
    const ws = new WebSocket(`${WS_BASE}/ws/scan/${LIVE_SESSION}/`);
    ws.onopen  = () => setWsStatus("connected");
    ws.onclose = () => setWsStatus("disconnected");
    ws.onerror = () => setWsStatus("disconnected");
    ws.onmessage = e => {
      try {
        const data = JSON.parse(e.data);
        if (data.event_type === "alert" || data.type) {
          const newAlert = {
            ...data,
            t:  data.timestamp ? data.timestamp.slice(11, 19) : nowStr(),
            id: Date.now(),
            isNew: true,
          };
          setAlerts(prev => [newAlert, ...prev].slice(0, 30));
          setAlertCount(n => n + 1);
        }
      } catch {}
    };
    return () => ws.close();
  }, []);

  // Simulation tick (runs when WS is disconnected = demo mode)
  const NEW_ALERTS = [
    { severity:"critical", message:"SYN flood spike — rate exceeded 1000/s",    src_ip:"192.168.56.10 (kali)", type:"DET-001" },
    { severity:"high",     message:"ARP table change detected on win-victim",    src_ip:"192.168.56.10 (kali)", type:"DET-002" },
    { severity:"critical", message:"TCP backlog 100% full on port :80",          src_ip:"192.168.56.101",        type:"DET-001" },
    { severity:"medium",   message:"ICMP redirect probe from 192.168.56.10",    src_ip:"192.168.56.10 (kali)", type:"DET-007" },
    { severity:"high",     message:"Banner grab on SSH port 22 detected",       src_ip:"192.168.56.10 (kali)", type:"DET-003" },
    { severity:"critical", message:"SYN_RECV connections maxed out on victim",   src_ip:"192.168.56.101",        type:"DET-001" },
  ];

  useEffect(() => {
    // Always animate metrics
    setSynPps(v  => Math.min(999, Math.max(400, v + Math.round((Math.random()-.3)*60))));
    setPktsSent(v => v + Math.round(synPps * 0.9 + Math.random()*80));
    setSynRecv(v  => Math.min(9999, v + Math.round(Math.random()*35)));
    setCpuVal(v   => Math.min(99, Math.max(70, v + Math.round((Math.random()-.4)*4))));
    setAlertCount(n => n + 1);

    if (tick % 3 === 0) setArpCount(v => v + (Math.random() > .6 ? 1 : 0));

    // Only push simulated alerts when WS not connected
    if (wsStatus !== "connected" && tick % 4 === 0) {
      const a = {
        ...NEW_ALERTS[newIdxRef.current % NEW_ALERTS.length],
        t: nowStr(),
        id: Date.now(),
        isNew: true,
      };
      newIdxRef.current++;
      setAlerts(prev => [a, ...prev].slice(0, 30));
    }
  }, [tick]);

  const critCount = alerts.filter(a => a.severity === "critical").length;

  return (
    <div style={{ display:"flex", flex:1, width:"100%", minWidth:0, height:"100%", background:"#0f1117", color:"#e2e8f0", fontFamily:"-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif", fontSize:13 }}>

      {/* ── Sidebar ───────────────────────────────────────────────────── */}
      <div style={{ width:200, minWidth:200, background:"#161b24", borderRight:"1px solid #2a3348", display:"flex", flexDirection:"column" }}>
        <div style={{ padding:"16px 14px 12px", borderBottom:"1px solid #2a3348" }}>
          <div style={{ fontSize:15, fontWeight:700, color:"#e2e8f0" }}>AegisWR SOC</div>
          <div style={{ fontSize:11, color:"#5a6478", marginTop:2 }}>Wassim + Reda Cyber Defense</div>
        </div>

        {[["VIEWS",[
          ["!", "Live alerts",  "red"],
          ["◉", "Network map", "blue"],
          ["≡", "Packet logs", null],
          ["⊞", "Port matrix", null],
          ["📄","Reports",     null],
        ]],["DETECTION",[
          ["🔍","Rules fired", null],
          ["🛡","ARP watch",   null],
        ]]].map(([section, items]) => (
          <div key={section}>
            <div style={{ padding:"14px 10px 4px", fontSize:10, fontWeight:600, color:"#5a6478", textTransform:"uppercase", letterSpacing:".08em" }}>
              {section}
            </div>
            {items.map(([icon, label, accent]) => (
              <div key={label} style={{
                display:"flex", alignItems:"center", gap:9, padding:"8px 12px",
                borderRadius:7, cursor:"pointer", margin:"1px 6px",
                background: accent === "red"  ? "rgba(239,68,68,.2)"
                          : accent === "blue" ? "rgba(59,130,246,.18)"
                          : "transparent",
                color: accent === "red"  ? "#ef4444"
                     : accent === "blue" ? "#3b82f6"
                     : "#8892a4",
              }}>
                <span style={{ width:16, fontSize:13 }}>{icon}</span>
                <span style={{ fontSize:13 }}>{label}</span>
              </div>
            ))}
          </div>
        ))}

        {/* Agents */}
        <div style={{ marginTop:"auto", padding:12, borderTop:"1px solid #2a3348" }}>
          <div style={{ fontSize:10, color:"#5a6478", textTransform:"uppercase", letterSpacing:".06em", marginBottom:8 }}>Agents</div>
          {[
            { name:"kali-attacker", os:"Kali",  color:"#ef4444" },
            { name:"win-victim",    os:"Win10", color:"#22c55e" },
          ].map(a => (
            <div key={a.name} style={{ display:"flex", alignItems:"center", gap:7, padding:"4px 0" }}>
              <div style={{ width:7, height:7, borderRadius:"50%", background:a.color, animation: a.color==="#ef4444" ? "blink 1s infinite" : "none" }}/>
              <div style={{ fontSize:11, color:"#8892a4", flex:1 }}>{a.name}</div>
              <div style={{ fontSize:10, color:"#5a6478" }}>{a.os}</div>
            </div>
          ))}
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
          <div style={{ padding:"4px 12px", borderRadius:20, fontSize:11, fontWeight:700, background:"rgba(34,197,94,.2)", color:"#4ade80", border:"1px solid rgba(34,197,94,.35)" }}>
            Agents: 2/2
          </div>
          <div style={{ fontFamily:"monospace", fontSize:13, color:"#8892a4" }}>{nowStr()}</div>
          {wsStatus === "connected" && (
            <div style={{ fontSize:10, color:"#22c55e", display:"flex", alignItems:"center", gap:4 }}>
              <div style={{ width:6, height:6, borderRadius:"50%", background:"#22c55e", animation:"blink 1s infinite" }}/>
              live
            </div>
          )}
        </div>

        {/* Content */}
        <div style={{ flex:1, overflow:"auto", padding:"14px 16px", display:"flex", flexDirection:"column", gap:12 }}>

          {/* Metrics */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, flexShrink:0 }}>
            <MetricCard label="SYN packets / sec" value={synPps.toLocaleString()} sub="↑ SYN flood active" color="#ef4444"/>
            <MetricCard label="ARP anomalies"     value={arpCount}               sub={`MAC changed × ${arpCount}`} color="#f59e0b"/>
            <MetricCard label="Alerts fired"       value={alertCount}             sub="Last 60 seconds"  color="#ef4444"/>
            <MetricCard label="Agents online"      value={2}                      sub="kali · win-victim" color="#22c55e"/>
          </div>

          {/* Two columns */}
          <div style={{ display:"grid", gridTemplateColumns:"1fr 340px", gap:12, flex:1, minHeight:0 }}>

            {/* Alert feed */}
            <div style={{ background:"#1a2030", border:"1px solid #2a3348", borderRadius:10, display:"flex", flexDirection:"column", minHeight:0, overflow:"hidden" }}>
              <div style={{ padding:"10px 14px", borderBottom:"1px solid #2a3348", display:"flex", alignItems:"center", gap:8, flexShrink:0 }}>
                <div style={{ fontSize:12, fontWeight:600, color:"#8892a4", textTransform:"uppercase", letterSpacing:".06em", flex:1 }}>Alert Feed</div>
                <div style={{ width:7, height:7, borderRadius:"50%", background:"#ef4444", animation:"blink 1s infinite" }}/>
                <span style={{ fontSize:11, color:"#5a6478" }}>live</span>
              </div>
              <div style={{ overflowY:"auto", flex:1 }}>
                {alerts.map((a, i) => <AlertItem key={a.id || i} alert={a} isNew={a.isNew && i === 0}/>)}
              </div>
            </div>

            {/* Right column */}
            <div style={{ display:"flex", flexDirection:"column", gap:10, minHeight:0 }}>

              <AgentCard
                name="kali-attacker" ip="192.168.56.10"
                avatarBg="rgba(239,68,68,.2)" avatarEmoji="🐉"
                statusLabel="ATTACKING" statusColor="#ef4444"
                stats={[
                  { label:"Attack type", value:"SYN Flood",                     color:"#ef4444" },
                  { label:"Target",      value:".101 :80",                       color:"#e2e8f0" },
                  { label:"Pkts sent",   value:pktsSent.toLocaleString(),        color:"#ef4444" },
                  { label:"Spoofed IPs", value:"random",                         color:"#f59e0b" },
                ]}
              />

              <AgentCard
                name="win-victim" ip="192.168.56.101"
                avatarBg="rgba(59,130,246,.18)" avatarEmoji="🪟"
                statusLabel="UNDER ATTACK" statusColor="#f59e0b"
                stats={[
                  { label:"SYN_RECV", value:synRecv.toLocaleString(), color:"#ef4444" },
                  { label:"CPU load", value:cpuVal + "%",              color:"#f59e0b" },
                  { label:"Port :80", value:"degraded",                color:"#f59e0b" },
                  { label:"ARP table",value:"poisoned",                color:"#ef4444" },
                ]}
              />

              <SynChart synPps={synPps}/>
              <RulesPanel synPps={synPps} arpCount={arpCount}/>

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
