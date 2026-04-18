/**
 * App.jsx
 * -------
 * Root component with sidebar navigation and page routing.
 * Pages:
 *   - soc        → SOC Live Dashboard (the dark monitoring view)
 *   - dashboard  → Scan controls + NetworkMap / PortMatrix / OS / Packets
 *   - attacks    → Attack Console (ARP spoof, SYN flood, ICMP redirect)
 *   - report     → Session Report + PDF export
 */
import React, { useEffect, useState } from "react";
import Dashboard     from "./pages/Dashboard";
import SOCDashboard  from "./pages/SOCDashboard";
import AttackConsole from "./components/AttackConsole";
import SessionReport from "./components/SessionReport";
import Inventory     from "./pages/Inventory";
import Endpoints     from "./pages/Endpoints";
import Login         from "./pages/Login";

const NAV = [
  { id: "soc",       label: "SOC Monitor",    icon: "🛡" },
  { id: "endpoints", label: "Endpoints",      icon: "W" },
  { id: "dashboard", label: "Scan Tools",     icon: "⬡" },
  { id: "inventory", label: "Host Inventory", icon: "🧭" },
  { id: "attacks",   label: "Attack Console", icon: "⚡" },
  { id: "report",    label: "Session Report", icon: "📋" },
];

const VALID_PAGES = new Set(NAV.map((item) => item.id));

export default function App() {
  const [auth, setAuth] = useState(() => {
    try {
      const saved = window.localStorage.getItem("recon.auth");
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [page,          setPage]          = useState(() => {
    try {
      const saved = window.localStorage.getItem("recon.page");
      return VALID_PAGES.has(saved) ? saved : "dashboard";
    } catch {
      return "dashboard";
    }
  });
  const [activeSession, setActiveSession] = useState(null);

  useEffect(() => {
    try {
      window.localStorage.setItem("recon.page", page);
    } catch {
      // Ignore storage failures (private mode, policy restrictions, etc.)
    }
  }, [page]);

  function handleLogin(payload) {
    const session = { user: payload.username || "root", ts: Date.now() };
    setAuth(session);
    try {
      window.localStorage.setItem("recon.auth", JSON.stringify(session));
    } catch {
      // Ignore storage failures
    }
  }

  function handleLogout() {
    setAuth(null);
    try {
      window.localStorage.removeItem("recon.auth");
    } catch {
      // Ignore storage failures
    }
  }

  if (!auth) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div style={{ display:"flex", height:"100vh", overflow:"hidden" }}>

      {/* SOC page owns its own full-screen layout including sidebar */}
      {page === "soc" ? (
        <div style={{ display:"flex", flex:1, minWidth:0, position:"relative", background:"#0f1117" }}>
          <SOCDashboard />
          {/* Switch button overlay */}
          <div style={{ position:"absolute", bottom:16, left:16, zIndex:100 }}>
            <button
              onClick={() => setPage("dashboard")}
              style={{
                background:"#1a2030", border:"1px solid #2a3348",
                color:"#8892a4", borderRadius:8, padding:"6px 12px",
                fontSize:11, cursor:"pointer", display:"flex", alignItems:"center", gap:6,
              }}
            >
              ⬡ Switch to Scan Tools
            </button>
          </div>
        </div>
      ) : (

        /* All other pages use the original light sidebar layout */
        <div className="flex h-screen bg-gray-950 text-gray-100 overflow-hidden" style={{ flex:1 }}>

          {/* Sidebar */}
          <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col flex-shrink-0">
            <div className="px-4 py-5 border-b border-gray-800">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 text-xl">⬡</span>
                <div>
                  <div className="text-white font-bold text-sm">ReconTool</div>
                  <div className="text-gray-600 text-[10px]">Network Intelligence</div>
                </div>
              </div>
            </div>

            <nav className="flex-1 px-2 py-4 space-y-1">
              {NAV.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setPage(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm
                              transition-colors text-left ${
                    page === item.id
                      ? "bg-cyan-900/50 text-cyan-400 border border-cyan-800"
                      : "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
                  }`}
                >
                  <span>{item.icon}</span>
                  {item.label}
                </button>
              ))}
            </nav>

            <div className="px-3 py-3 border-t border-gray-800">
              <div className="text-gray-600 text-[10px] uppercase mb-1">Active Session</div>
              {activeSession ? (
                <div className="text-cyan-500 font-mono text-[10px] truncate">
                  {activeSession.slice(0, 18)}…
                </div>
              ) : (
                <div className="text-gray-700 text-xs">None</div>
              )}
            </div>
          </aside>

          {/* Main content */}
          <main className="flex-1 overflow-y-auto">
            <header className="sticky top-0 z-10 bg-gray-950/90 backdrop-blur
                               border-b border-gray-800 px-6 py-3 flex items-center gap-3">
              <h1 className="text-white font-semibold text-sm flex-1">
                {NAV.find((n) => n.id === page)?.label}
              </h1>
              <div className="text-xs text-gray-500">root: {auth.user}</div>
              <div className="flex items-center gap-2 text-xs text-gray-600">
                <span className="w-2 h-2 rounded-full bg-green-500" />
                Backend connected
              </div>
              <button
                onClick={handleLogout}
                className="text-xs text-gray-400 border border-gray-700 rounded px-2 py-1 hover:text-gray-200"
              >
                Logout
              </button>
            </header>

            <div className="p-6">
              {page === "endpoints" && <Endpoints />}
              {page === "dashboard" && <Dashboard onSessionStart={setActiveSession} />}
              {page === "inventory" && <Inventory />}
              {page === "attacks"   && <AttackConsole onSessionStart={setActiveSession} />}
              {page === "report"    && <SessionReport sessionId={activeSession} />}
            </div>
          </main>
        </div>
      )}
    </div>
  );
}
