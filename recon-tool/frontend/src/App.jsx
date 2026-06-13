import React, { useEffect, useMemo, useState } from "react";
import Dashboard from "./pages/Dashboard";
import SOCDashboard from "./pages/SOCDashboard";
import Endpoints from "./pages/Endpoints";
import Inventory from "./pages/Inventory";
import AttackConsole from "./components/AttackConsole";
import SessionReport from "./components/SessionReport";
import LoginPage from "./pages/LoginPage";
import { useWebSocket } from "./hooks/useWebSocket";
import { useInventory } from "./hooks/useInventory";
import { useAgentRegistry } from "./hooks/useAgentRegistry";

const UI_STATE_KEY = "recon-ui-state";

function loadUiState() {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(UI_STATE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function ShieldIcon({ className = "h-4 w-4" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M12 3 4.5 6v6.2c0 5.2 3.2 8.7 7.5 10.8 4.3-2.1 7.5-5.6 7.5-10.8V6L12 3Z" />
    </svg>
  );
}

function RadarIcon({ className = "h-4 w-4" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="4" />
      <path d="m12 12 5.8-3.4" />
    </svg>
  );
}

function CircleNodeIcon({ className = "h-4 w-4" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <circle cx="12" cy="12" r="7" />
      <circle cx="12" cy="12" r="1.2" fill="currentColor" />
    </svg>
  );
}

function BoltIcon({ className = "h-4 w-4" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M13 2 5 13h6l-1 9 9-13h-6l0-7Z" />
    </svg>
  );
}

function ReportIcon({ className = "h-4 w-4" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M6 3h9l4 4v14H6z" />
      <path d="M15 3v4h4" />
      <path d="M9 12h6M9 16h6" />
    </svg>
  );
}

function EndpointsIcon({ className = "h-4 w-4" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <rect x="4" y="4" width="6" height="6" rx="1" />
      <rect x="14" y="4" width="6" height="6" rx="1" />
      <rect x="4" y="14" width="6" height="6" rx="1" />
      <path d="M10 7h4M7 10v4M17 10v4M10 17h4" />
    </svg>
  );
}

function InventoryIcon({ className = "h-4 w-4" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M4 7h16" />
      <path d="M6 3h12a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" />
      <path d="M8 11h8M8 15h5" />
    </svg>
  );
}

function ChevronIcon({ collapsed }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-4 w-4">
      {collapsed ? <path d="m9 6 6 6-6 6" /> : <path d="m15 6-6 6 6 6" />}
    </svg>
  );
}

const NAV_SECTIONS = [
  {
    label: "MONITORING",
    items: [
      { id: "soc-monitor", page: "soc", title: "SOC Monitor", Icon: ShieldIcon },
      { id: "network-map", page: "dashboard", title: "Network Map", Icon: CircleNodeIcon },
    ],
  },
  {
    label: "SCANNING",
    items: [
      { id: "scan-tools", page: "dashboard", title: "Scan Tools", Icon: RadarIcon },
      { id: "attack-console", page: "attacks", title: "Attack Console", Icon: BoltIcon },
    ],
  },
  {
    label: "ANALYSIS",
    items: [{ id: "session-report", page: "report", title: "Session Report", Icon: ReportIcon }],
  },
  {
    label: "ASSETS",
    items: [
      { id: "endpoints", page: "endpoints", title: "Endpoints", Icon: EndpointsIcon },
      { id: "inventory", page: "inventory", title: "Inventory", Icon: InventoryIcon },
    ],
  },
];

const ONLINE_WINDOW_MS = 300000;

export default function App() {
  const initialState = loadUiState();
  const initialAuthed = false;

  const [theme, setTheme] = useState(() => {
    if (typeof window === "undefined") return "dark";
    const saved = window.localStorage.getItem("recon-theme");
    return saved === "light" ? "light" : "dark";
  });
  const [isAuthenticated, setIsAuthenticated] = useState(initialAuthed);
  const [currentPage, setCurrentPage] = useState("login");
  const [activeSession, setActiveSession] = useState("live");
  const [wsConnected, setWsConnected] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [dashboardEntry, setDashboardEntry] = useState(() => initialState.dashboardEntry || "scan-tools");
  const [currentTime, setCurrentTime] = useState(() => new Date());

  const ws = useWebSocket(activeSession);
  const { items: inventoryItems } = useInventory();
  const { items: registryItems } = useAgentRegistry();

  useEffect(() => {
    setWsConnected(ws.status === "connected");
  }, [ws.status]);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    window.localStorage.setItem("recon-theme", theme);
  }, [theme]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(UI_STATE_KEY, JSON.stringify({
      page: currentPage,
      activeSession,
      dashboardEntry,
    }));
  }, [isAuthenticated, currentPage, activeSession, dashboardEntry]);

  const pageTitle = useMemo(() => {
    if (currentPage === "soc") return "SOC Monitor";
    if (currentPage === "dashboard") {
      return dashboardEntry === "network-map" ? "Network Map" : "Scan Tools";
    }
    if (currentPage === "attacks") return "Attack Console";
    if (currentPage === "report") return "Session Report";
    if (currentPage === "endpoints") return "Endpoints";
    if (currentPage === "inventory") return "Inventory";
    return "ReconTool";
  }, [currentPage, dashboardEntry]);

  const sidebarAgents = useMemo(() => {
    const map = new Map();

    (registryItems || []).forEach((agent) => {
      const key = agent.agent_id || agent.hostname || agent.ip;
      if (!key) return;
      map.set(key, {
        id: agent.agent_id || key,
        name: agent.hostname || agent.agent_id || "unknown",
        ip: agent.ip || "—",
        lastSeen: null,
      });
    });

    (inventoryItems || []).forEach((item) => {
      const key = item.agent_id || item.hostname || (item.ips || [])[0];
      if (!key) return;

      const prev = map.get(key) || {
        id: item.agent_id || key,
        name: item.hostname || item.agent_id || "unknown",
        ip: (item.ips || [])[0] || "—",
        lastSeen: null,
      };

      map.set(key, {
        ...prev,
        id: item.agent_id || prev.id,
        name: item.hostname || prev.name,
        ip: (item.ips || [])[0] || prev.ip,
        lastSeen: item.last_seen ? new Date(item.last_seen) : prev.lastSeen,
      });
    });

    return Array.from(map.values())
      .map((agent) => {
        const online = agent.lastSeen ? Date.now() - agent.lastSeen.getTime() < ONLINE_WINDOW_MS : false;
        return { ...agent, online };
      })
      .sort((a, b) => {
        if (a.online !== b.online) return Number(b.online) - Number(a.online);
        const ta = a.lastSeen ? a.lastSeen.getTime() : 0;
        const tb = b.lastSeen ? b.lastSeen.getTime() : 0;
        return tb - ta;
      })
      .slice(0, 4);
  }, [inventoryItems, registryItems]);

  function handleLogin() {
    setIsAuthenticated(true);
    setCurrentPage("soc");
    setActiveSession("live");
  }

  function handleNavSelect(itemId, page) {
    if (page === "dashboard") {
      setDashboardEntry(itemId);
    }
    setCurrentPage(page);
  }

  function isNavActive(itemId, page) {
    if (page !== currentPage) return false;
    if (page !== "dashboard") return true;
    return dashboardEntry === itemId;
  }

  function renderPage() {
    if (currentPage === "soc") {
      return <SOCDashboard />;
    }
    if (currentPage === "dashboard") {
      return <Dashboard onSessionStart={setActiveSession} />;
    }
    if (currentPage === "attacks") {
      return <AttackConsole onSessionStart={setActiveSession} />;
    }
    if (currentPage === "report") {
      return <SessionReport sessionId={activeSession} />;
    }
    if (currentPage === "endpoints") {
      return <Endpoints />;
    }
    if (currentPage === "inventory") {
      return <Inventory />;
    }
    return <SOCDashboard />;
  }

  if (!isAuthenticated) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <div className="scene-3d flex h-screen overflow-hidden bg-bg-app text-text-primary">
      {/* Atmospheric background */}
      <div className="pointer-events-none fixed inset-0">
        <div className="holo-ring holo-ring-primary" />
        <div className="holo-ring holo-ring-secondary" />
        <div className="absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, rgba(0,212,255,0.1) 0px, rgba(0,212,255,0.1) 1px, transparent 1px, transparent 32px), repeating-linear-gradient(90deg, rgba(0,212,255,0.1) 0px, rgba(0,212,255,0.1) 1px, transparent 1px, transparent 32px)",
          }}
        />
        <div className="absolute -bottom-20 -left-20 h-[300px] w-[300px] rounded-full bg-accent-primary blur-3xl opacity-[0.03] depth-float" />
        <div className="absolute top-[10%] right-[12%] h-40 w-40 rounded-2xl border border-accent-primary/20 bg-accent-primary/5 blur-sm"
          style={{
            transform: "rotateX(58deg) rotateZ(34deg) translateZ(-60px)",
          }}
        />
      </div>

      {/* Sidebar */}
      <aside className="relative flex h-full flex-col border-r border-border-premium bg-gradient-to-b from-bg-sidebar to-bg-card/40 transition-all duration-200 tilt-3d-soft"
        style={{
          width: isSidebarCollapsed ? "60px" : "260px",
          backdropFilter: "blur(12px)",
          WebkitBackdropFilter: "blur(12px)",
          boxShadow: "inset -1px 0 0 rgba(0,212,255,0.08)",
        }}
      >
        {/* Brand */}
        <div className="border-b border-border-premium/60 px-3 py-5 transition-all duration-300">
          <div className="flex items-center gap-3">
            <div className="relative flex h-10 w-10 items-center justify-center">
              <div className="absolute inset-0 rounded-lg bg-accent-primary/20 blur opacity-0 group-hover/brand:opacity-100 transition-opacity duration-300" />
              <div className="relative flex h-10 w-10 items-center justify-center rounded-lg border border-border-accent bg-gradient-to-br from-accent-primary/30 to-accent-primary/10 text-accent-primary shadow-card">
                <ShieldIcon className="h-5 w-5" />
              </div>
            </div>
            {!isSidebarCollapsed && (
              <div className="min-w-0 transition-all duration-300">
                <p className="truncate text-lg font-bold text-gradient">ReconTool</p>
                <p className="truncate text-xs font-medium text-text-tertiary">Security Ops</p>
              </div>
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto px-2 py-4 space-y-6">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label} className="transition-all duration-300">
              {!isSidebarCollapsed && (
                <p className="px-3 pb-3 text-xs font-bold tracking-wider text-accent-primary opacity-60 uppercase">{section.label}</p>
              )}
              <div className="space-y-1.5">
                {section.items.map((item, idx) => {
                  const active = isNavActive(item.id, item.page);
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => handleNavSelect(item.id, item.page)}
                      className={`group relative flex w-full items-center rounded-lg px-3 py-2.5 text-left transition-all duration-200 stagger-item`}
                      style={{ animationDelay: `${idx * 30}ms` }}
                    >
                      {/* Active background */}
                      {active && (
                        <div className="absolute inset-0 rounded-lg bg-accent-primary/15 border border-accent-primary/40"
                          style={{
                            boxShadow: "inset 0 0 12px rgba(0,212,255,0.1)",
                          }}
                        />
                      )}

                      {/* Hover glow */}
                      <div className="absolute inset-0 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300 bg-white/[0.06] border border-white/[0.08]" />

                      <item.Icon className={`relative h-4 w-4 flex-shrink-0 transition-all duration-200 ${
                        active ? "text-accent-primary" : "text-text-secondary group-hover:text-accent-primary"
                      }`} />

                      {!isSidebarCollapsed && (
                        <span className={`relative ml-3 truncate text-sm font-medium transition-colors duration-200 ${
                          active ? "text-accent-primary font-semibold" : "text-text-secondary group-hover:text-text-primary"
                        }`}>
                          {item.title}
                        </span>
                      )}

                      {active && !isSidebarCollapsed && (
                        <div className="absolute right-2 h-1.5 w-1.5 rounded-full bg-accent-primary animate-pulse" />
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Collapse button */}
        <div className="border-t border-border-premium/60 px-2 py-3">
          <button
            type="button"
            onClick={() => setIsSidebarCollapsed((prev) => !prev)}
            className="group flex w-full items-center rounded-lg border border-border-default/40 bg-white/[0.05] px-3 py-2.5 text-text-tertiary transition-all duration-200 hover:bg-white/[0.08] hover:text-text-secondary hover:border-border-elevated/60"
          >
            <ChevronIcon collapsed={isSidebarCollapsed} />
            {!isSidebarCollapsed && <span className="ml-3 text-sm font-medium">Collapse</span>}
          </button>
        </div>

        {/* Agents section */}
        <div className="border-t border-border-premium/60 px-3 py-4">
          {!isSidebarCollapsed && <p className="mb-3 text-xs font-bold tracking-wider text-accent-primary/60 uppercase">Live Agents</p>}
          <div className="space-y-2">
            {sidebarAgents.length === 0 ? (
              <div className={`flex items-center text-text-tertiary ${isSidebarCollapsed ? "justify-center py-2" : "gap-2"}`}>
                <span className="h-2 w-2 rounded-full bg-status-offline/60" />
                {!isSidebarCollapsed && <p className="text-xs">No agents</p>}
              </div>
            ) : (
              sidebarAgents.map((agent, idx) => (
                <div key={agent.id}
                  className="group/agent rounded-lg border border-transparent p-2 transition-all duration-200 hover:border-border-elevated/40 hover:bg-white/[0.05]"
                  style={{
                    animationDelay: `${idx * 40}ms`,
                  }}
                >
                  <div className={`flex items-center ${isSidebarCollapsed ? "justify-center" : "gap-2"}`}>
                    <span className={`relative h-2.5 w-2.5 rounded-full transition-all duration-200 ${
                      agent.online
                        ? "bg-status-online shadow-lg shadow-status-online/50"
                        : "bg-status-offline/50"
                    }`} />
                    {!isSidebarCollapsed && (
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-text-primary group-hover/agent:text-accent-primary transition-colors duration-200">{agent.name}</p>
                        <p className="truncate font-mono text-xs text-text-tertiary">{agent.ip}</p>
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-border-premium/60 px-3 py-3 text-center" />
      </aside>

      {/* Main content */}
      <div className="relative flex min-w-0 flex-1 flex-col scene-3d">
        {/* Header */}
        <header className="relative border-b border-border-premium/40 bg-gradient-to-r from-bg-card/60 to-bg-elevated/40 px-6 py-4 transition-all duration-300 tilt-3d-soft"
          style={{
            backdropFilter: "blur(12px)",
            WebkitBackdropFilter: "blur(12px)",
            boxShadow: "0 1px 0 rgba(0,212,255,0.1)",
          }}
        >
          {/* Header glow */}
          <div className="absolute inset-0 opacity-0 transition-opacity duration-300"
            style={{
              background: "linear-gradient(90deg, transparent, rgba(0,212,255,0.05), transparent)",
            }}
          />

          <div className="relative flex items-center justify-between">
            {/* Title */}
            <div>
              <h1 className="text-2xl font-bold text-text-primary">{pageTitle}</h1>
              <p className="mt-1 text-xs font-medium text-text-tertiary tracking-wide">Advanced Network Operations Center</p>
            </div>

            {/* Right side controls */}
            <div className="flex items-center gap-4">
              {/* Theme switch */}
              <button
                type="button"
                onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
                className="flex items-center gap-2 rounded-lg border border-border-default/40 bg-white/[0.04] px-4 py-2.5 text-sm font-semibold text-text-secondary transition-all duration-300 hover:bg-white/[0.06] hover:text-text-primary"
                aria-label="Toggle light and dark mode"
                title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              >
                {theme === "dark" ? (
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="4" />
                    <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
                  </svg>
                ) : (
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 12.79A9 9 0 1 1 11.21 3c0 .28-.01.56-.01.84A7 7 0 0 0 18.16 10.8c.28 0 .56 0 .84-.01Z" />
                  </svg>
                )}
                {theme === "dark" ? "Light" : "Dark"}
              </button>

              {/* Connection status */}
              <div className="flex items-center gap-3 rounded-lg border border-border-default/40 bg-white/[0.04] px-4 py-2.5 transition-all duration-300 hover:bg-white/[0.06]">
                <div className="flex items-center gap-2">
                  <span className={`h-2.5 w-2.5 rounded-full transition-all duration-200 ${
                    wsConnected
                      ? "bg-status-online shadow-lg shadow-status-online/50 animate-pulse"
                      : "bg-status-offline/60"
                  }`} />
                  <span className={`text-sm font-semibold transition-colors duration-200 ${
                    wsConnected ? "text-status-online" : "text-status-offline/80"
                  }`}>
                    {wsConnected ? "LIVE" : "OFFLINE"}
                  </span>
                </div>
              </div>

              {/* Clock */}
              <div className="flex items-center gap-2 rounded-lg border border-border-default/40 bg-white/[0.04] px-4 py-2.5 font-mono text-sm font-medium text-text-secondary transition-all duration-300 hover:bg-white/[0.06]">
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <polyline points="12 6 12 12 16 14" />
                </svg>
                {currentTime.toLocaleTimeString()}
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="relative flex-1 overflow-y-auto">
          <div className="p-6 lg:p-8">
            {renderPage()}
          </div>
        </main>
      </div>
    </div>
  );
}

