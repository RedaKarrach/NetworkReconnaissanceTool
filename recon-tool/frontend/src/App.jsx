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
    <div className="flex h-screen overflow-hidden bg-bg-app text-text-primary">
      {/* Sidebar */}
      <aside className="relative flex h-full flex-col border-r border-border-default bg-bg-sidebar transition-[width] duration-150"
        style={{ width: isSidebarCollapsed ? "60px" : "240px" }}
      >
        {/* Brand */}
        <div className="border-b border-border-default px-3 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md border border-border-default bg-bg-elevated text-accent-primary">
              <ShieldIcon className="h-5 w-5" />
            </div>
            {!isSidebarCollapsed && (
              <div className="min-w-0">
                <p className="truncate text-md font-semibold text-text-primary">ReconTool</p>
                <p className="truncate text-xs font-medium text-text-tertiary">Security Ops</p>
              </div>
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto px-2 py-4 space-y-5">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label}>
              {!isSidebarCollapsed && (
                <p className="px-3 pb-2 text-xs font-semibold tracking-wide text-text-tertiary uppercase">{section.label}</p>
              )}
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const active = isNavActive(item.id, item.page);
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => handleNavSelect(item.id, item.page)}
                      className={`group relative flex w-full items-center rounded-md px-3 py-2 text-left transition-colors duration-120 ${
                        active
                          ? "bg-accent-muted border border-accent-border"
                          : "border border-transparent hover:bg-bg-card-hover"
                      }`}
                    >
                      <item.Icon className={`h-4 w-4 flex-shrink-0 ${
                        active ? "text-accent-primary" : "text-text-tertiary group-hover:text-text-secondary"
                      }`} />
                      {!isSidebarCollapsed && (
                        <span className={`ml-3 truncate text-sm ${
                          active ? "text-text-primary font-semibold" : "text-text-secondary group-hover:text-text-primary"
                        }`}>
                          {item.title}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Collapse button */}
        <div className="border-t border-border-default px-2 py-3">
          <button
            type="button"
            onClick={() => setIsSidebarCollapsed((prev) => !prev)}
            className="flex w-full items-center rounded-md border border-border-default px-3 py-2 text-text-tertiary transition-colors duration-120 hover:bg-bg-card-hover hover:text-text-secondary"
          >
            <ChevronIcon collapsed={isSidebarCollapsed} />
            {!isSidebarCollapsed && <span className="ml-3 text-sm font-medium">Collapse</span>}
          </button>
        </div>

        {/* Agents section */}
        <div className="border-t border-border-default px-3 py-4">
          {!isSidebarCollapsed && <p className="mb-2 text-xs font-semibold tracking-wide text-text-tertiary uppercase">Live Agents</p>}
          <div className="space-y-1">
            {sidebarAgents.length === 0 ? (
              <div className={`flex items-center text-text-tertiary ${isSidebarCollapsed ? "justify-center py-2" : "gap-2"}`}>
                <span className="h-2 w-2 rounded-full bg-status-offline" />
                {!isSidebarCollapsed && <p className="text-xs">No agents</p>}
              </div>
            ) : (
              sidebarAgents.map((agent) => (
                <div key={agent.id}
                  className="group/agent rounded-md border border-transparent p-2 transition-colors duration-120 hover:border-border-default hover:bg-bg-card-hover"
                >
                  <div className={`flex items-center ${isSidebarCollapsed ? "justify-center" : "gap-2"}`}>
                    <span className={`h-2 w-2 rounded-full ${agent.online ? "bg-status-online" : "bg-status-offline"}`} />
                    {!isSidebarCollapsed && (
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-text-primary">{agent.name}</p>
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
        <div className="border-t border-border-default px-3 py-3 text-center" />
      </aside>

      {/* Main content */}
      <div className="relative flex min-w-0 flex-1 flex-col">
        {/* Header */}
        <header className="border-b border-border-default bg-bg-card px-6 py-3">
          <div className="flex items-center justify-between">
            {/* Title */}
            <div>
              <h1 className="text-xl font-semibold text-text-primary">{pageTitle}</h1>
              <p className="mt-0.5 text-xs font-medium text-text-tertiary">Network Operations Center</p>
            </div>

            {/* Right side controls */}
            <div className="flex items-center gap-2">
              {/* Theme switch */}
              <button
                type="button"
                onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
                className="flex items-center gap-2 rounded-md border border-border-default bg-bg-elevated px-3 py-1.5 text-sm font-medium text-text-secondary transition-colors duration-120 hover:bg-bg-card-hover hover:text-text-primary"
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
              <div className="flex items-center gap-2 rounded-md border border-border-default bg-bg-elevated px-3 py-1.5">
                <span className={`h-2 w-2 rounded-full ${wsConnected ? "bg-status-online" : "bg-status-offline"}`} />
                <span className={`text-sm font-semibold ${wsConnected ? "text-status-online" : "text-text-tertiary"}`}>
                  {wsConnected ? "LIVE" : "OFFLINE"}
                </span>
              </div>

              {/* Clock */}
              <div className="flex items-center gap-2 rounded-md border border-border-default bg-bg-elevated px-3 py-1.5 font-mono text-sm text-text-secondary">
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
          <div className="p-6">
            {renderPage()}
          </div>
        </main>
      </div>
    </div>
  );
}

