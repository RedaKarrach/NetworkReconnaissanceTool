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

export default function App() {
  const [currentPage, setCurrentPage] = useState("login");
  const [activeSession, setActiveSession] = useState("live");
  const [wsConnected, setWsConnected] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [dashboardEntry, setDashboardEntry] = useState("scan-tools");
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
        const online = agent.lastSeen ? Date.now() - agent.lastSeen.getTime() < 120000 : false;
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

  if (currentPage === "login") {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <div className="flex h-screen bg-bg-app text-text-primary">
      <aside
        className="flex h-full flex-col border-r border-border-default bg-bg-sidebar transition-all duration-150"
        style={{ width: isSidebarCollapsed ? "60px" : "220px" }}
      >
        <div className="border-b border-border-default px-3 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-border-accent bg-accent-muted text-accent-primary shadow-accent">
              <ShieldIcon className="h-5 w-5" />
            </div>
            {!isSidebarCollapsed && (
              <div className="min-w-0">
                <p className="truncate text-lg font-semibold text-text-primary">ReconTool</p>
                <p className="truncate text-xs text-text-tertiary">NIDS Platform</p>
              </div>
            )}
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-3">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label} className="mb-4">
              {!isSidebarCollapsed && (
                <p className="px-2 pb-2 text-xs font-medium tracking-widest text-text-tertiary">{section.label}</p>
              )}
              <div className="space-y-1">
                {section.items.map((item) => {
                  const active = isNavActive(item.id, item.page);
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => handleNavSelect(item.id, item.page)}
                      className={`group flex w-full items-center rounded-md border border-transparent px-2 py-2 text-left transition-all duration-150 ${
                        isSidebarCollapsed ? "justify-center" : "gap-3"
                      } ${
                        active
                          ? "border-border-accent bg-accent-muted text-accent-primary shadow-accent"
                          : "text-text-secondary hover:bg-bg-card-hover hover:text-text-primary"
                      }`}
                      style={active ? { borderLeftWidth: "3px", borderLeftColor: "var(--color-accent-primary)" } : undefined}
                    >
                      <item.Icon className="h-4 w-4" />
                      {!isSidebarCollapsed && <span className="truncate text-md font-medium">{item.title}</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-border-default px-2 py-3">
          <button
            type="button"
            onClick={() => setIsSidebarCollapsed((prev) => !prev)}
            className={`flex w-full items-center rounded-md border border-border-default bg-bg-card px-2 py-2 text-text-secondary transition-colors duration-150 hover:bg-bg-card-hover hover:text-text-primary ${
              isSidebarCollapsed ? "justify-center" : "gap-3"
            }`}
          >
            <ChevronIcon collapsed={isSidebarCollapsed} />
            {!isSidebarCollapsed && <span className="text-md font-medium">Collapse</span>}
          </button>
        </div>

        <div className="border-t border-border-default px-3 py-3">
          {!isSidebarCollapsed && <p className="mb-2 text-xs font-medium tracking-widest text-text-tertiary">AGENTS</p>}
          <div className="space-y-2">
            {sidebarAgents.length === 0 ? (
              <div className={`flex items-center ${isSidebarCollapsed ? "justify-center" : "gap-2"}`}>
                <span className="h-2 w-2 rounded-full bg-status-offline" />
                {!isSidebarCollapsed && <p className="text-xs text-text-tertiary">No agents yet</p>}
              </div>
            ) : (
              sidebarAgents.map((agent) => (
                <div key={agent.id} className={`flex items-center ${isSidebarCollapsed ? "justify-center" : "gap-2"}`}>
                  <span className={`h-2 w-2 rounded-full ${agent.online ? "bg-status-success" : "bg-status-offline"}`} />
                  {!isSidebarCollapsed && (
                    <div className="min-w-0">
                      <p className="truncate text-sm text-text-primary">{agent.name}</p>
                      <p className="truncate font-mono text-xs text-text-tertiary">{agent.ip}</p>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        <div className="border-t border-border-default px-3 py-2 text-center text-xs text-text-tertiary">v1.0.0</div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-16 items-center border-b border-border-default bg-bg-card px-4">
          <h1 className="text-lg font-semibold text-text-primary">{pageTitle}</h1>
          <div className="ml-auto flex items-center gap-4">
            <div className="flex items-center gap-2 text-md">
              <span className={`h-2 w-2 rounded-full transition-colors duration-150 ${wsConnected ? "bg-status-online" : "bg-status-offline"}`} />
              <span className={wsConnected ? "text-status-online" : "text-status-offline"}>
                {wsConnected ? "Live" : "Disconnected"}
              </span>
            </div>
            <div className="rounded-md border border-border-default bg-bg-elevated px-3 py-1 font-mono text-md text-text-secondary">
              {currentTime.toLocaleTimeString()}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto bg-bg-app p-4 lg:p-6">{renderPage()}</main>
      </div>
    </div>
  );
}
