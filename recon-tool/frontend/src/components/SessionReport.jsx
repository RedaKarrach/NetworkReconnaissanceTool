/**
 * components/SessionReport.jsx
 * ----------------------------
 * Summary of a completed scan session with PDF download button.
 */
import React, { useState } from "react";
import { useScan } from "../hooks/useScan";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

const CHART_COLORS = {
  open: "#22C55E",
  closed: "#EF4444",
  filtered: "#F59E0B",
};

const SEVERITY_STYLE = {
  critical: {
    bar: "bg-threat-critical",
    badge: "bg-threat-critical/15 text-threat-critical",
  },
  high: {
    bar: "bg-threat-high",
    badge: "bg-threat-high/15 text-threat-high",
  },
  medium: {
    bar: "bg-threat-medium",
    badge: "bg-threat-medium/15 text-threat-medium",
  },
  low: {
    bar: "bg-threat-low",
    badge: "bg-threat-low/15 text-threat-low",
  },
};

function toPercent(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  const scaled = numeric > 1 ? numeric : numeric * 100;
  return Math.max(0, Math.min(100, Math.round(scaled)));
}

function osMeta(osGuess) {
  const value = String(osGuess || "").toLowerCase();
  if (value.includes("linux")) return { emoji: "🐧", className: "text-os-linux" };
  if (value.includes("windows")) return { emoji: "🪟", className: "text-os-windows" };
  if (value.includes("mac")) return { emoji: "🍎", className: "text-os-macos" };
  return { emoji: "❓", className: "text-text-tertiary" };
}

function confidencePillClass(percent) {
  if (percent >= 80) return "bg-status-success/15 text-status-success";
  if (percent >= 50) return "bg-threat-high/15 text-threat-high";
  return "bg-threat-critical/15 text-threat-critical";
}

function formatTime(value) {
  if (!value) return "—";
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return String(value);
  return new Date(timestamp).toLocaleString();
}

function formatDuration(value) {
  if (value === undefined || value === null || value === "") return "—";
  if (typeof value === "number") {
    const mins = Math.floor(value / 60);
    const secs = Math.floor(value % 60);
    return `${mins}m ${secs}s`;
  }
  return String(value);
}

function formatAlertTime(value) {
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return "--:--:--";
  const date = new Date(timestamp);
  const part = (n) => String(n).padStart(2, "0");
  return `${part(date.getHours())}:${part(date.getMinutes())}:${part(date.getSeconds())}`;
}

export default function SessionReport({ sessionId }) {
  const { getResults, getPdfUrl } = useScan();
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(null);
  const [exporting, setExporting] = useState(false);
  const [alertsOpen, setAlertsOpen] = useState(true);

  async function loadReport() {
    if (!sessionId) { setError("No session ID"); return; }
    setLoading(true);
    setError(null);
    const result = await getResults(sessionId);
    if (result) setData(result);
    else setError("Failed to load session results");
    setLoading(false);
  }

  function handleExport() {
    if (!data || !sessionId || exporting) return;
    setExporting(true);
    window.open(getPdfUrl(sessionId), "_blank", "noopener,noreferrer");
    setTimeout(() => setExporting(false), 900);
  }

  const chartData = data
    ? (data.hosts || []).map((host) => {
        const open = (host.ports || []).filter((p) => p.status === "open").length;
        const closed = (host.ports || []).filter((p) => p.status === "closed").length;
        const filtered = (host.ports || []).filter((p) => p.status === "filtered" || p.status === "open|filtered").length;
        return {
          host: host.ip || "unknown",
          open,
          closed,
          filtered,
        };
      })
    : [];

  const hasChartData = chartData.some((item) => item.open > 0 || item.closed > 0 || item.filtered > 0);
  const isRunning = String(data?.status || "").toLowerCase().includes("run");
  const sessionValue = data?.session_id || sessionId || "—";
  const subnetValue = data?.subnet || "—";
  const timestampValue = data?.timestamp || data?.created_at || data?.started_at || "—";
  const durationValue = data?.duration || data?.elapsed || data?.scan_duration || "—";
  const alerts = Array.isArray(data?.alerts) ? data.alerts : [];

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="relative rounded-lg border border-border-default bg-bg-card p-5">
        <div className="absolute right-5 top-5 flex items-center gap-2">
          <button
            onClick={loadReport}
            disabled={loading || !sessionId}
            className="rounded-md border border-border-default bg-bg-elevated px-3 py-2 text-sm font-medium text-text-secondary transition-colors duration-150 hover:bg-bg-card-hover hover:text-text-primary disabled:opacity-50"
          >
            {loading ? "Loading…" : "Load Report"}
          </button>
          {data && (
            <button
              type="button"
              onClick={handleExport}
              disabled={exporting}
              className="inline-flex items-center gap-2 rounded-md border border-accent-border bg-accent-muted px-4 py-2 text-sm font-medium text-accent-primary transition-colors duration-150 hover:bg-accent-primary hover:text-text-primary disabled:opacity-60"
            >
              {exporting && (
                <span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />
              )}
              {exporting ? "Generating..." : "⬇ Export PDF"}
            </button>
          )}
        </div>

        <div className="flex items-center justify-between pr-52">
          <h2 className="text-xs uppercase tracking-widest text-text-tertiary">SESSION REPORT</h2>
          <span
            className={`rounded-sm px-2 py-0.5 text-xs font-medium ${
              isRunning ? "bg-accent-muted text-accent-primary" : "bg-status-success/15 text-status-success"
            }`}
          >
            {isRunning ? "Running" : "Complete"}
          </span>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <div>
            <p className="text-xs text-text-tertiary">Session ID</p>
            <p className="truncate font-mono text-xs text-text-primary" title={sessionValue}>{sessionValue}</p>
          </div>
          <div>
            <p className="text-xs text-text-tertiary">Subnet</p>
            <p className="font-mono text-sm text-text-primary">{subnetValue}</p>
          </div>
          <div>
            <p className="text-xs text-text-tertiary">Timestamp</p>
            <p className="text-sm text-text-primary">{formatTime(timestampValue)}</p>
          </div>
          <div>
            <p className="text-xs text-text-tertiary">Duration</p>
            <p className="text-sm font-bold text-text-primary">{formatDuration(durationValue)}</p>
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-border-danger bg-threat-critical/15 px-3 py-2 text-sm text-threat-critical">{error}</div>
      )}

      {!data && !loading && (
        <div className="rounded-lg border border-border-default bg-bg-card py-8 text-center text-sm text-text-tertiary">
          {sessionId
            ? "Click 'Load Report' to fetch session results"
            : "No active session — run a scan first"}
        </div>
      )}

      {data && (
        <>
          <div className="rounded-lg border border-border-default bg-bg-card p-4">
            <h3 className="mb-4 text-sm font-semibold text-text-primary">Port Status by Host</h3>
            {hasChartData ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" strokeDasharray="3 3" />
                  <XAxis dataKey="host" tick={{ fill: "#73819A", fontSize: 11 }} tickLine={false} axisLine={{ stroke: "rgba(255,255,255,0.06)" }} />
                  <YAxis tick={{ fill: "#73819A", fontSize: 11 }} tickLine={false} axisLine={{ stroke: "rgba(255,255,255,0.06)" }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      background: "#1A2740",
                      border: "1px solid #FFFFFF0F",
                      borderRadius: "8px",
                      boxShadow: "none",
                    }}
                    labelStyle={{ color: "#E6EDF7" }}
                    itemStyle={{ color: "#A9B6CC" }}
                  />
                  <Bar className="animate-bar-rise" dataKey="open" fill={CHART_COLORS.open} radius={[4, 4, 0, 0]} animationDuration={400} />
                  <Bar className="animate-bar-rise" dataKey="closed" fill={CHART_COLORS.closed} radius={[4, 4, 0, 0]} animationDuration={400} />
                  <Bar className="animate-bar-rise" dataKey="filtered" fill={CHART_COLORS.filtered} radius={[4, 4, 0, 0]} animationDuration={400} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="py-8 text-center text-sm text-text-tertiary">No port metrics available</div>
            )}
          </div>

          <div className="overflow-hidden rounded-lg border border-border-default bg-bg-card">
            <div className="grid grid-cols-[80px_1.2fr_1fr_1fr_110px_130px] bg-bg-elevated px-4 py-2.5 text-xs uppercase text-text-tertiary">
              <span>STATUS</span>
              <span>IP ADDRESS</span>
              <span>MAC</span>
              <span>OS</span>
              <span>OPEN PORTS</span>
              <span>CONFIDENCE</span>
            </div>
            <div>
              {(data.hosts || []).map((host, index) => {
                const openPorts = (host.ports || []).filter((p) => p.status === "open");
                const confidence = toPercent(host.confidence);
                const os = osMeta(host.os_guess);
                const isOnline = openPorts.length > 0;

                return (
                  <div
                    key={`${host.ip || "host"}-${index}`}
                    className="grid grid-cols-[80px_1.2fr_1fr_1fr_110px_130px] items-center border-b border-border-default/50 px-4 py-2.5 hover:bg-bg-card-hover"
                  >
                    <span className={`h-2 w-2 rounded-full ${isOnline ? "bg-status-success" : "bg-status-offline"}`} />
                    <span className="font-mono text-sm text-text-primary">{host.ip || "—"}</span>
                    <span className="font-mono text-xs text-text-tertiary">{host.mac || "—"}</span>
                    <span className="text-sm text-text-primary">
                      <span className="mr-1">{os.emoji}</span>
                      <span className={os.className}>{host.os_guess || "unknown"}</span>
                    </span>
                    <span className="font-mono text-sm text-text-primary">{openPorts.length}</span>
                    <span className={`inline-flex w-fit rounded-sm px-2 py-0.5 text-xs ${confidencePillClass(confidence)}`}>
                      {confidence}%
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="overflow-hidden rounded-lg border border-border-default bg-bg-card">
            <button
              type="button"
              onClick={() => setAlertsOpen((prev) => !prev)}
              className="flex w-full items-center justify-between px-4 py-3 text-left"
            >
              <span className="text-sm font-semibold text-text-primary">Security Alerts ({alerts.length})</span>
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                className={`h-4 w-4 text-text-tertiary transition-transform duration-150 ${alertsOpen ? "rotate-180" : "rotate-0"}`}
              >
                <path d="m6 9 6 6 6-6" />
              </svg>
            </button>

            {alertsOpen && (
              <div>
                {alerts.length === 0 ? (
                  <div className="px-4 py-3 text-sm text-text-tertiary">No alerts in this session.</div>
                ) : (
                  alerts.map((alert, index) => {
                    const severity = String(alert?.severity || "low").toLowerCase();
                    const style = SEVERITY_STYLE[severity] || SEVERITY_STYLE.low;
                    return (
                      <div
                        key={`${alert.timestamp || "alert"}-${index}`}
                        className="flex items-stretch gap-2 border-t border-border-default/50 px-4 py-2 hover:bg-bg-card-hover"
                      >
                        <span className={`w-1 rounded-sm ${style.bar}`} />
                        <div className="flex-1">
                          <p className="text-sm text-text-primary">{alert.message || alert.type || "Security alert"}</p>
                          <p className="text-xs text-text-tertiary">{alert.src_ip || "?"} → {alert.dst_ip || "?"}</p>
                        </div>
                        <div className="text-right">
                          <span className={`inline-flex rounded-sm px-2 py-0.5 text-xs ${style.badge}`}>
                            {severity.toUpperCase()}
                          </span>
                          <p className="mt-1 font-mono text-xs text-text-tertiary">{formatAlertTime(alert.timestamp)}</p>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            )}
            </div>
        </>
      )}
    </div>
  );
}
