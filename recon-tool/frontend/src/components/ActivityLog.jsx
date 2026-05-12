import React, { useEffect, useMemo, useState } from "react";
import { API_BASE } from "../lib/runtimeConfig";

const ACTION_OPTIONS = [
  { value: "all", label: "All actions" },
  { value: "scan_started", label: "Scan started" },
  { value: "scan_completed", label: "Scan completed" },
  { value: "fingerprint_run", label: "Fingerprint run" },
  { value: "attack_initiated", label: "Attack initiated" },
  { value: "alert_generated", label: "Alert generated" },
];

const STATUS_OPTIONS = [
  { value: "all", label: "All statuses" },
  { value: "success", label: "Success" },
  { value: "failure", label: "Failure" },
];

const RANGE_OPTIONS = [
  { value: 24, label: "Last 24h" },
  { value: 168, label: "Last 7d" },
  { value: 720, label: "Last 30d" },
];

const STATUS_STYLE = {
  success: "bg-status-success/15 text-status-success border-status-success/40",
  failure: "bg-threat-critical/15 text-threat-critical border-threat-critical/40",
};

function formatAction(value) {
  const map = {
    scan_started: "Scan started",
    scan_completed: "Scan completed",
    fingerprint_run: "Fingerprint run",
    attack_initiated: "Attack initiated",
    alert_generated: "Alert generated",
  };
  return map[value] || value || "unknown";
}

function formatDuration(value) {
  const ms = Number(value);
  if (!Number.isFinite(ms) || ms <= 0) return "--";
  if (ms < 1000) return `${ms} ms`;
  const secs = ms / 1000;
  if (secs < 60) return `${secs.toFixed(2)} s`;
  const mins = Math.floor(secs / 60);
  const rem = Math.round(secs % 60);
  return `${mins}m ${rem}s`;
}

function parseDetail(detail) {
  if (!detail) return {};
  if (typeof detail === "object") return detail;
  try {
    return JSON.parse(detail);
  } catch {
    return { raw: String(detail) };
  }
}

export default function ActivityLog() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(new Set());
  const [actionFilter, setActionFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [rangeHours, setRangeHours] = useState(24);

  useEffect(() => {
    let active = true;
    const params = new URLSearchParams();
    params.set("limit", "200");
    params.set("offset", "0");
    params.set("hours", String(rangeHours));
    if (actionFilter !== "all") params.set("action", actionFilter);
    if (statusFilter !== "all") params.set("status", statusFilter);

    setLoading(true);
    setError("");

    fetch(`${API_BASE}/api/audit-logs/?${params}`)
      .then((res) => (res.ok ? res.json() : Promise.reject(res)))
      .then((data) => {
        if (!active) return;
        const results = Array.isArray(data?.results) ? data.results : [];
        setItems(results);
      })
      .catch(() => {
        if (active) setError("Failed to load audit logs.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [actionFilter, statusFilter, rangeHours]);

  const rows = useMemo(() => {
    const filtered = items.filter((item) => {
      if (actionFilter !== "all" && item.action !== actionFilter) return false;
      if (statusFilter !== "all" && item.status !== statusFilter) return false;
      return true;
    });
    return filtered.map((item, idx) => ({
      ...item,
      detail: parseDetail(item.detail),
      _rowId: `${item.initiated_at || "unknown"}-${item.action || "action"}-${idx}`,
    }));
  }, [items, actionFilter, statusFilter]);

  const summary = useMemo(() => {
    const scanActions = new Set(["scan_started", "scan_completed", "fingerprint_run"]);
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    const scansToday = items.filter((item) => {
      if (item.action !== "scan_started") return false;
      const ts = Date.parse(item.initiated_at);
      return Number.isFinite(ts) && ts >= today.getTime();
    }).length;

    const completed = items.filter((item) => scanActions.has(item.action) && item.action !== "scan_started");
    const completedCount = completed.length;
    const successCount = completed.filter((item) => item.status === "success").length;
    const successRate = completedCount ? Math.round((successCount / completedCount) * 100) : 0;

    const avgDuration = completedCount
      ? Math.round(completed.reduce((sum, item) => sum + (Number(item.duration_ms) || 0), 0) / completedCount)
      : 0;

    return {
      scansToday,
      successRate,
      avgDuration,
    };
  }, [items]);

  function toggleExpanded(rowId) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(rowId)) next.delete(rowId);
      else next.add(rowId);
      return next;
    });
  }

  return (
    <div className="flex h-full flex-col gap-4 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <p className="text-xs uppercase tracking-widest text-text-tertiary">Activity Log</p>
          <p className="text-sm text-text-secondary">Audit trail for scans, attacks, and alerts</p>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="rounded-md border border-border-default bg-bg-input/70 px-3 py-2 text-xs text-text-primary"
          >
            {ACTION_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-md border border-border-default bg-bg-input/70 px-3 py-2 text-xs text-text-primary"
          >
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <select
            value={rangeHours}
            onChange={(e) => setRangeHours(Number(e.target.value))}
            className="rounded-md border border-border-default bg-bg-input/70 px-3 py-2 text-xs text-text-primary"
          >
            {RANGE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <div className="card-premium p-4">
          <p className="text-xs uppercase tracking-widest text-text-tertiary">Total scans today</p>
          <p className="mt-2 font-mono text-2xl text-accent-primary">{summary.scansToday}</p>
        </div>
        <div className="card-premium p-4">
          <p className="text-xs uppercase tracking-widest text-text-tertiary">Success rate</p>
          <p className="mt-2 font-mono text-2xl text-status-success">{summary.successRate}%</p>
        </div>
        <div className="card-premium p-4">
          <p className="text-xs uppercase tracking-widest text-text-tertiary">Avg scan duration</p>
          <p className="mt-2 font-mono text-2xl text-text-primary">{formatDuration(summary.avgDuration)}</p>
        </div>
      </div>

      <div className="panel-premium flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="border-b border-border-default/60 px-4 py-2 text-xs uppercase tracking-widest text-text-tertiary">
          Audit entries ({rows.length})
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {loading ? (
            <div className="px-4 py-6 text-sm text-text-tertiary">Loading audit logs...</div>
          ) : error ? (
            <div className="px-4 py-6 text-sm text-threat-critical">{error}</div>
          ) : rows.length === 0 ? (
            <div className="px-4 py-6 text-sm text-text-tertiary">No audit logs for the selected range.</div>
          ) : (
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-border-default/60 text-xs text-text-tertiary">
                  <th className="px-4 py-2 text-left">Timestamp</th>
                  <th className="px-4 py-2 text-left">Action</th>
                  <th className="px-4 py-2 text-left">User</th>
                  <th className="px-4 py-2 text-left">Status</th>
                  <th className="px-4 py-2 text-left">Duration</th>
                  <th className="px-4 py-2 text-left">Details</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const ts = row.initiated_at ? new Date(row.initiated_at).toLocaleString() : "--";
                  const detailPreview = row.detail?.scan_type || row.detail?.attack_type || row.detail?.alert_type || "--";
                  const statusClass = STATUS_STYLE[row.status] || "bg-bg-elevated text-text-tertiary border-border-default";
                  const isExpanded = expanded.has(row._rowId);
                  return (
                    <React.Fragment key={row._rowId}>
                      <tr
                        className="endpoint-row border-b border-border-default/40 hover:bg-bg-card-hover cursor-pointer"
                        onClick={() => toggleExpanded(row._rowId)}
                      >
                        <td className="px-4 py-2 font-mono text-xs text-text-tertiary">{ts}</td>
                        <td className="px-4 py-2 text-text-primary">{formatAction(row.action)}</td>
                        <td className="px-4 py-2 text-text-secondary">{row.initiated_by || "system"}</td>
                        <td className="px-4 py-2">
                          <span className={`rounded-full border px-2 py-0.5 text-xs uppercase ${statusClass}`}>
                            {row.status || "unknown"}
                          </span>
                        </td>
                        <td className="px-4 py-2 font-mono text-xs text-text-tertiary">{formatDuration(row.duration_ms)}</td>
                        <td className="px-4 py-2 text-xs text-text-tertiary">{detailPreview}</td>
                      </tr>
                      {isExpanded && (
                        <tr className="border-b border-border-default/40 bg-bg-elevated/40">
                          <td colSpan={6} className="px-4 py-3">
                            <div className="rounded-md border border-border-default/60 bg-bg-card/60 p-3">
                              <div className="text-xs uppercase tracking-widest text-text-tertiary">Action detail</div>
                              <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs text-text-secondary">
                                {JSON.stringify(row.detail || {}, null, 2)}
                              </pre>
                              {row.error_message && (
                                <div className="mt-2 text-xs text-threat-critical">Error: {row.error_message}</div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
