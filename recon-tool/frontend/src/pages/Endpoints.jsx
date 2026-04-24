import React, { useMemo, useState } from "react";
import { useInventory } from "../hooks/useInventory";
import { useAgentRegistry } from "../hooks/useAgentRegistry";

function pct(n, d) {
  if (!d) return "0%";
  return `${Math.round((n / d) * 100)}%`;
}

function donutStyle(active, total) {
  const ratio = total ? active / total : 0;
  const deg = Math.round(ratio * 360);
  return {
    width: 140,
    height: 140,
    borderRadius: "50%",
    background: `conic-gradient(var(--color-status-success) ${deg}deg, var(--color-bg-elevated) ${deg}deg 360deg)`,
  };
}

function osMeta(osName) {
  const os = String(osName || "unknown").toLowerCase();
  if (os.includes("linux")) return { emoji: "??", className: "text-os-linux" };
  if (os.includes("windows")) return { emoji: "??", className: "text-os-windows" };
  if (os.includes("mac")) return { emoji: "??", className: "text-os-macos" };
  return { emoji: "?", className: "text-text-tertiary" };
}

function statusClass(status) {
  if (status === "connected") return { dot: "bg-status-online", text: "text-status-online", label: "Connected" };
  if (status === "error") return { dot: "bg-status-danger", text: "text-status-danger", label: "Error" };
  if (status === "connecting") return { dot: "bg-status-warning", text: "text-status-warning", label: "Connecting" };
  return { dot: "bg-status-offline", text: "text-status-offline", label: "Disconnected" };
}

export default function Endpoints() {
  const { items: inventory, status } = useInventory();
  const { items: registry } = useAgentRegistry();
  const [query, setQuery] = useState("");

  const merged = useMemo(() => {
    const map = new Map();
    registry.forEach((a) => map.set(a.agent_id, { registry: a, inventory: null }));
    inventory.forEach((i) => {
      const key = i.agent_id || i.hostname || (i.ips || [])[0] || "unknown";
      if (!map.has(key)) map.set(key, { registry: null, inventory: i });
      else map.get(key).inventory = i;
    });

    return Array.from(map.values()).map((entry) => {
      const reg = entry.registry || {};
      const inv = entry.inventory || {};
      const lastSeen = inv.last_seen ? new Date(inv.last_seen) : null;
      const online = lastSeen ? Date.now() - lastSeen.getTime() < 120000 : false;

      return {
        agent_id: reg.agent_id || inv.agent_id || inv.hostname || "unknown",
        hostname: reg.hostname || inv.hostname || "�",
        ip: reg.ip || (inv.ips || [])[0] || "�",
        os: reg.os_name || inv.os_name || "unknown",
        os_version: inv.os_version || "",
        last_seen: lastSeen,
        online,
      };
    });
  }, [inventory, registry]);

  const filtered = useMemo(() => {
    if (!query) return merged;
    const q = query.toLowerCase();
    return merged.filter((m) =>
      [m.agent_id, m.hostname, m.ip, m.os, m.os_version].join(" ").toLowerCase().includes(q)
    );
  }, [merged, query]);

  const active = merged.filter((m) => m.online).length;
  const disconnected = merged.length - active;
  const statusUi = statusClass(status);
  const registeredOnly = merged.filter((row) => row.hostname !== "�" && !row.last_seen).length;
  const inventoryOnly = merged.filter((row) => row.hostname === "�" && row.last_seen).length;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <p className="text-xs uppercase tracking-widest text-text-tertiary">Endpoints</p>
          <div className="mt-1 flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${statusUi.dot}`} />
            <span className={`text-sm ${statusUi.text}`}>{statusUi.label}</span>
          </div>
        </div>

        <div className="ml-auto w-full max-w-sm">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by agent, host, IP or OS"
            className="w-full rounded-md border border-border-default bg-bg-input px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:border-accent-border focus:outline-none"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="rounded-lg border border-border-default bg-bg-card p-4">
          <p className="text-xs uppercase tracking-widest text-text-tertiary">Live Presence</p>
          <div className="mt-4 flex items-center gap-5">
            <div className="relative" style={donutStyle(active, merged.length)}>
              <div className="absolute inset-4 flex items-center justify-center rounded-full border border-border-default bg-bg-card">
                <span className="font-mono text-sm text-text-primary">{pct(active, merged.length)}</span>
              </div>
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2 text-text-secondary">
                <span className="h-2 w-2 rounded-full bg-status-success" /> Active ({active})
              </div>
              <div className="flex items-center gap-2 text-text-tertiary">
                <span className="h-2 w-2 rounded-full bg-status-offline" /> Disconnected ({disconnected})
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-border-default bg-bg-card p-4">
          <div className="mb-3 text-xs uppercase tracking-widest text-text-tertiary">Registry Sync</div>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <div className="text-xs text-text-tertiary">Registered</div>
              <div className="text-lg font-semibold text-accent-primary">{registry.length}</div>
            </div>
            <div>
              <div className="text-xs text-text-tertiary">Inventory records</div>
              <div className="text-lg font-semibold text-text-primary">{inventory.length}</div>
            </div>
            <div>
              <div className="text-xs text-text-tertiary">Registry only</div>
              <div className="text-lg font-semibold text-threat-high">{registeredOnly}</div>
            </div>
            <div>
              <div className="text-xs text-text-tertiary">Inventory only</div>
              <div className="text-lg font-semibold text-os-windows">{inventoryOnly}</div>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-border-default bg-bg-card p-4">
          <div className="mb-3 text-xs uppercase tracking-widest text-text-tertiary">Coverage</div>
          <div className="h-24 rounded-md bg-bg-elevated p-2">
            <div className="flex h-full items-end gap-1">
              {[active, disconnected, registry.length, inventory.length, filtered.length].map((v, i) => {
                const peak = Math.max(1, active, disconnected, registry.length, inventory.length, filtered.length);
                const height = Math.max(8, Math.round((v / peak) * 100));
                return (
                  <div key={i} className="flex-1">
                    <div className="w-full rounded-sm bg-accent-muted" style={{ height: `${height}%` }} />
                  </div>
                );
              })}
            </div>
          </div>
          <div className="mt-2 text-xs text-text-tertiary">Active vs disconnected vs source totals</div>
        </div>
      </div>

      <div className="overflow-hidden rounded-lg border border-border-default bg-bg-card">
        <div className="border-b border-border-default bg-bg-elevated px-4 py-2 text-xs uppercase tracking-widest text-text-tertiary">
          Agents ({filtered.length})
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-border-default/60 text-xs text-text-tertiary">
                <th className="px-4 py-2 text-left">ID</th>
                <th className="px-4 py-2 text-left">Name</th>
                <th className="px-4 py-2 text-left">IP address</th>
                <th className="px-4 py-2 text-left">Operating system</th>
                <th className="px-4 py-2 text-left">Last seen</th>
                <th className="px-4 py-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={row.agent_id} className="border-b border-border-default/50 hover:bg-bg-card-hover">
                  <td className="px-4 py-2 font-mono text-accent-primary">{row.agent_id}</td>
                  <td className="px-4 py-2 text-text-primary">{row.hostname}</td>
                  <td className="px-4 py-2 font-mono text-text-secondary">{row.ip}</td>
                  <td className="px-4 py-2 text-text-secondary">
                    <span className="mr-1">{osMeta(row.os).emoji}</span>
                    <span className={osMeta(row.os).className}>{row.os}</span>
                    {row.os_version ? ` ${row.os_version}` : ""}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-text-tertiary">
                    {row.last_seen ? row.last_seen.toLocaleTimeString() : "�"}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`inline-flex items-center gap-2 rounded-sm px-2 py-0.5 text-xs ${
                        row.online
                          ? "bg-status-success/15 text-status-success"
                          : "bg-bg-elevated text-text-tertiary"
                      }`}
                    >
                      <span className={`h-2 w-2 rounded-full ${row.online ? "bg-status-success" : "bg-status-offline"}`} />
                      {row.online ? "active" : "disconnected"}
                    </span>
                  </td>
                </tr>
              ))}

              {filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-sm text-text-tertiary">
                    No endpoints match the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
