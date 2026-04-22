import React, { useMemo, useState } from "react";
import { useInventory } from "../hooks/useInventory";
import { useAgentRegistry } from "../hooks/useAgentRegistry";

function fmtBytesGb(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${Number(value).toFixed(1)} GB`;
}

function fmtUptime(sec) {
  if (!sec && sec !== 0) return "—";
  const s = Math.max(0, Number(sec));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

function statusClass(status) {
  if (status === "connected") return { dot: "bg-status-online", text: "text-status-online", label: "Connected" };
  if (status === "error") return { dot: "bg-status-danger", text: "text-status-danger", label: "Error" };
  if (status === "connecting") return { dot: "bg-status-warning", text: "text-status-warning", label: "Connecting" };
  return { dot: "bg-status-offline", text: "text-status-offline", label: "Disconnected" };
}

export default function Inventory() {
  const { items, status, error, refresh } = useInventory();
  const { items: agents, error: agentError, addAgent, deleteAgent } = useAgentRegistry();
  const [query, setQuery] = useState("");
  const [form, setForm] = useState({ agent_id: "", hostname: "", ip: "", os_name: "" });
  const [saving, setSaving] = useState(false);
  const statusUi = statusClass(status);

  const filtered = useMemo(() => {
    if (!query) return items;
    const q = query.toLowerCase();
    return items.filter((i) =>
      [i.agent_id, i.hostname, i.os_name, i.os_version, (i.ips || []).join(" ")]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(q)
    );
  }, [items, query]);

  const inventoryByAgent = useMemo(() => {
    const map = new Map();
    items.forEach((i) => {
      if (i.agent_id) map.set(i.agent_id, i);
      if (i.hostname) map.set(i.hostname, i);
      (i.ips || []).forEach((ip) => map.set(ip, i));
    });
    return map;
  }, [items]);

  async function handleAddAgent(e) {
    e.preventDefault();
    if (!form.agent_id) return;
    setSaving(true);
    const ok = await addAgent({
      agent_id: form.agent_id.trim(),
      hostname: form.hostname.trim(),
      ip: form.ip.trim(),
      os_name: form.os_name.trim(),
    });
    setSaving(false);
    if (ok) setForm({ agent_id: "", hostname: "", ip: "", os_name: "" });
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <p className="text-xs uppercase tracking-widest text-text-tertiary">Host Inventory</p>
          <div className="mt-1 flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${statusUi.dot}`} />
            <span className={`text-sm ${statusUi.text}`}>{statusUi.label}</span>
          </div>
        </div>

        <div className="ml-auto flex items-center gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="filter by IP, host, OS..."
            className="w-64 rounded-md border border-border-default bg-bg-input px-3 py-1.5 text-sm text-text-primary placeholder:text-text-tertiary focus:border-accent-border focus:outline-none"
          />
          <button
            onClick={refresh}
            className="rounded-md border border-border-default bg-bg-elevated px-3 py-1.5 text-sm text-text-secondary transition-colors duration-150 hover:bg-bg-card-hover hover:text-text-primary"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-border-danger bg-threat-critical/15 px-4 py-3 text-sm text-threat-critical">
          {error}
        </div>
      )}

      {agentError && (
        <div className="rounded-md border border-border-danger bg-threat-critical/15 px-4 py-3 text-sm text-threat-critical">
          {agentError}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-lg border border-border-default bg-bg-card p-4">
          <div className="mb-3 text-xs uppercase tracking-widest text-text-tertiary">Add Agent</div>
          <form className="grid grid-cols-1 md:grid-cols-2 gap-3" onSubmit={handleAddAgent}>
            <input
              value={form.agent_id}
              onChange={(e) => setForm((f) => ({ ...f, agent_id: e.target.value }))}
              placeholder="Agent ID (required)"
              className="rounded-md border border-border-default bg-bg-input px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:border-accent-border focus:outline-none"
            />
            <input
              value={form.hostname}
              onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value }))}
              placeholder="Hostname"
              className="rounded-md border border-border-default bg-bg-input px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:border-accent-border focus:outline-none"
            />
            <input
              value={form.ip}
              onChange={(e) => setForm((f) => ({ ...f, ip: e.target.value }))}
              placeholder="IP address"
              className="rounded-md border border-border-default bg-bg-input px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:border-accent-border focus:outline-none"
            />
            <input
              value={form.os_name}
              onChange={(e) => setForm((f) => ({ ...f, os_name: e.target.value }))}
              placeholder="OS (e.g., Windows 10)"
              className="rounded-md border border-border-default bg-bg-input px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:border-accent-border focus:outline-none"
            />
            <div className="md:col-span-2 flex items-center gap-2">
              <button
                type="submit"
                disabled={saving || !form.agent_id.trim()}
                className="rounded-md bg-gradient-to-r from-accent-primary to-accent-hover px-4 py-2 text-sm font-medium text-text-primary transition-all duration-150 active:scale-[0.98] disabled:opacity-50"
              >
                {saving ? "Saving..." : "Add Agent"}
              </button>
              <div className="text-xs text-text-tertiary">
                This only registers the agent for visualization. The VM must run inventory_agent.py.
              </div>
            </div>
          </form>
        </div>

        <div className="rounded-lg border border-border-default bg-bg-card p-4">
          <div className="mb-3 text-xs uppercase tracking-widest text-text-tertiary">Registered Agents</div>
          {agents.length === 0 ? (
            <div className="text-sm text-text-tertiary">No agents registered yet.</div>
          ) : (
            <div className="space-y-2">
              {agents.map((a) => {
                const live = inventoryByAgent.get(a.agent_id) || inventoryByAgent.get(a.hostname) || inventoryByAgent.get(a.ip);
                const lastSeen = live?.last_seen ? new Date(live.last_seen) : null;
                const online = lastSeen ? Date.now() - lastSeen.getTime() < 120000 : false;
                return (
                  <div key={a.agent_id} className="flex items-center gap-3 rounded-md border border-border-default bg-bg-elevated px-3 py-2">
                    <span className={`h-2 w-2 rounded-full ${online ? "bg-status-success" : "bg-status-offline"}`} />
                    <div className="flex-1 min-w-0">
                      <div className="truncate text-sm text-text-primary">{a.agent_id}</div>
                      <div className="truncate text-xs text-text-tertiary">
                        {a.os_name || "unknown"} · {a.ip || "no ip"}
                      </div>
                    </div>
                    <div className="font-mono text-xs text-text-tertiary">
                      {lastSeen ? lastSeen.toLocaleTimeString() : "—"}
                    </div>
                    <button
                      onClick={() => deleteAgent({ agent_id: a.agent_id })}
                      className="rounded-sm border border-border-danger px-2 py-1 text-xs text-threat-critical transition-colors duration-150 hover:bg-threat-critical/10"
                    >
                      Delete
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="py-10 text-center text-sm text-text-tertiary">
          No inventory yet — start the inventory agent on your VMs.
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border-default bg-bg-card">
          <div className="border-b border-border-default bg-bg-elevated px-4 py-2 text-xs uppercase tracking-widest text-text-tertiary">
            {filtered.length} hosts
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-border-default/60 text-xs text-text-tertiary">
                  <th className="px-4 py-2 text-left">Agent</th>
                  <th className="px-4 py-2 text-left">Host</th>
                  <th className="px-4 py-2 text-left">OS</th>
                  <th className="px-4 py-2 text-left">IPs</th>
                  <th className="px-4 py-2 text-left">MACs</th>
                  <th className="px-4 py-2 text-left">CPU</th>
                  <th className="px-4 py-2 text-left">RAM</th>
                  <th className="px-4 py-2 text-left">Disk</th>
                  <th className="px-4 py-2 text-left">Uptime</th>
                  <th className="px-4 py-2 text-left">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => (
                  <tr key={item.agent_id} className="border-b border-border-default/50 hover:bg-bg-card-hover">
                    <td className="px-4 py-2 font-mono text-accent-primary">{item.agent_id}</td>
                    <td className="px-4 py-2 text-text-primary">{item.hostname || "—"}</td>
                    <td className="px-4 py-2 text-text-secondary">
                      {(item.os_name || "unknown") + (item.os_version ? ` ${item.os_version}` : "")}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {(item.ips || []).slice(0, 3).join(", ") || "—"}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {(item.macs || []).slice(0, 2).join(", ") || "—"}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {item.cpu_model ? `${item.cpu_model} (${item.cpu_cores || "?"}c)` : "—"}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {item.ram_mb ? `${item.ram_mb} MB` : "—"}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {fmtBytesGb(item.disk_free_gb)} / {fmtBytesGb(item.disk_total_gb)}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">{fmtUptime(item.uptime_sec)}</td>
                    <td className="px-4 py-2 font-mono text-text-tertiary">
                      {item.last_seen ? new Date(item.last_seen).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
