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

export default function Inventory() {
  const { items, status, error, refresh } = useInventory();
  const { items: agents, error: agentError, addAgent, deleteAgent } = useAgentRegistry();
  const [query, setQuery] = useState("");
  const [form, setForm] = useState({ agent_id: "", hostname: "", ip: "", os_name: "" });
  const [saving, setSaving] = useState(false);

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
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="text-gray-500 text-xs uppercase tracking-wide">Host Inventory</div>
        <div className="flex items-center gap-1.5 text-xs text-gray-500">
          <span className={`w-2 h-2 rounded-full ${status === "connected" ? "bg-green-500" : status === "error" ? "bg-red-500" : "bg-gray-500"}`} />
          {status}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="filter by IP, host, OS..."
            className="bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 w-64"
          />
          <button
            onClick={refresh}
            className="px-3 py-1.5 text-sm rounded bg-gray-800 border border-gray-700 text-gray-300 hover:bg-gray-700"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/40 border border-red-700 text-red-300 rounded px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {agentError && (
        <div className="bg-red-900/40 border border-red-700 text-red-300 rounded px-4 py-3 text-sm">
          {agentError}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <div className="text-gray-400 text-xs uppercase mb-3">Add Agent</div>
          <form className="grid grid-cols-1 md:grid-cols-2 gap-3" onSubmit={handleAddAgent}>
            <input
              value={form.agent_id}
              onChange={(e) => setForm((f) => ({ ...f, agent_id: e.target.value }))}
              placeholder="Agent ID (required)"
              className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300"
            />
            <input
              value={form.hostname}
              onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value }))}
              placeholder="Hostname"
              className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300"
            />
            <input
              value={form.ip}
              onChange={(e) => setForm((f) => ({ ...f, ip: e.target.value }))}
              placeholder="IP address"
              className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300"
            />
            <input
              value={form.os_name}
              onChange={(e) => setForm((f) => ({ ...f, os_name: e.target.value }))}
              placeholder="OS (e.g., Windows 10)"
              className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300"
            />
            <div className="md:col-span-2 flex items-center gap-2">
              <button
                type="submit"
                disabled={saving || !form.agent_id.trim()}
                className="px-4 py-2 text-sm rounded bg-cyan-700 text-white disabled:opacity-50"
              >
                {saving ? "Saving..." : "Add Agent"}
              </button>
              <div className="text-xs text-gray-500">
                This only registers the agent for visualization. The VM must run inventory_agent.py.
              </div>
            </div>
          </form>
        </div>

        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <div className="text-gray-400 text-xs uppercase mb-3">Registered Agents</div>
          {agents.length === 0 ? (
            <div className="text-gray-600 text-sm">No agents registered yet.</div>
          ) : (
            <div className="space-y-2">
              {agents.map((a) => {
                const live = inventoryByAgent.get(a.agent_id) || inventoryByAgent.get(a.hostname) || inventoryByAgent.get(a.ip);
                const lastSeen = live?.last_seen ? new Date(live.last_seen) : null;
                const online = lastSeen ? Date.now() - lastSeen.getTime() < 120000 : false;
                return (
                  <div key={a.agent_id} className="flex items-center gap-3 bg-gray-800/60 border border-gray-700 rounded px-3 py-2">
                    <span className={`w-2 h-2 rounded-full ${online ? "bg-green-500" : "bg-gray-500"}`} />
                    <div className="flex-1 min-w-0">
                      <div className="text-gray-200 text-sm truncate">{a.agent_id}</div>
                      <div className="text-gray-500 text-xs truncate">
                        {a.os_name || "unknown"} · {a.ip || "no ip"}
                      </div>
                    </div>
                    <div className="text-gray-500 text-xs font-mono">
                      {lastSeen ? lastSeen.toLocaleTimeString() : "—"}
                    </div>
                    <button
                      onClick={() => deleteAgent({ agent_id: a.agent_id })}
                      className="text-xs text-red-400 border border-red-800 rounded px-2 py-1 hover:text-red-300"
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
        <div className="text-gray-600 text-sm text-center py-10">
          No inventory yet — start the inventory agent on your VMs.
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
          <div className="px-4 py-2 border-b border-gray-700 text-xs uppercase text-gray-500">
            {filtered.length} hosts
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-gray-500 text-xs border-b border-gray-800">
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
                  <tr key={item.agent_id} className="border-b border-gray-800 hover:bg-gray-800/30">
                    <td className="px-4 py-2 font-mono text-cyan-400">{item.agent_id}</td>
                    <td className="px-4 py-2 text-gray-300">{item.hostname || "—"}</td>
                    <td className="px-4 py-2 text-gray-300">
                      {(item.os_name || "unknown") + (item.os_version ? ` ${item.os_version}` : "")}
                    </td>
                    <td className="px-4 py-2 text-gray-400">
                      {(item.ips || []).slice(0, 3).join(", ") || "—"}
                    </td>
                    <td className="px-4 py-2 text-gray-400">
                      {(item.macs || []).slice(0, 2).join(", ") || "—"}
                    </td>
                    <td className="px-4 py-2 text-gray-400">
                      {item.cpu_model ? `${item.cpu_model} (${item.cpu_cores || "?"}c)` : "—"}
                    </td>
                    <td className="px-4 py-2 text-gray-400">
                      {item.ram_mb ? `${item.ram_mb} MB` : "—"}
                    </td>
                    <td className="px-4 py-2 text-gray-400">
                      {fmtBytesGb(item.disk_free_gb)} / {fmtBytesGb(item.disk_total_gb)}
                    </td>
                    <td className="px-4 py-2 text-gray-400">{fmtUptime(item.uptime_sec)}</td>
                    <td className="px-4 py-2 text-gray-500 font-mono">
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
