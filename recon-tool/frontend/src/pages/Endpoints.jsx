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
    background: `conic-gradient(#14b8a6 ${deg}deg, #1f2937 ${deg}deg 360deg)`
  };
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
        hostname: reg.hostname || inv.hostname || "—",
        ip: reg.ip || (inv.ips || [])[0] || "—",
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

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="text-gray-500 text-xs uppercase tracking-wide">Endpoints</div>
        <div className="flex items-center gap-1.5 text-xs text-gray-500">
          <span className={`w-2 h-2 rounded-full ${status === "connected" ? "bg-green-500" : status === "error" ? "bg-red-500" : "bg-gray-500"}`} />
          {status}
        </div>
        <div className="ml-auto">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search agents"
            className="bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 w-64"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4 flex items-center gap-5">
          <div style={donutStyle(active, merged.length)} />
          <div className="space-y-2 text-sm">
            <div className="flex items-center gap-2 text-gray-300">
              <span className="w-2 h-2 rounded-full bg-teal-400" /> Active ({active})
            </div>
            <div className="flex items-center gap-2 text-gray-500">
              <span className="w-2 h-2 rounded-full bg-gray-500" /> Disconnected ({disconnected})
            </div>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <div className="text-gray-400 text-xs uppercase mb-3">Details</div>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <div className="text-gray-500 text-xs">Active</div>
              <div className="text-teal-400 text-lg font-semibold">{active}</div>
            </div>
            <div>
              <div className="text-gray-500 text-xs">Disconnected</div>
              <div className="text-gray-300 text-lg font-semibold">{disconnected}</div>
            </div>
            <div>
              <div className="text-gray-500 text-xs">Agents coverage</div>
              <div className="text-gray-200 text-lg font-semibold">{pct(active, merged.length)}</div>
            </div>
            <div>
              <div className="text-gray-500 text-xs">Total</div>
              <div className="text-gray-200 text-lg font-semibold">{merged.length}</div>
            </div>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <div className="text-gray-400 text-xs uppercase mb-3">Evolution (24h)</div>
          <div className="h-24 flex items-end gap-2">
            {[3, 4, 2, 5, 6, 4, 7, 6, 8, 7].map((v, i) => (
              <div key={i} className="flex-1 bg-teal-500/30" style={{ height: `${v * 10}%` }} />
            ))}
          </div>
          <div className="text-gray-500 text-xs mt-2">Active agents in last 24 hours</div>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
        <div className="px-4 py-2 border-b border-gray-700 text-xs uppercase text-gray-500">
          Agents ({filtered.length})
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs border-b border-gray-800">
                <th className="px-4 py-2 text-left">ID</th>
                <th className="px-4 py-2 text-left">Name</th>
                <th className="px-4 py-2 text-left">IP address</th>
                <th className="px-4 py-2 text-left">Operating system</th>
                <th className="px-4 py-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={row.agent_id} className="border-b border-gray-800 hover:bg-gray-800/30">
                  <td className="px-4 py-2 font-mono text-cyan-400">{row.agent_id}</td>
                  <td className="px-4 py-2 text-gray-300">{row.hostname}</td>
                  <td className="px-4 py-2 text-gray-300">{row.ip}</td>
                  <td className="px-4 py-2 text-gray-300">{row.os} {row.os_version}</td>
                  <td className="px-4 py-2">
                    <span className={`inline-flex items-center gap-2 text-xs ${row.online ? "text-teal-400" : "text-gray-500"}`}>
                      <span className={`w-2 h-2 rounded-full ${row.online ? "bg-teal-400" : "bg-gray-500"}`} />
                      {row.online ? "active" : "disconnected"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
