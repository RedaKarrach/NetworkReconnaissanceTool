/**
 * components/SessionReport.jsx
 * ----------------------------
 * Summary of a completed scan session with PDF download button.
 */
import React, { useState } from "react";
import { useScan } from "../hooks/useScan";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell
} from "recharts";

const STATUS_COLOR = { open: "#22c55e", closed: "#ef4444", filtered: "#eab308" };

export default function SessionReport({ sessionId }) {
  const { getResults, getPdfUrl } = useScan();
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(null);

  async function loadReport() {
    if (!sessionId) { setError("No session ID"); return; }
    setLoading(true);
    setError(null);
    const result = await getResults(sessionId);
    if (result) setData(result);
    else setError("Failed to load session results");
    setLoading(false);
  }

  // Build chart data
  const portStats = data ? (() => {
    const counts = { open: 0, closed: 0, filtered: 0 };
    data.hosts?.forEach((h) => h.ports?.forEach((p) => {
      counts[p.status] = (counts[p.status] || 0) + 1;
    }));
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  })() : [];

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700 p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-white font-semibold text-sm tracking-wide uppercase">
          Session Report
        </h2>
        <div className="flex gap-2">
          <button
            onClick={loadReport}
            disabled={loading || !sessionId}
            className="px-3 py-1.5 bg-blue-700 hover:bg-blue-600 disabled:opacity-50
                       text-white text-sm rounded transition-colors"
          >
            {loading ? "Loading…" : "Load Report"}
          </button>
          {data && (
            <a
              href={getPdfUrl(sessionId)}
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 bg-green-700 hover:bg-green-600
                         text-white text-sm rounded transition-colors"
            >
              ⬇ Export PDF
            </a>
          )}
        </div>
      </div>

      {error && (
        <div className="text-red-400 text-sm bg-red-900/30 rounded px-3 py-2">{error}</div>
      )}

      {!data && !loading && (
        <div className="text-gray-600 text-sm text-center py-8">
          {sessionId
            ? "Click 'Load Report' to fetch session results"
            : "No active session — run a scan first"}
        </div>
      )}

      {data && (
        <>
          {/* Meta row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "Session",   value: data.session_id?.slice(0, 8) + "…" },
              { label: "Subnet",    value: data.subnet || "—" },
              { label: "Status",    value: data.status },
              { label: "Hosts",     value: data.hosts?.length ?? 0 },
            ].map((s) => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-3">
                <div className="text-gray-500 text-xs">{s.label}</div>
                <div className="text-white font-mono text-sm mt-0.5">{s.value}</div>
              </div>
            ))}
          </div>

          {/* Port status chart */}
          {portStats.some((s) => s.value > 0) && (
            <div className="bg-gray-800 rounded-lg p-3">
              <div className="text-gray-400 text-xs uppercase mb-2">Port Status Summary</div>
              <ResponsiveContainer width="100%" height={120}>
                <BarChart data={portStats} layout="vertical">
                  <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 10 }} />
                  <YAxis dataKey="name" type="category" tick={{ fill: "#9ca3af", fontSize: 11 }} width={60} />
                  <Tooltip
                    contentStyle={{ background: "#1f2937", border: "1px solid #374151", borderRadius: 6 }}
                    labelStyle={{ color: "#fff" }}
                    itemStyle={{ color: "#9ca3af" }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {portStats.map((entry) => (
                      <Cell key={entry.name} fill={STATUS_COLOR[entry.name] || "#6b7280"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Host table */}
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-700 text-gray-400 text-xs uppercase">
              Discovered Hosts
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 text-xs border-b border-gray-700">
                  <th className="px-3 py-2 text-left">IP</th>
                  <th className="px-3 py-2 text-left">MAC</th>
                  <th className="px-3 py-2 text-left">OS Guess</th>
                  <th className="px-3 py-2 text-left">Confidence</th>
                  <th className="px-3 py-2 text-left">Open Ports</th>
                </tr>
              </thead>
              <tbody>
                {data.hosts?.map((h, i) => (
                  <tr key={i} className="border-b border-gray-800 hover:bg-gray-700/30">
                    <td className="px-3 py-2 font-mono text-cyan-400">{h.ip}</td>
                    <td className="px-3 py-2 font-mono text-gray-400 text-xs">{h.mac || "—"}</td>
                    <td className="px-3 py-2 text-gray-300">{h.os_guess || "unknown"}</td>
                    <td className="px-3 py-2 text-gray-400">
                      {h.confidence ? `${Math.round(h.confidence * 100)}%` : "—"}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {h.ports?.filter((p) => p.status === "open").slice(0, 8).map((p) => (
                          <span key={p.port}
                            className="bg-green-900 text-green-300 text-[10px] font-mono px-1.5 rounded">
                            {p.port}
                          </span>
                        ))}
                        {(h.ports?.filter((p) => p.status === "open").length || 0) > 8 && (
                          <span className="text-gray-600 text-[10px]">
                            +{h.ports.filter((p) => p.status === "open").length - 8} more
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Alerts */}
          {data.alerts?.length > 0 && (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="px-3 py-2 border-b border-gray-700 text-red-400 text-xs uppercase flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                {data.alerts.length} Alerts
              </div>
              {data.alerts.map((a, i) => (
                <div key={i} className="px-3 py-2 border-b border-gray-800 text-xs flex gap-3">
                  <span className={`font-medium ${
                    a.severity === "critical" ? "text-red-400" :
                    a.severity === "high"     ? "text-orange-400" :
                    "text-yellow-400"
                  }`}>
                    [{a.severity?.toUpperCase()}]
                  </span>
                  <span className="text-gray-400">{a.type}</span>
                  <span className="text-gray-500">{a.src_ip} → {a.dst_ip}</span>
                  <span className="text-gray-400 flex-1">{a.message}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
