/**
 * components/PortMatrix.jsx
 * -------------------------
 * Grid of scanned ports per host.
 * Green = open, Red = closed, Yellow = filtered, Gray = open|filtered
 * Hover shows banner if available.
 */
import React, { useState } from "react";

const STATUS_STYLE = {
  open:           "bg-green-500 border-green-400 text-white",
  closed:         "bg-red-900  border-red-700   text-red-300",
  filtered:       "bg-yellow-800 border-yellow-600 text-yellow-200",
  "open|filtered":"bg-gray-600 border-gray-500  text-gray-300",
};

const STATUS_DOT = {
  open:           "bg-green-400",
  closed:         "bg-red-500",
  filtered:       "bg-yellow-400",
  "open|filtered":"bg-gray-400",
};

function PortCell({ result }) {
  const [showTip, setShowTip] = useState(false);
  const style = STATUS_STYLE[result.status] || STATUS_STYLE.filtered;

  return (
    <div
      className={`relative border rounded px-1.5 py-1 text-center text-xs font-mono cursor-default select-none ${style}`}
      style={{ minWidth: 52 }}
      onMouseEnter={() => setShowTip(true)}
      onMouseLeave={() => setShowTip(false)}
    >
      <div className="font-bold">{result.port}</div>
      <div className="text-[9px] opacity-75 uppercase">{result.protocol}</div>

      {showTip && (
        <div className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2 w-64
                        bg-gray-900 border border-gray-600 rounded shadow-xl p-2 text-left">
          <div className="text-green-400 font-semibold mb-1">
            Port {result.port}/{result.protocol.toUpperCase()}
          </div>
          <div className="flex gap-2 mb-1">
            <span className={`w-2 h-2 mt-0.5 rounded-full flex-shrink-0 ${STATUS_DOT[result.status]}`} />
            <span className="text-gray-300 text-xs capitalize">{result.status}</span>
          </div>
          {result.banner && (
            <div className="mt-1 pt-1 border-t border-gray-700">
              <div className="text-gray-500 text-[9px] uppercase mb-0.5">Banner</div>
              <div className="text-cyan-300 text-[10px] font-mono break-all">
                {result.banner}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function PortMatrix({ portResults = [] }) {
  // Group by IP
  const byHost = portResults.reduce((acc, r) => {
    const key = r.ip || r.host || "unknown";
    if (!acc[key]) acc[key] = [];
    acc[key].push(r);
    return acc;
  }, {});

  const openCount     = portResults.filter((r) => r.status === "open").length;
  const filteredCount = portResults.filter((r) => r.status === "filtered").length;

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700 p-4">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-white font-semibold text-sm tracking-wide uppercase">Port Matrix</h2>
        <div className="flex gap-4 text-xs">
          <span className="flex items-center gap-1.5 text-green-400">
            <span className="w-2 h-2 rounded-full bg-green-400" /> {openCount} open
          </span>
          <span className="flex items-center gap-1.5 text-yellow-400">
            <span className="w-2 h-2 rounded-full bg-yellow-400" /> {filteredCount} filtered
          </span>
        </div>
      </div>

      {Object.keys(byHost).length === 0 ? (
        <div className="text-gray-600 text-sm text-center py-8">
          No port results yet — run a port scan
        </div>
      ) : (
        Object.entries(byHost).map(([ip, results]) => (
          <div key={ip} className="mb-6">
            <div className="text-cyan-400 font-mono text-sm mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" />
              {ip}
              <span className="text-gray-500 text-xs">({results.length} ports scanned)</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {results
                .sort((a, b) => a.port - b.port)
                .map((r, i) => (
                  <PortCell key={`${r.port}-${r.protocol}-${i}`} result={r} />
                ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
