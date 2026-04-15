/**
 * components/OSFingerprintPanel.jsx
 * ----------------------------------
 * Per-host breakdown showing TTL, window size, Xmas probe result,
 * and final OS guess with confidence bar.
 */
import React from "react";

const OS_ICONS = {
  Windows:    "🪟",
  Linux:      "🐧",
  macOS:      "🍎",
  "Cisco/BSD":"🔌",
  unknown:    "❓",
};

function getIcon(os) {
  for (const key of Object.keys(OS_ICONS)) {
    if (os && os.includes(key)) return OS_ICONS[key];
  }
  return OS_ICONS.unknown;
}

function ConfidenceBar({ value }) {
  const pct = Math.round((value || 0) * 100);
  const color =
    pct >= 70 ? "bg-green-500" :
    pct >= 40 ? "bg-yellow-500" :
    "bg-red-500";

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-gray-700 rounded-full h-2">
        <div
          className={`h-2 rounded-full transition-all duration-500 ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs text-gray-400 w-8 text-right">{pct}%</span>
    </div>
  );
}

function SignalRow({ label, value, mono = false }) {
  return (
    <div className="flex justify-between items-center py-1 border-b border-gray-800">
      <span className="text-gray-500 text-xs">{label}</span>
      <span className={`text-sm ${mono ? "font-mono text-cyan-300" : "text-gray-300"}`}>
        {value ?? "—"}
      </span>
    </div>
  );
}

function HostCard({ result }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xl">{getIcon(result.os_guess)}</span>
            <span className="text-white font-semibold">{result.os_guess || "unknown"}</span>
          </div>
          <div className="text-gray-500 text-xs font-mono mt-0.5">{result.ip}</div>
        </div>
        <div className="text-right">
          <div className="text-gray-500 text-xs mb-1">Confidence</div>
          <div className="w-32">
            <ConfidenceBar value={result.confidence} />
          </div>
        </div>
      </div>

      <div className="space-y-0.5">
        <SignalRow label="TTL"         value={result.ttl}          mono />
        <SignalRow label="Window Size" value={result.window_size}  mono />
        <SignalRow label="Xmas Probe"  value={result.xmas_result} />
        {result.details && (
          <>
            <SignalRow label="TTL signal"    value={result.details.ttl_signal} />
            <SignalRow label="Window signal" value={result.details.window_signal} />
          </>
        )}
      </div>
    </div>
  );
}

export default function OSFingerprintPanel({ osResults = [], hosts = [] }) {
  // Merge osResults with host data
  const combined = osResults.length > 0 ? osResults : hosts.filter((h) => h.os_guess);

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700 p-4">
      <h2 className="text-white font-semibold text-sm tracking-wide uppercase mb-4">
        OS Fingerprints
      </h2>

      {combined.length === 0 ? (
        <div className="text-gray-600 text-sm text-center py-8">
          No OS data yet — run OS fingerprinting on a host
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {combined.map((r, i) => (
            <HostCard key={r.ip || i} result={r} />
          ))}
        </div>
      )}
    </div>
  );
}
