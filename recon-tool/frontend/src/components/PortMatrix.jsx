/**
 * components/PortMatrix.jsx
 * -------------------------
 * Grid of scanned ports per host.
 * Green = open, Red = closed, Yellow = filtered, Gray = open|filtered
 * Hover shows banner if available.
 */
import React, { useState } from "react";

const STATUS_STYLE = {
  open: "bg-threat-low/20 border-threat-low/40 text-threat-low",
  closed: "bg-threat-critical/15 border-threat-critical/30 text-threat-critical",
  filtered: "bg-threat-high/20 border-threat-high/40 text-threat-high",
  "open|filtered": "bg-bg-elevated border-border-default text-text-tertiary",
};

const OS_DOT = {
  linux: "bg-os-linux",
  windows: "bg-os-windows",
  macos: "bg-os-macos",
  unknown: "bg-os-unknown",
};

function normalizeOsName(value) {
  const name = String(value || "unknown");
  const lower = name.toLowerCase();
  if (lower.includes("linux")) return "linux";
  if (lower.includes("windows")) return "windows";
  if (lower.includes("mac")) return "macos";
  return "unknown";
}

function PortCell({ result, index }) {
  const [showTip, setShowTip] = useState(false);
  const style = STATUS_STYLE[result.status] || STATUS_STYLE.filtered;
  const protocol = typeof result.protocol === "string" && result.protocol
    ? result.protocol
    : "unknown";
  const service = result.service || "n/a";
  const banner = result.banner ? String(result.banner).slice(0, 60) : "n/a";

  const tooltip = `Port: ${result.port}\nProtocol: ${protocol.toUpperCase()}\nService: ${service}\nBanner: ${banner}`;

  return (
    <div
      className={`relative flex items-center justify-center rounded-sm border font-mono text-xs font-medium text-center cursor-default select-none animate-fade-in ${style}`}
      style={{ width: "56px", height: "28px", animationDelay: `${index * 20}ms` }}
      onMouseEnter={() => setShowTip(true)}
      onMouseLeave={() => setShowTip(false)}
      title={tooltip}
    >
      {result.port}

      {showTip && (
        <div className="absolute bottom-full left-1/2 z-50 mb-2 w-64 -translate-x-1/2 rounded-md border border-border-elevated bg-bg-elevated p-2 text-left shadow-card">
          <div className="mb-1 font-semibold text-accent-primary">
            Port {result.port}/{protocol.toUpperCase()}
          </div>
          <div className="mb-1 flex gap-2">
            <span className="text-xs capitalize text-text-secondary">{result.status}</span>
          </div>
          <div className="font-mono text-xs text-text-tertiary">Service: {service}</div>
          <div className="mt-1 font-mono text-xs text-text-tertiary">Banner: {banner}</div>
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
    <div className="flex flex-col gap-4 p-4">
      {Object.keys(byHost).length === 0 ? (
        <div className="py-8 text-center text-sm text-text-tertiary">
          No port results yet — run a port scan
        </div>
      ) : (
        Object.entries(byHost).map(([ip, results]) => (
          <div key={ip}>
            {(() => {
              const open = results.filter((r) => r.status === "open").length;
              const closed = results.filter((r) => r.status === "closed").length;
              const filtered = results.filter((r) => r.status === "filtered" || r.status === "open|filtered").length;
              const first = results[0] || {};
              const osName = first.os || first.os_guess || "unknown";
              const osClass = OS_DOT[normalizeOsName(osName)] || OS_DOT.unknown;

              return (
                <>
                  <div className="flex items-center">
                    <span className={`h-1.5 w-1.5 rounded-full ${osClass}`} />
                    <span className="ml-2 font-mono text-sm font-semibold text-text-primary">{ip}</span>
                    <span className="ml-2 text-xs text-text-tertiary">{osName}</span>
                    <span className="ml-auto text-xs text-text-tertiary">{open} open · {closed} closed · {filtered} filtered</span>
                  </div>

                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {results
                      .sort((a, b) => a.port - b.port)
                      .map((r, i) => (
                        <PortCell key={`${r.port}-${r.protocol}-${i}`} result={r} index={i} />
                      ))}
                  </div>

                  <div className="mt-2 text-xs text-text-tertiary">
                    Scanned {results.length} ports — {open} open, {closed} closed, {filtered} filtered
                  </div>
                </>
              );
            })()}
          </div>
        ))
      )}
      {(openCount > 0 || filteredCount > 0) && (
        <div className="text-xs text-text-tertiary">
          Total observed — {openCount} open, {filteredCount} filtered
        </div>
      )}
    </div>
  );
}
