/**
 * components/OSFingerprintPanel.jsx
 * ----------------------------------
 * Per-host breakdown showing TTL, window size, Xmas probe result,
 * and final OS guess with confidence bar.
 */
import React from "react";

const OS_META = {
  linux: {
    emoji: "🐧",
    className: "text-os-linux",
  },
  windows: {
    emoji: "🪟",
    className: "text-os-windows",
  },
  macos: {
    emoji: "🍎",
    className: "text-os-macos",
  },
  unknown: {
    emoji: "❓",
    className: "text-text-tertiary",
  },
};

function normalizeOs(osGuess) {
  const value = String(osGuess || "").toLowerCase();
  if (value.includes("linux")) return "linux";
  if (value.includes("windows")) return "windows";
  if (value.includes("mac")) return "macos";
  return "unknown";
}

function toPercent(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  const scaled = numeric > 1 ? numeric : numeric * 100;
  return Math.max(0, Math.min(100, Math.round(scaled)));
}

function confidenceGradient(percent) {
  if (percent >= 80) return "bg-gradient-to-r from-status-success to-accent-primary";
  if (percent >= 50) return "bg-gradient-to-r from-threat-high to-threat-medium";
  return "bg-gradient-to-r from-threat-critical to-threat-high";
}

function parseSignal(signalKey, result) {
  if (signalKey === "ttl") {
    const explicit = result?.details?.ttl_signal;
    if (explicit) return explicit;
    const ttl = Number(result?.ttl);
    if (!Number.isFinite(ttl)) return "No response";
    if (ttl <= 64) return "Linux / macOS";
    if (ttl <= 128) return "Windows";
    return "Unknown";
  }

  if (signalKey === "window") {
    const explicit = result?.details?.window_signal;
    if (explicit) return explicit;
    const win = Number(result?.window_size);
    if (!Number.isFinite(win)) return "No response";
    if (win >= 64000) return "Linux / macOS";
    if (win >= 8000 && win < 64000) return "Windows";
    return "Unknown";
  }

  const xmas = String(result?.xmas_result || "");
  if (!xmas) return "No response";
  const lower = xmas.toLowerCase();
  if (lower.includes("no response") || lower.includes("filtered")) return "No response";
  if (lower.includes("rst") || lower.includes("closed")) return "Windows";
  if (lower.includes("open")) return "Linux / macOS";
  return xmas;
}

function interpretationClass(value) {
  const lower = String(value || "").toLowerCase();
  if (lower.includes("linux") && lower.includes("mac")) return "bg-os-linux/15 text-os-linux";
  if (lower.includes("linux")) return "bg-os-linux/15 text-os-linux";
  if (lower.includes("windows")) return "bg-os-windows/15 text-os-windows";
  if (lower.includes("mac")) return "bg-os-macos/15 text-os-macos";
  if (lower.includes("no response") || lower.includes("unknown")) {
    return "border border-border-default bg-bg-elevated text-text-tertiary";
  }
  return "bg-accent-muted text-accent-primary";
}

function contributionClass(value) {
  const lower = String(value || "").toLowerCase();
  if (lower.includes("linux") || lower.includes("windows") || lower.includes("mac")) {
    return "bg-accent-primary";
  }
  if (lower.includes("/") || lower.includes("possible")) return "bg-text-secondary";
  return "bg-text-disabled";
}

function ConfidenceBar({ value }) {
  const percent = toPercent(value);

  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs text-text-secondary">Confidence</span>
        <span className="font-mono text-xs text-text-tertiary">{percent}%</span>
      </div>
      <div className="h-2 w-full rounded-full bg-bg-elevated">
        <div
          className={`h-full rounded-full animate-bar-rise transition-[width] duration-500 ${confidenceGradient(percent)}`}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}

function SignalRow({ label, value, interpretation }) {
  return (
    <div className="flex items-center gap-3 rounded-md bg-bg-elevated p-2">
      <span className="w-28 flex-shrink-0 text-xs text-text-secondary">{label}</span>
      <span className="w-24 rounded-sm border border-border-default bg-bg-card px-2 py-0.5 text-center font-mono text-xs text-text-primary">
        {value}
      </span>
      <span className={`flex-shrink-0 rounded-sm px-2 py-0.5 text-xs ${interpretationClass(interpretation)}`}>
        {interpretation}
      </span>
      <span className={`ml-auto h-2 w-2 rounded-full ${contributionClass(interpretation)}`} />
    </div>
  );
}

function HostCard({ result }) {
  const osKey = normalizeOs(result.os_guess);
  const osMeta = OS_META[osKey] || OS_META.unknown;
  const hostLabel = result.hostname || result.ip || "unknown-host";
  const confidence = toPercent(result.confidence);

  const signals = [
    {
      label: "TTL Analysis",
      value: result.ttl ?? "—",
      interpretation: parseSignal("ttl", result),
    },
    {
      label: "TCP Window Size",
      value: result.window_size ?? "—",
      interpretation: parseSignal("window", result),
    },
    {
      label: "Xmas Scan Response",
      value: result.xmas_result || "—",
      interpretation: parseSignal("xmas", result),
    },
  ];

  return (
    <div className="rounded-lg border border-border-default bg-bg-card p-4">
      <div className="mb-4 flex items-center gap-3">
        <span className="leading-none" style={{ fontSize: "24px" }}>{osMeta.emoji}</span>
        <div>
          <div className="font-mono text-sm font-semibold text-text-primary">{hostLabel}</div>
          <div className="text-xs text-text-tertiary">OS Detection Result</div>
        </div>
        <div className="ml-auto text-right">
          <div className={`text-lg font-bold ${osMeta.className}`}>{result.os_guess || "unknown"}</div>
          <div className="text-sm text-text-tertiary">{confidence}% confidence</div>
        </div>
      </div>

      <ConfidenceBar value={result.confidence} />

      <div className="mt-4 flex flex-col gap-2">
        {signals.map((signal) => (
          <SignalRow
            key={signal.label}
            label={signal.label}
            value={signal.value}
            interpretation={signal.interpretation}
          />
        ))}
      </div>
    </div>
  );
}

export default function OSFingerprintPanel({ osResults = [], hosts = [] }) {
  // Merge osResults with host data
  const combined = osResults.length > 0 ? osResults : hosts.filter((h) => h.os_guess);

  return (
    <div className="flex flex-col gap-3 p-4">
      {combined.length === 0 ? (
        <div className="py-8 text-center text-sm text-text-tertiary">
          No OS data yet — run OS fingerprinting on a host
        </div>
      ) : (
        combined.map((r, i) => <HostCard key={r.ip || i} result={r} />)
      )}
    </div>
  );
}
