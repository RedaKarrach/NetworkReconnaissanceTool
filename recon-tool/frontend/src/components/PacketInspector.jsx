/**
 * components/PacketInspector.jsx
 * --------------------------------
 * Live scrolling feed of every raw packet event during a scan.
 * Shows: timestamp, src→dst, protocol, flags, TTL, payload summary.
 * Auto-scrolls to newest; can be paused.
 */
import React, { useEffect, useRef, useState } from "react";

const PROTO_COLOR = {
  TCP: "text-accent-primary",
  UDP: "text-threat-high",
  ARP: "text-threat-medium",
  ICMP: "text-os-macos",
};

const FLAG_COLOR = {
  SYN: "bg-accent-muted text-accent-primary",
  ACK: "bg-status-success/15 text-status-success",
  RST: "bg-threat-critical/15 text-threat-critical",
  FIN: "bg-bg-elevated text-text-tertiary",
  SA: "bg-status-success/15 text-status-success",
  "SYN-FLOOD": "bg-accent-muted text-accent-primary",
  "ARP-SPOOF": "bg-threat-medium-bg text-threat-medium",
  "ARP-REPLY": "bg-threat-medium-bg text-threat-medium",
  "ICMP-REDIRECT": "bg-os-macos/15 text-os-macos",
  R: "bg-threat-critical/15 text-threat-critical",
  RA: "bg-threat-critical/15 text-threat-critical",
  S: "bg-accent-muted text-accent-primary",
  "S-ACK": "bg-status-success/15 text-status-success",
};

function flagStyle(flags) {
  if (!flags) return "bg-bg-elevated text-text-tertiary";
  return FLAG_COLOR[flags] || "bg-bg-elevated text-text-tertiary";
}

function protoColor(proto) {
  return PROTO_COLOR[proto?.toUpperCase()] || "text-text-tertiary";
}

function PacketRow({ pkt, idx }) {
  const ts = pkt.timestamp
    ? new Date(pkt.timestamp).toLocaleTimeString("en-US", {
        hour12: false,
        fractionalSecondDigits: 2,
      })
    : "";

  const proto = String(pkt.protocol || "").toUpperCase();
  const flags = String(pkt.flags || "").toUpperCase().split(/[\s,|]+/).filter(Boolean).slice(0, 3);

  return (
    <div
      className={`flex items-start gap-2 border-b border-border-default/50 px-3 py-1.5 text-xs transition-colors hover:bg-white/[0.02] ${
        idx === 0 ? "bg-bg-elevated/40" : ""
      }`}
    >
      {/* Timestamp */}
      <span className="w-16 flex-shrink-0 font-mono text-xs text-text-tertiary">{ts}</span>

      {/* Protocol */}
      <span className={`w-8 flex-shrink-0 font-mono text-xs font-bold ${protoColor(proto)}`}>
        {proto || "?"}
      </span>

      {/* Flags badge */}
      <div className="w-12 flex-shrink-0">
        <div className="flex flex-wrap gap-1">
          {flags.length === 0 ? (
            <span className="rounded-sm bg-bg-elevated px-1 text-xs text-text-tertiary">—</span>
          ) : (
            flags.map((flag) => (
              <span key={`${pkt.timestamp || idx}-${flag}`} className={`rounded-sm px-1 text-xs ${flagStyle(flag)}`}>
                {flag}
              </span>
            ))
          )}
        </div>
      </div>

      {/* TTL */}
      <span className="w-10 flex-shrink-0 font-mono text-xs text-text-tertiary">{pkt.ttl ?? ""}</span>

      {/* src → dst */}
      <span className="w-48 flex-shrink-0 truncate font-mono text-xs">
        <span className="text-accent-primary">{pkt.src_ip || "?"}</span>
        <span className="mx-1 text-text-tertiary">→</span>
        <span className="text-os-macos">{pkt.dst_ip || "?"}</span>
      </span>

      {/* Summary */}
      <span className="ml-1 flex-1 truncate text-xs text-text-tertiary">
        {pkt.summary || pkt.message || ""}
      </span>
    </div>
  );
}

export default function PacketInspector({ packets = [], pps = 0, wsStatus = "disconnected" }) {
  const bottomRef = useRef(null);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [maxLines, setMaxLines] = useState(200);
  const [isAutoScrolling, setIsAutoScrolling] = useState(true);

  // Auto-scroll to bottom when new packets arrive (if not paused)
  useEffect(() => {
    if (!paused && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
      setIsAutoScrolling(true);
    }
  }, [packets, paused]);

  function onScroll(event) {
    const element = event.currentTarget;
    const nearBottom = element.scrollHeight - element.scrollTop - element.clientHeight < 4;
    setIsAutoScrolling(nearBottom);
  }

  const filtered = packets
    .filter((p) => {
      if (!filter) return true;
      const hay = JSON.stringify(p).toLowerCase();
      return hay.includes(filter.toLowerCase());
    })
    .slice(0, maxLines);

  return (
    <div className="relative flex h-full min-h-0 flex-col rounded-lg border border-border-default bg-bg-app font-mono">
      {/* Header */}
      <div className="flex flex-shrink-0 items-center gap-3 border-b border-border-default px-3 py-2">
        <h2 className="text-xs font-semibold tracking-widest text-text-tertiary">
          Packet Inspector
        </h2>

        {/* PPS counter */}
        <div className="flex items-end gap-1">
          <span className="font-mono text-xl font-bold leading-none text-accent-primary">{pps}</span>
          <span className="text-xs text-text-tertiary">pkt/s</span>
        </div>

        {/* Filter input */}
        <div className="relative mx-auto w-full max-w-sm">
          <span className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-text-tertiary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-4 w-4">
              <circle cx="11" cy="11" r="7" />
              <path d="m20 20-3.5-3.5" />
            </svg>
          </span>
          <input
            type="text"
            placeholder="Filter packets..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full rounded-md border border-border-default bg-bg-input px-3 py-1.5 pl-8 text-sm text-text-primary placeholder:text-text-tertiary outline-none transition-colors duration-150 focus:border-accent-border"
          />
        </div>

        {/* Pause toggle */}
        <button
          onClick={() => setPaused((p) => !p)}
          className="rounded-md border border-border-default bg-bg-elevated px-3 py-1.5 text-sm text-text-secondary transition-colors duration-150 hover:bg-bg-card-hover hover:text-text-primary"
        >
          {paused ? "▶ Resume" : "⏸ Pause"}
        </button>

        <button
          type="button"
          onClick={() => setFilter("")}
          className="text-sm text-text-tertiary transition-colors duration-150 hover:text-status-danger"
        >
          Clear
        </button>
      </div>

      {/* Column headers */}
      <div className="flex flex-shrink-0 gap-2 border-b border-border-default bg-bg-elevated/50 px-3 py-1.5 text-xs uppercase text-text-tertiary">
        <span className="w-16">Time</span>
        <span className="w-8">Proto</span>
        <span className="w-12">Flags</span>
        <span className="w-10">TTL</span>
        <span className="w-48">Route</span>
        <span className="flex-1">Summary</span>
      </div>

      {/* Packet rows */}
      <div className="flex-1 overflow-y-auto" onScroll={onScroll}>
        {filtered.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-text-tertiary">
            {packets.length === 0
              ? "Waiting for packets…"
              : `No packets match "${filter}"`}
          </div>
        ) : (
          <>
            {[...filtered].reverse().map((pkt, i) => (
              <PacketRow key={i} pkt={pkt} idx={i} />
            ))}
            <div ref={bottomRef} />
          </>
        )}
      </div>

      <div
        className={`pointer-events-none absolute bottom-3 left-1/2 -translate-x-1/2 rounded-full bg-accent-muted px-3 py-1 text-xs text-accent-primary transition-opacity duration-150 ${
          !paused && isAutoScrolling ? "opacity-100" : "opacity-0"
        }`}
      >
        ↓ Auto-scrolling
      </div>
    </div>
  );
}
