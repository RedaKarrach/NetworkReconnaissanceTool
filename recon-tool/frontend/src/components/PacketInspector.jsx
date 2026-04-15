/**
 * components/PacketInspector.jsx
 * --------------------------------
 * Live scrolling feed of every raw packet event during a scan.
 * Shows: timestamp, src→dst, protocol, flags, TTL, payload summary.
 * Auto-scrolls to newest; can be paused.
 */
import React, { useEffect, useRef, useState } from "react";

const PROTO_COLOR = {
  TCP:  "text-blue-400",
  UDP:  "text-purple-400",
  ARP:  "text-yellow-400",
  ICMP: "text-orange-400",
  HTTP: "text-green-400",
};

const FLAG_COLOR = {
  "SYN-FLOOD":     "bg-red-900 text-red-300",
  "ARP-SPOOF":     "bg-orange-900 text-orange-300",
  "ARP-REPLY":     "bg-yellow-900 text-yellow-300",
  "ICMP-REDIRECT": "bg-pink-900 text-pink-300",
  "FPU":           "bg-purple-900 text-purple-300",
  "S":             "bg-blue-900 text-blue-300",
  "SA":            "bg-green-900 text-green-300",
  "R":             "bg-red-900 text-red-300",
  "RA":            "bg-red-900 text-red-300",
  "ERROR":         "bg-red-950 text-red-400",
};

function flagStyle(flags) {
  if (!flags) return "bg-gray-800 text-gray-500";
  return FLAG_COLOR[flags] || "bg-gray-800 text-gray-400";
}

function protoColor(proto) {
  return PROTO_COLOR[proto?.toUpperCase()] || "text-gray-400";
}

function PacketRow({ pkt, idx }) {
  const ts = pkt.timestamp
    ? new Date(pkt.timestamp).toLocaleTimeString("en-US", { hour12: false, fractionalSecondDigits: 2 })
    : "";

  return (
    <div className={`flex items-start gap-2 px-3 py-1.5 border-b border-gray-800 hover:bg-gray-800/50
                     text-xs font-mono transition-colors ${idx === 0 ? "bg-gray-800/30" : ""}`}>
      {/* Timestamp */}
      <span className="text-gray-600 w-24 flex-shrink-0">{ts}</span>

      {/* Protocol */}
      <span className={`w-10 flex-shrink-0 font-bold ${protoColor(pkt.protocol)}`}>
        {pkt.protocol || "???"}
      </span>

      {/* Flags badge */}
      <span className={`px-1.5 py-0.5 rounded text-[10px] flex-shrink-0 ${flagStyle(pkt.flags)}`}>
        {pkt.flags || "—"}
      </span>

      {/* TTL */}
      <span className="text-gray-600 w-10 flex-shrink-0">
        {pkt.ttl ? `ttl=${pkt.ttl}` : ""}
      </span>

      {/* src → dst */}
      <span className="text-gray-500 flex-shrink-0">
        <span className="text-cyan-500">{pkt.src_ip || "?"}</span>
        <span className="text-gray-600"> → </span>
        <span className="text-indigo-400">{pkt.dst_ip || "?"}</span>
      </span>

      {/* Summary */}
      <span className="text-gray-400 flex-1 truncate ml-1">
        {pkt.summary || pkt.message || ""}
      </span>
    </div>
  );
}

export default function PacketInspector({ packets = [], pps = 0, wsStatus = "disconnected" }) {
  const bottomRef = useRef(null);
  const [paused,   setPaused]   = useState(false);
  const [filter,   setFilter]   = useState("");
  const [maxLines, setMaxLines] = useState(200);

  // Auto-scroll to bottom when new packets arrive (if not paused)
  useEffect(() => {
    if (!paused && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [packets, paused]);

  const filtered = packets
    .filter((p) => {
      if (!filter) return true;
      const hay = JSON.stringify(p).toLowerCase();
      return hay.includes(filter.toLowerCase());
    })
    .slice(0, maxLines);

  const statusColor = {
    connected:    "bg-green-500",
    connecting:   "bg-yellow-500",
    disconnected: "bg-gray-500",
    error:        "bg-red-500",
  }[wsStatus] || "bg-gray-500";

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700 flex flex-col" style={{ height: 480 }}>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-700 flex-shrink-0">
        <h2 className="text-white font-semibold text-sm tracking-wide uppercase flex-1">
          Packet Inspector
        </h2>

        {/* WS status */}
        <div className="flex items-center gap-1.5">
          <span className={`w-2 h-2 rounded-full ${statusColor} ${wsStatus === "connected" ? "animate-pulse" : ""}`} />
          <span className="text-gray-500 text-xs">{wsStatus}</span>
        </div>

        {/* PPS counter */}
        <div className="text-xs text-gray-500">
          <span className="text-green-400 font-mono">{pps}</span> pkt/s
        </div>

        {/* Filter input */}
        <input
          type="text"
          placeholder="filter…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs text-gray-300
                     placeholder-gray-600 focus:outline-none focus:border-cyan-500 w-32"
        />

        {/* Pause toggle */}
        <button
          onClick={() => setPaused((p) => !p)}
          className={`px-2 py-1 rounded text-xs font-medium transition-colors
            ${paused
              ? "bg-green-700 text-green-200 hover:bg-green-600"
              : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}
        >
          {paused ? "▶ Resume" : "⏸ Pause"}
        </button>

        {/* Total count */}
        <span className="text-gray-600 text-xs">{packets.length} events</span>
      </div>

      {/* Column headers */}
      <div className="flex gap-2 px-3 py-1 bg-gray-800/50 border-b border-gray-800 text-[10px] text-gray-600 font-mono flex-shrink-0">
        <span className="w-24">Time</span>
        <span className="w-10">Proto</span>
        <span className="w-16">Flags</span>
        <span className="w-10">TTL</span>
        <span className="flex-1">src → dst → summary</span>
      </div>

      {/* Packet rows */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-600 text-sm">
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
    </div>
  );
}
