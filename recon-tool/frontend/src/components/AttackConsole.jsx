/**
 * components/AttackConsole.jsx
 * ----------------------------
 * Launch / stop attack simulations.
 * Live counters showing packets-per-second from WebSocket stream.
 * ⚠️  FOR AUTHORISED LAB USE ONLY — displays prominent warning banner.
 */
import React, { useState } from "react";
import { useScan } from "../hooks/useScan";

const ATTACK_TYPES = [
  {
    id:    "arp_spoof",
    label: "ARP Spoof",
    icon:  "🕸️",
    desc:  "Poison ARP caches of target + gateway to intercept traffic (MITM)",
    color: "orange",
    fields: [
      { key: "target_ip",  label: "Target IP",  placeholder: "192.168.56.101" },
      { key: "gateway_ip", label: "Gateway IP", placeholder: "192.168.56.1" },
    ],
  },
  {
    id:    "syn_flood",
    label: "SYN Flood",
    icon:  "🌊",
    desc:  "Overwhelm a TCP port with spoofed SYN packets to exhaust connection tables",
    color: "red",
    fields: [
      { key: "target_ip",   label: "Target IP",   placeholder: "192.168.56.101" },
      { key: "target_port", label: "Target Port", placeholder: "80" },
    ],
  },
  {
    id:    "icmp_redirect",
    label: "ICMP Redirect",
    icon:  "↩️",
    desc:  "Forge ICMP redirect messages to reroute victim traffic through attacker",
    color: "purple",
    fields: [
      { key: "target_ip",       label: "Target IP",        placeholder: "192.168.56.101" },
      { key: "spoofed_gateway", label: "Spoofed Gateway",  placeholder: "192.168.56.1" },
      { key: "attacker_ip",     label: "Attacker IP",      placeholder: "192.168.56.50" },
      { key: "destination_ip",  label: "Destination IP",   placeholder: "8.8.8.8" },
    ],
  },
];

function AttackCard({ attack, activeThreads, onLaunch, onStop }) {
  const [params, setParams] = useState({});
  const activeEntry = activeThreads.find((t) => t.attackId === attack.id);
  const isRunning   = !!activeEntry;

  const borderColor = {
    orange: "border-orange-700 hover:border-orange-500",
    red:    "border-red-800   hover:border-red-600",
    purple: "border-purple-800 hover:border-purple-600",
  }[attack.color];

  const btnColor = {
    orange: "bg-orange-700 hover:bg-orange-600 text-white",
    red:    "bg-red-700    hover:bg-red-600    text-white",
    purple: "bg-purple-700 hover:bg-purple-600 text-white",
  }[attack.color];

  return (
    <div className={`bg-gray-800 border rounded-xl p-4 transition-colors ${borderColor}`}>
      <div className="flex items-start gap-3 mb-3">
        <span className="text-2xl">{attack.icon}</span>
        <div>
          <h3 className="text-white font-semibold">{attack.label}</h3>
          <p className="text-gray-500 text-xs mt-0.5">{attack.desc}</p>
        </div>
        {isRunning && (
          <div className="ml-auto flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            <span className="text-red-400 text-xs font-medium">RUNNING</span>
          </div>
        )}
      </div>

      {/* Parameter inputs */}
      <div className="grid grid-cols-2 gap-2 mb-3">
        {attack.fields.map((f) => (
          <div key={f.key}>
            <label className="text-gray-500 text-xs mb-1 block">{f.label}</label>
            <input
              type="text"
              placeholder={f.placeholder}
              value={params[f.key] || ""}
              onChange={(e) => setParams((p) => ({ ...p, [f.key]: e.target.value }))}
              disabled={isRunning}
              className="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1.5
                         text-sm text-gray-300 font-mono placeholder-gray-700
                         focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            />
          </div>
        ))}
      </div>

      {/* Stats when running */}
      {isRunning && activeEntry.pktCount !== undefined && (
        <div className="flex gap-4 mb-3 text-xs">
          <div className="bg-gray-900 rounded px-3 py-1.5">
            <div className="text-gray-500">Packets sent</div>
            <div className="text-green-400 font-mono text-lg">{activeEntry.pktCount}</div>
          </div>
          <div className="bg-gray-900 rounded px-3 py-1.5">
            <div className="text-gray-500">Thread ID</div>
            <div className="text-cyan-400 font-mono text-[10px] truncate w-32">{activeEntry.threadId}</div>
          </div>
        </div>
      )}

      <div className="flex gap-2">
        {!isRunning ? (
          <button
            onClick={() => onLaunch(attack.id, params)}
            className={`flex-1 py-2 rounded font-medium text-sm transition-colors ${btnColor}`}
          >
            Launch {attack.label}
          </button>
        ) : (
          <button
            onClick={() => onStop(activeEntry.threadId, attack.id)}
            className="flex-1 py-2 rounded font-medium text-sm
                       bg-gray-700 hover:bg-gray-600 text-white transition-colors"
          >
            ■ Stop Attack
          </button>
        )}
      </div>
    </div>
  );
}

export default function AttackConsole({ onSessionStart }) {
  const { startArpSpoof, startSynFlood, startIcmpRedirect, stopThread, loading, error } = useScan();
  const [activeThreads, setActiveThreads] = useState([]);
  const [log,           setLog]           = useState([]);

  function addLog(msg, type = "info") {
    setLog((prev) => [{ ts: new Date().toLocaleTimeString(), msg, type }, ...prev].slice(0, 100));
  }

  async function handleLaunch(attackId, params) {
    let result = null;

    if (attackId === "arp_spoof") {
      if (!params.target_ip || !params.gateway_ip) {
        addLog("Target IP and Gateway IP are required", "error"); return;
      }
      result = await startArpSpoof(params.target_ip, params.gateway_ip);
    } else if (attackId === "syn_flood") {
      if (!params.target_ip) {
        addLog("Target IP is required", "error"); return;
      }
      result = await startSynFlood(params.target_ip, parseInt(params.target_port || 80));
    } else if (attackId === "icmp_redirect") {
      if (!params.target_ip || !params.spoofed_gateway || !params.attacker_ip) {
        addLog("target_ip, spoofed_gateway, and attacker_ip are required", "error"); return;
      }
      result = await startIcmpRedirect(
        params.target_ip, params.spoofed_gateway,
        params.attacker_ip, params.destination_ip || "8.8.8.8"
      );
    }

    if (result) {
      setActiveThreads((prev) => [
        ...prev,
        { attackId, threadId: result.thread_id, sessionId: result.session_id, pktCount: 0 }
      ]);
      addLog(`Launched ${attackId} → session ${result.session_id.slice(0, 8)}`, "success");
      if (onSessionStart) onSessionStart(result.session_id);
    }
  }

  async function handleStop(threadId, attackId) {
    await stopThread(threadId);
    setActiveThreads((prev) => prev.filter((t) => t.threadId !== threadId));
    addLog(`Stopped ${attackId} (thread ${threadId.slice(0, 8)})`, "warn");
  }

  return (
    <div className="space-y-4">
      {/* Warning banner */}
      <div className="bg-red-950 border border-red-700 rounded-xl p-3 flex items-start gap-3">
        <span className="text-red-400 text-lg">⚠️</span>
        <div>
          <div className="text-red-400 font-semibold text-sm">Authorised Lab Use Only</div>
          <div className="text-red-500 text-xs mt-0.5">
            These tools are for educational purposes in isolated VM environments only.
            Running them against systems you don't own is illegal.
          </div>
        </div>
      </div>

      {/* Attack cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {ATTACK_TYPES.map((a) => (
          <AttackCard
            key={a.id}
            attack={a}
            activeThreads={activeThreads}
            onLaunch={handleLaunch}
            onStop={handleStop}
          />
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-900/50 border border-red-700 rounded px-3 py-2 text-red-300 text-sm">
          {error}
        </div>
      )}

      {/* Activity log */}
      <div className="bg-gray-900 rounded-xl border border-gray-700 p-4">
        <h3 className="text-gray-400 text-xs uppercase tracking-wide mb-2">Attack Log</h3>
        <div className="space-y-1 font-mono text-xs max-h-40 overflow-y-auto">
          {log.length === 0 && (
            <div className="text-gray-700">No activity yet</div>
          )}
          {log.map((entry, i) => (
            <div key={i} className={`flex gap-2 ${
              entry.type === "error"   ? "text-red-400" :
              entry.type === "success" ? "text-green-400" :
              entry.type === "warn"    ? "text-yellow-400" :
              "text-gray-400"
            }`}>
              <span className="text-gray-700">{entry.ts}</span>
              <span>{entry.msg}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
