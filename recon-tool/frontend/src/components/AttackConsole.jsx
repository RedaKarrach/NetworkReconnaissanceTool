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
    desc:  "Poison ARP caches of target + gateway to intercept traffic (MITM)",
    fields: [
      { key: "target_ip",  label: "Target IP",  placeholder: "192.168.56.101" },
      { key: "gateway_ip", label: "Gateway IP", placeholder: "192.168.56.1" },
    ],
  },
  {
    id:    "syn_flood",
    label: "SYN Flood",
    desc:  "Overwhelm a TCP port with spoofed SYN packets to exhaust connection tables",
    fields: [
      { key: "target_ip",   label: "Target IP",   placeholder: "192.168.56.101" },
      { key: "target_port", label: "Target Port", placeholder: "80" },
    ],
  },
  {
    id:    "icmp_redirect",
    label: "ICMP Redirect",
    desc:  "Forge ICMP redirect messages to reroute victim traffic through attacker",
    fields: [
      { key: "target_ip",       label: "Target IP",        placeholder: "192.168.56.101" },
      { key: "spoofed_gateway", label: "Spoofed Gateway",  placeholder: "192.168.56.1" },
      { key: "attacker_ip",     label: "Attacker IP",      placeholder: "192.168.56.50" },
      { key: "destination_ip",  label: "Destination IP",   placeholder: "8.8.8.8" },
    ],
  },
];

const ATTACK_STYLE = {
  arp_spoof: {
    iconWrap: "bg-threat-high/15",
    iconText: "text-threat-high-text",
    launchBtn: "bg-gradient-to-r from-threat-high to-threat-medium text-text-primary",
  },
  syn_flood: {
    iconWrap: "bg-threat-critical/15",
    iconText: "text-threat-critical-text",
    launchBtn: "bg-gradient-to-r from-threat-critical to-threat-high text-text-primary",
  },
  icmp_redirect: {
    iconWrap: "bg-os-macos/15",
    iconText: "text-os-macos",
    launchBtn: "bg-gradient-to-r from-os-macos to-accent-primary text-text-primary",
  },
};

function AttackIcon({ attackId, className }) {
  if (attackId === "arp_spoof") {
    return (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
        <path d="M4 7h6" />
        <path d="m8 4 3 3-3 3" />
        <path d="M20 17h-6" />
        <path d="m16 14-3 3 3 3" />
        <circle cx="5" cy="17" r="2" />
        <circle cx="19" cy="7" r="2" />
      </svg>
    );
  }

  if (attackId === "syn_flood") {
    return (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
        <path d="M3 14c1.5-2 3-2 4.5 0s3 2 4.5 0 3-2 4.5 0 3 2 4.5 0" />
        <path d="M3 9c1.5-2 3-2 4.5 0s3 2 4.5 0 3-2 4.5 0 3 2 4.5 0" />
        <path d="M12 3v6" />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M5 12h12" />
      <path d="m13 6 6 6-6 6" />
      <path d="M5 6v12" />
    </svg>
  );
}

function AttackCard({ attack, activeThreads, onLaunch, onStop }) {
  const [params, setParams] = useState({});
  const activeEntry = activeThreads.find((t) => t.attackId === attack.id);
  const isRunning   = !!activeEntry;
  const style = ATTACK_STYLE[attack.id] || ATTACK_STYLE.arp_spoof;

  return (
    <div
      className={`flex flex-col rounded-lg border bg-bg-card p-5 transition-all duration-200 ${
        isRunning
          ? "border-border-danger shadow-danger animate-pulse-critical"
          : "border-border-default"
      }`}
    >
      <div className="mb-4 flex items-center gap-3">
        <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${style.iconWrap}`}>
          <AttackIcon attackId={attack.id} className={`h-5 w-5 ${style.iconText}`} />
        </div>
        <div>
          <h3 className="font-semibold text-text-primary">{attack.label}</h3>
        </div>
        <div className="ml-auto">
          {isRunning ? (
            <span className="inline-flex items-center gap-1 rounded-sm bg-threat-critical/15 px-2 py-0.5 text-xs text-threat-critical">
              <span className="h-1.5 w-1.5 rounded-full bg-threat-critical animate-pulse" />
              ● Running
            </span>
          ) : (
            <span className="inline-flex items-center rounded-sm bg-bg-elevated px-2 py-0.5 text-xs text-text-tertiary">Idle</span>
          )}
        </div>
      </div>

      <p className="mb-4 text-xs leading-relaxed text-text-tertiary">{attack.desc}</p>

      <div className="flex flex-1 flex-col gap-3">
        {attack.fields.map((f) => (
          <div key={f.key}>
            <label className="mb-1 block text-xs text-text-secondary">{f.label}</label>
            <input
              type="text"
              placeholder={f.placeholder}
              value={params[f.key] || ""}
              onChange={(e) => setParams((p) => ({ ...p, [f.key]: e.target.value }))}
              disabled={isRunning}
              className="w-full rounded-md border border-border-default bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-tertiary focus:border-accent-border focus:outline-none disabled:opacity-50"
            />
          </div>
        ))}
      </div>

      <div className="mt-4">
        {!isRunning ? (
          <button
            onClick={() => onLaunch(attack.id, params)}
            className={`w-full rounded-md py-3 font-semibold transition-all duration-150 hover:-translate-y-px hover:shadow-danger active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-60 ${style.launchBtn}`}
          >
            ⚡ Launch Attack
          </button>
        ) : (
          <button
            onClick={() => onStop(activeEntry.threadId, attack.id)}
            className="w-full rounded-md border border-border-danger bg-bg-elevated py-3 font-semibold text-threat-critical transition-all duration-150 hover:-translate-y-px hover:shadow-danger active:scale-[0.98]"
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
    setLog((prev) => [{ ts: new Date().toLocaleTimeString(), msg, type }, ...prev].slice(0, 20));
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
    <div>
      {/* Warning banner */}
      <div className="mb-4 flex items-center gap-2 rounded-lg border border-threat-high/30 bg-threat-high/10 px-4 py-3 text-sm text-threat-high">
        <span className="text-threat-high">⚠</span>
        <span>Authorized lab environment only — 192.168.56.0/24 network</span>
      </div>

      {/* Attack cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
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
        <div className="mt-4 rounded-md border border-border-danger bg-threat-critical/15 px-3 py-2 text-sm text-threat-critical">
          {error}
        </div>
      )}

      {/* Activity log */}
      <div className="mt-6 overflow-hidden rounded-lg border border-border-default bg-bg-card">
        <div className="px-4 pt-3 text-xs uppercase tracking-widest text-text-tertiary">ACTIVITY LOG</div>
        <div className="max-h-48 overflow-y-auto font-mono text-xs">
          {log.length === 0 ? (
            <div className="px-4 py-2 text-text-tertiary">No activity yet</div>
          ) : (
            log.map((entry, i) => {
              const marker =
                entry.type === "success"
                  ? { label: "[START]", className: "text-threat-critical" }
                  : entry.type === "warn"
                    ? { label: "[STOP]", className: "text-status-success" }
                    : { label: "[INFO]", className: "text-accent-primary" };

              return (
                <div key={i} className="border-b border-border-default/30 px-4 py-1.5">
                  <span className="mr-3 text-text-tertiary">{entry.ts}</span>
                  <span className={`mr-2 ${marker.className}`}>{marker.label}</span>
                  <span className="text-text-secondary">{entry.msg}</span>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
