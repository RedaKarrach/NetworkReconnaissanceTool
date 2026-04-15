/**
 * pages/Dashboard.jsx
 * --------------------
 * Main scan control panel.
 * Allows launching scans, shows live results via WebSocket.
 */
import React, { useState } from "react";
import { useScan }         from "../hooks/useScan";
import { useWebSocket }    from "../hooks/useWebSocket";
import NetworkMap          from "../components/NetworkMap";
import PortMatrix          from "../components/PortMatrix";
import OSFingerprintPanel  from "../components/OSFingerprintPanel";
import PacketInspector     from "../components/PacketInspector";

const COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,3389,8080,8443];

export default function Dashboard() {
  const { startHostDiscovery, startPortScan, startOsFingerprint, stopThread, loading, error } = useScan();

  const [sessionId,  setSessionId]  = useState(null);
  const [threadId,   setThreadId]   = useState(null);
  const [subnet,     setSubnet]     = useState("192.168.56.0/24");
  const [scanIp,     setScanIp]     = useState("");
  const [ports,      setPorts]      = useState("21,22,80,443,8080");
  const [protocol,   setProtocol]   = useState("tcp");
  const [fpIp,       setFpIp]       = useState("");
  const [activeTab,  setActiveTab]  = useState("map");
  const [localHosts, setLocalHosts] = useState([]);

  // Subscribe to live events for the active session
  const ws = useWebSocket(sessionId);

  // Merge WebSocket host events with local state for the map
  const allHosts = [
    ...localHosts,
    ...ws.hosts.filter((wh) => !localHosts.some((lh) => lh.ip === wh.ip))
  ];

  async function handleHostDiscovery() {
    const res = await startHostDiscovery(subnet);
    if (res) {
      setSessionId(res.session_id);
      setThreadId(res.thread_id);
      setLocalHosts([]);
    }
  }

  async function handlePortScan() {
    const portList = ports.split(",").map((p) => parseInt(p.trim())).filter(Boolean);
    const res = await startPortScan(scanIp, portList, protocol);
    if (res) {
      setSessionId(res.session_id);
      setThreadId(res.thread_id);
    }
  }

  async function handleFingerprint() {
    const res = await startOsFingerprint(fpIp);
    if (res) {
      setSessionId(res.session_id);
      setThreadId(res.thread_id);
    }
  }

  const tabs = [
    { id: "map",   label: "Network Map" },
    { id: "ports", label: "Port Matrix" },
    { id: "os",    label: "OS Fingerprints" },
    { id: "pkts",  label: "Packet Inspector" },
  ];

  return (
    <div className="space-y-6">
      {/* Scan Controls */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

        {/* Host Discovery */}
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
          <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
            <span className="text-green-400">◉</span> Host Discovery
          </h3>
          <label className="text-gray-500 text-xs mb-1 block">Subnet (CIDR)</label>
          <input
            value={subnet}
            onChange={(e) => setSubnet(e.target.value)}
            className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm
                       text-gray-300 font-mono mb-3 focus:outline-none focus:border-cyan-500"
            placeholder="192.168.56.0/24"
          />
          <button
            onClick={handleHostDiscovery}
            disabled={loading}
            className="w-full py-2 bg-green-700 hover:bg-green-600 disabled:opacity-50
                       text-white text-sm rounded font-medium transition-colors"
          >
            {loading ? "Scanning…" : "ARP Sweep"}
          </button>
        </div>

        {/* Port Scan */}
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
          <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
            <span className="text-blue-400">◉</span> Port Scan
          </h3>
          <label className="text-gray-500 text-xs mb-1 block">Target IP</label>
          <input
            value={scanIp}
            onChange={(e) => setScanIp(e.target.value)}
            className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm
                       text-gray-300 font-mono mb-2 focus:outline-none focus:border-cyan-500"
            placeholder="192.168.56.101"
          />
          <div className="flex gap-2 mb-2">
            <div className="flex-1">
              <label className="text-gray-500 text-xs mb-1 block">Ports</label>
              <input
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                className="w-full bg-gray-900 border border-gray-600 rounded px-2 py-2 text-sm
                           text-gray-300 font-mono focus:outline-none focus:border-cyan-500"
                placeholder="22,80,443"
              />
            </div>
            <div>
              <label className="text-gray-500 text-xs mb-1 block">Proto</label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="bg-gray-900 border border-gray-600 rounded px-2 py-2 text-sm
                           text-gray-300 focus:outline-none"
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
            </div>
          </div>
          <div className="flex flex-wrap gap-1 mb-3">
            {COMMON_PORTS.map((p) => (
              <button
                key={p}
                onClick={() => setPorts(COMMON_PORTS.join(","))}
                className="text-[10px] text-gray-500 hover:text-cyan-400 font-mono"
              >
                {p}
              </button>
            ))}
            <button
              onClick={() => setPorts(COMMON_PORTS.join(","))}
              className="text-[10px] text-cyan-600 hover:text-cyan-400 ml-1"
            >
              use all common
            </button>
          </div>
          <button
            onClick={handlePortScan}
            disabled={loading || !scanIp}
            className="w-full py-2 bg-blue-700 hover:bg-blue-600 disabled:opacity-50
                       text-white text-sm rounded font-medium transition-colors"
          >
            {loading ? "Scanning…" : "SYN Scan"}
          </button>
        </div>

        {/* OS Fingerprint */}
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
          <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
            <span className="text-purple-400">◉</span> OS Fingerprint
          </h3>
          <label className="text-gray-500 text-xs mb-1 block">Target IP</label>
          <input
            value={fpIp}
            onChange={(e) => setFpIp(e.target.value)}
            className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-sm
                       text-gray-300 font-mono mb-3 focus:outline-none focus:border-cyan-500"
            placeholder="192.168.56.101"
          />
          <div className="text-gray-600 text-xs mb-3 space-y-0.5">
            <div>• TTL analysis</div>
            <div>• TCP window size</div>
            <div>• Xmas scan probe</div>
          </div>
          <button
            onClick={handleFingerprint}
            disabled={loading || !fpIp}
            className="w-full py-2 bg-purple-700 hover:bg-purple-600 disabled:opacity-50
                       text-white text-sm rounded font-medium transition-colors"
          >
            {loading ? "Probing…" : "Fingerprint OS"}
          </button>
        </div>
      </div>

      {/* Active session banner */}
      {sessionId && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 flex items-center gap-3">
          <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
            ws.status === "connected" ? "bg-green-400 animate-pulse" : "bg-gray-500"
          }`} />
          <div className="flex-1 min-w-0">
            <span className="text-gray-400 text-xs">Active session: </span>
            <span className="text-cyan-400 font-mono text-xs">{sessionId}</span>
          </div>
          <div className="text-gray-500 text-xs">{ws.pps} pkt/s</div>
          <button
            onClick={() => stopThread(threadId)}
            className="px-3 py-1 bg-red-800 hover:bg-red-700 text-red-200 text-xs rounded"
          >
            Stop
          </button>
        </div>
      )}

      {error && (
        <div className="bg-red-900/40 border border-red-700 text-red-300 rounded px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {/* Tab navigation */}
      <div className="border-b border-gray-700">
        <div className="flex gap-1">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === t.id
                  ? "border-cyan-500 text-cyan-400"
                  : "border-transparent text-gray-500 hover:text-gray-300"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab panels */}
      {activeTab === "map"   && <NetworkMap hosts={allHosts} onSelectHost={(h) => setScanIp(h.ip)} />}
      {activeTab === "ports" && <PortMatrix portResults={ws.portResults} />}
      {activeTab === "os"    && <OSFingerprintPanel osResults={ws.osResults} hosts={allHosts} />}
      {activeTab === "pkts"  && (
        <PacketInspector packets={ws.packets} pps={ws.pps} wsStatus={ws.status} />
      )}
    </div>
  );
}
