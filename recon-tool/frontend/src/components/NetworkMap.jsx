/**
 * components/NetworkMap.jsx
 * -------------------------
 * D3.js force-directed graph showing discovered hosts as nodes.
 * Color-coded by OS guess. Clicking a node selects it.
 */
import React, { useEffect, useRef } from "react";
import * as d3 from "d3";

const OS_COLORS = {
  windows: "var(--color-os-windows)",
  linux: "var(--color-os-linux)",
  macos: "var(--color-os-macos)",
  unknown: "var(--color-os-unknown)",
};

const RISK_COLORS = {
  critical: "var(--color-threat-critical)",
  high: "var(--color-threat-high)",
  medium: "var(--color-threat-medium)",
  low: "var(--color-threat-low)",
};

const RISK_CLASSES = {
  critical: "bg-red-600 ring-2 ring-red-500 glow-red",
  high: "bg-orange-500 ring-2 ring-orange-400 glow-orange",
  medium: "bg-yellow-400 ring-2 ring-yellow-300",
  low: "bg-green-500 ring-2 ring-green-400",
};

function normalizeOsLabel(value) {
  const label = String(value || "").trim();
  return label || "unknown";
}

function getColor(os) {
  const value = String(os || "").toLowerCase();
  if (value.includes("linux") || value.includes("ubuntu") || value.includes("debian") || value.includes("kali") || value.includes("centos") || value.includes("fedora") || value.includes("red hat") || value.includes("rhel")) {
    return OS_COLORS.linux;
  }
  if (value.includes("windows") || value.includes("win") || value.includes("microsoft")) return OS_COLORS.windows;
  if (value.includes("macos") || value.includes("os x") || value.includes("darwin") || value.includes("apple") || value.includes("mac")) return OS_COLORS.macos;
  return OS_COLORS.unknown;
}

function normalizeRiskLevel(value) {
  const level = String(value || "").toLowerCase();
  if (level === "critical" || level === "high" || level === "medium" || level === "low") return level;
  return "low";
}

function riskClassFor(level) {
  return RISK_CLASSES[normalizeRiskLevel(level)] || RISK_CLASSES.low;
}

function riskColorFor(level, fallback) {
  return RISK_COLORS[normalizeRiskLevel(level)] || fallback;
}

export default function NetworkMap({ hosts = [], riskScores = {}, onSelectHost, maxHosts = 200, selectedHostId = null }) {
  const svgRef = useRef(null);
  const tooltipRef = useRef(null);
  const zoomInRef = useRef(null);
  const zoomOutRef = useRef(null);
  const zoomResetRef = useRef(null);
  const positionRef = useRef(new Map());

  useEffect(() => {
    if (!svgRef.current) return;

    const selectedId = selectedHostId || null;
    const root = d3.select(svgRef.current);

    root.selectAll("g[data-node-id]").each(function () {
      const nodeGroup = d3.select(this);
      const nodeIp = nodeGroup.attr("data-node-ip");
      const isSelected = selectedId && nodeIp === selectedId;

      nodeGroup.select("circle.node-ring")
        .attr("opacity", isSelected ? 0.3 : 0)
        .style("animation", "none");

      nodeGroup.select("circle.node-core")
        .attr("r", isSelected ? 24 : 20);
    });
  }, [selectedHostId]);

  useEffect(() => {
    if (!svgRef.current) return;
    const width = svgRef.current.clientWidth || 800;
    const height = svgRef.current.clientHeight || 500;

    // Clear previous render
    d3.select(svgRef.current).selectAll("*").remove();

    const svg = d3.select(svgRef.current)
      .attr("width", width)
      .attr("height", height);

    // Add zoom support
    const g = svg.append("g");
    const zoom = d3.zoom().scaleExtent([0.3, 3]).on("zoom", (e) => {
      g.attr("transform", e.transform);
    });
    svg.call(zoom);

    // Build nodes from endpoint list (allow multiple nodes per IP when agent_id differs).
    const uniqueHosts = [];
    const seenKey = new Set();
    hosts.forEach((host, index) => {
      const ip = String(host?.ip || "").trim();
      if (!ip) return;
      const agentKey = String(host?.agent_id || host?.hostname || index);
      const key = `${ip}|${agentKey}`;
      if (seenKey.has(key)) return;
      seenKey.add(key);
      uniqueHosts.push({ ...host, ip, _nodeKey: key });
    });

    const trimmedHosts = uniqueHosts.slice(0, maxHosts);
    const nodes = trimmedHosts.map((h) => {
      const nodeKey = h._nodeKey || h.ip;
      const riskInfo = riskScores?.[h.ip] || null;
      const riskLevel = normalizeRiskLevel(riskInfo?.level);
      const osLabel = normalizeOsLabel(h.os_guess || h.os_name || h.os);
      const previous = positionRef.current.get(nodeKey) || {};
      return {
        ...h,
        id: nodeKey,
        label: h.hostname || h.ip,
        ip: h.ip,
        mac: h.mac,
        os: osLabel,
        risk_level: riskLevel,
        risk_ports: Number(riskInfo?.riskyPortsCount) || 0,
        risk_vulns: Number(riskInfo?.vulnCount) || 0,
        type: "host",
        x: previous.x,
        y: previous.y,
        vx: previous.vx,
        vy: previous.vy,
      };
    });

    // Create links between all nodes to show network connectivity
    const links = [];
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        links.push({
          source: nodes[i].id,
          target: nodes[j].id,
        });
      }
    }

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
      .force("link",    d3.forceLink(links).id((d) => d.id).distance(120))
      .force("charge",  d3.forceManyBody().strength(-160))
      .force("center",  d3.forceCenter(width / 2, height / 2))
      .force("collide", d3.forceCollide(56))
      .alphaDecay(0.26)
      .velocityDecay(0.72);

    // Draw edges
    const link = g.append("g")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", "rgba(255,255,255,0.08)")
      .attr("stroke-width", 1)
      .attr("stroke-dasharray", "4 4");

    // Draw node groups
    const node = g.append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .attr("cursor", "pointer")
      .call(d3.drag()
        .on("start", (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag",  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on("end",   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on("click", (e, d) => {
        if (onSelectHost) onSelectHost(d);
      })
      .on("mouseover", (e, d) => {
        if (!tooltipRef.current || d.type !== "host") return;

        const openPorts = Array.isArray(d.open_ports) ? d.open_ports.length : (Number(d.open_ports) || 0);
        const riskLevel = normalizeRiskLevel(d.risk_level);
        const riskPorts = Number(d.risk_ports) || 0;
        const riskVulns = Number(d.risk_vulns) || 0;
        tooltipRef.current.innerHTML = `
          <div class="font-mono text-sm font-bold text-text-primary">${d.ip || d.label}</div>
          <div class="mt-1 font-mono text-xs text-text-tertiary">${d.mac || "N/A"}</div>
          <div class="mt-1 text-sm text-text-secondary">${d.hostname || "unknown-host"}</div>
          <div class="mt-1 text-sm text-text-secondary">${d.os || "unknown"}</div>
          <div class="text-sm text-text-tertiary">open ports: ${openPorts}</div>
          <div class="text-sm text-text-tertiary">Risk: ${riskLevel} | Ports: ${riskPorts} | Vulns: ${riskVulns}</div>
        `;
        tooltipRef.current.style.opacity = "1";
      })
      .on("mousemove", (e) => {
        if (!tooltipRef.current || !svgRef.current) return;
        const rect = svgRef.current.getBoundingClientRect();
        tooltipRef.current.style.left = `${e.clientX - rect.left + 12}px`;
        tooltipRef.current.style.top = `${e.clientY - rect.top + 12}px`;
      })
      .on("mouseout", () => {
        if (!tooltipRef.current) return;
        tooltipRef.current.style.opacity = "0";
      });

    node.attr("data-node-id", (d) => d.id);
    node.attr("data-node-ip", (d) => d.ip || d.id);

    node.append("circle")
      .attr("class", "node-ring")
      .attr("r", 32)
      .attr("fill", "none")
      .attr("stroke", (d) => (d.type === "scanner" ? "var(--color-accent-primary)" : getColor(d.os)))
      .attr("stroke-width", 1.5)
      .attr("opacity", (d) => (selectedHostId && d.ip === selectedHostId ? 0.3 : 0))
      .style("animation", "none");

    // Circles
    node.append("circle")
      .attr("class", "node-core")
      .attr("r", (d) => (selectedHostId && d.ip === selectedHostId ? 24 : 20))
      .attr("fill", (d) => (d.type === "scanner" ? "var(--color-accent-primary)" : getColor(d.os)))
      .attr("stroke", (d) => riskColorFor(d.risk_level, "rgba(255,255,255,0.25)"))
      .attr("stroke-width", 2);

    // Icons / labels inside circle
    node.append("text")
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central")
      .attr("font-size", "10px")
      .attr("fill", "#fff")
      .attr("font-weight", "bold")
      .text((d) => String(d.ip || d.label || "?").split(".").pop());

    // Label below circle
    node.append("text")
      .attr("y", 34)
      .attr("text-anchor", "middle")
      .attr("font-family", "JetBrains Mono, Fira Code, monospace")
      .attr("font-size", "11px")
      .attr("fill", "rgba(255,255,255,0.9)")
      .text((d) => d.ip || d.label);

    // OS sub-label
    node.append("text")
      .attr("y", 48)
      .attr("text-anchor", "middle")
      .attr("font-size", "9px")
      .attr("fill", "rgba(255,255,255,0.5)")
      .text((d) => d.os);

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);

      nodes.forEach((n) => {
        positionRef.current.set(n.id, { x: n.x, y: n.y, vx: n.vx, vy: n.vy });
      });
    });

    if (zoomInRef.current) {
      d3.select(zoomInRef.current).on("click", () => {
        svg.transition().duration(150).call(zoom.scaleBy, 1.2);
      });
    }
    if (zoomOutRef.current) {
      d3.select(zoomOutRef.current).on("click", () => {
        svg.transition().duration(150).call(zoom.scaleBy, 0.8);
      });
    }
    if (zoomResetRef.current) {
      d3.select(zoomResetRef.current).on("click", () => {
        svg.transition().duration(150).call(zoom.transform, d3.zoomIdentity);
      });
    }

    return () => {
      simulation.stop();
      if (zoomInRef.current) d3.select(zoomInRef.current).on("click", null);
      if (zoomOutRef.current) d3.select(zoomOutRef.current).on("click", null);
      if (zoomResetRef.current) d3.select(zoomResetRef.current).on("click", null);
    };
  }, [hosts, maxHosts, onSelectHost, riskScores]);

  return (
    <div className="relative flex h-full w-full flex-col overflow-hidden rounded-lg bg-bg-app">
      <svg ref={svgRef} className="h-full w-full flex-1" style={{ minHeight: 400 }} />

      <div
        ref={tooltipRef}
        className="pointer-events-none absolute z-50 rounded-lg border border-border-elevated bg-bg-elevated p-3 text-sm shadow-card transition-opacity duration-150"
        style={{ opacity: 0 }}
      />

      <div className="absolute bottom-20 right-4 z-20 rounded-md border border-border-elevated bg-bg-elevated/80 p-2 backdrop-blur">
        <div className="flex items-center gap-2 text-xs text-text-secondary">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: OS_COLORS.linux }} />
          Linux
        </div>
        <div className="mt-1 flex items-center gap-2 text-xs text-text-secondary">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: OS_COLORS.windows }} />
          Windows
        </div>
        <div className="mt-1 flex items-center gap-2 text-xs text-text-secondary">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: OS_COLORS.macos }} />
          macOS
        </div>
        <div className="mt-1 flex items-center gap-2 text-xs text-text-secondary">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: OS_COLORS.unknown }} />
          unknown
        </div>
      </div>

      <div className="border-t border-border-elevated/60 bg-bg-elevated/60 px-4 py-3">
        <div className="flex flex-wrap items-center gap-3 text-xs text-text-secondary">
          <span className="text-text-tertiary">Risk legend:</span>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-red-600 ring-2 ring-red-500 glow-red" />
            Critical
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-orange-500 ring-2 ring-orange-400 glow-orange" />
            High
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-yellow-400 ring-2 ring-yellow-300" />
            Medium
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-green-500 ring-2 ring-green-400" />
            Low
          </div>
        </div>
      </div>

      <div className="absolute right-4 top-4 z-20 flex flex-col gap-2">
        <button
          ref={zoomInRef}
          type="button"
          className="flex h-8 w-8 items-center justify-center rounded-md border border-border-default bg-bg-elevated text-text-secondary transition-colors duration-150 hover:bg-bg-card-hover hover:text-text-primary"
        >
          +
        </button>
        <button
          ref={zoomOutRef}
          type="button"
          className="flex h-8 w-8 items-center justify-center rounded-md border border-border-default bg-bg-elevated text-text-secondary transition-colors duration-150 hover:bg-bg-card-hover hover:text-text-primary"
        >
          -
        </button>
        <button
          ref={zoomResetRef}
          type="button"
          className="flex h-8 w-8 items-center justify-center rounded-md border border-border-default bg-bg-elevated text-text-secondary transition-colors duration-150 hover:bg-bg-card-hover hover:text-text-primary"
        >
          ⊕
        </button>
      </div>
    </div>
  );
}
