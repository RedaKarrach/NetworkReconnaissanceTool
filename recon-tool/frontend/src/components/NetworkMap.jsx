/**
 * components/NetworkMap.jsx
 * -------------------------
 * D3.js force-directed graph showing discovered hosts as nodes.
 * Color-coded by OS guess. Clicking a node selects it.
 */
import React, { useEffect, useRef, useState } from "react";
import * as d3 from "d3";

const OS_COLORS = {
  windows: "var(--color-os-windows)",
  linux: "var(--color-os-linux)",
  macos: "var(--color-os-macos)",
  unknown: "var(--color-os-unknown)",
};

function getColor(os) {
  const value = String(os || "").toLowerCase();
  if (value.includes("linux")) return OS_COLORS.linux;
  if (value.includes("windows")) return OS_COLORS.windows;
  if (value.includes("mac")) return OS_COLORS.macos;
  return OS_COLORS.unknown;
}

export default function NetworkMap({ hosts = [], onSelectHost, maxHosts = 200 }) {
  const svgRef = useRef(null);
  const tooltipRef = useRef(null);
  const zoomInRef = useRef(null);
  const zoomOutRef = useRef(null);
  const zoomResetRef = useRef(null);
  const [selected, setSelected] = useState(null);

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

    // Build nodes: scanner at center + discovered hosts
    const trimmedHosts = hosts.slice(0, maxHosts);
    const nodes = [
      { id: "scanner", label: "Scanner", os: "scanner", type: "scanner" },
      ...trimmedHosts.map((h) => ({
        id:    h.ip,
        label: h.ip,
        mac:   h.mac,
        os:    h.os_guess || "unknown",
        type:  "host",
      })),
    ];

    const links = trimmedHosts.map((h) => ({
      source: "scanner",
      target: h.ip,
    }));

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
      .force("link",    d3.forceLink(links).id((d) => d.id).distance(120))
      .force("charge",  d3.forceManyBody().strength(-300))
      .force("center",  d3.forceCenter(width / 2, height / 2))
      .force("collide", d3.forceCollide(45));

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
        setSelected(d.id);
        if (onSelectHost) onSelectHost(d);
      })
      .on("mouseover", (e, d) => {
        if (!tooltipRef.current || d.type !== "host") return;

        const openPorts = Array.isArray(d.open_ports) ? d.open_ports.length : (Number(d.open_ports) || 0);
        tooltipRef.current.innerHTML = `
          <div class="font-mono text-sm font-bold text-text-primary">${d.label}</div>
          <div class="mt-1 font-mono text-xs text-text-tertiary">${d.mac || "N/A"}</div>
          <div class="mt-1 text-sm text-text-secondary">${d.os || "unknown"}</div>
          <div class="text-sm text-text-tertiary">open ports: ${openPorts}</div>
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

    node.append("circle")
      .attr("r", 32)
      .attr("fill", "none")
      .attr("stroke", (d) => (d.type === "scanner" ? "var(--color-accent-primary)" : getColor(d.os)))
      .attr("stroke-width", 1.5)
      .attr("opacity", (d) => (d.id === selected ? 0.3 : 0))
      .style("animation", (d) => (d.id === selected ? "pulse-critical 2s ease-in-out infinite" : "none"));

    // Circles
    node.append("circle")
      .attr("r", (d) => (d.id === selected ? 26 : 20))
      .attr("fill", (d) => (d.type === "scanner" ? "var(--color-accent-primary)" : getColor(d.os)))
      .attr("stroke", "rgba(255,255,255,0.15)")
      .attr("stroke-width", 1.5);

    // Icons / labels inside circle
    node.append("text")
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central")
      .attr("font-size", "10px")
      .attr("fill", "#fff")
      .attr("font-weight", "bold")
      .text((d) => d.type === "scanner" ? "◎" : d.label.split(".").pop());

    // Label below circle
    node.append("text")
      .attr("y", 34)
      .attr("text-anchor", "middle")
      .attr("font-family", "JetBrains Mono, Fira Code, monospace")
      .attr("font-size", "11px")
      .attr("fill", "rgba(255,255,255,0.9)")
      .text((d) => d.label);

    // OS sub-label
    node.filter((d) => d.type === "host")
      .append("text")
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
  }, [hosts, maxHosts, onSelectHost, selected]);

  return (
    <div className="relative h-full w-full overflow-hidden rounded-lg bg-bg-app">
      <svg ref={svgRef} className="h-full w-full" style={{ minHeight: 400 }} />

      <div
        ref={tooltipRef}
        className="pointer-events-none absolute z-50 rounded-lg border border-border-elevated bg-bg-elevated p-3 text-sm shadow-card transition-opacity duration-150"
        style={{ opacity: 0 }}
      />

      <div className="absolute bottom-4 right-4 rounded-md border border-border-elevated bg-bg-elevated/80 p-2 backdrop-blur">
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

      <div className="absolute right-4 top-4 flex flex-col gap-2">
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
