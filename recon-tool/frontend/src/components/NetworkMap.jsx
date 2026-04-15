/**
 * components/NetworkMap.jsx
 * -------------------------
 * D3.js force-directed graph showing discovered hosts as nodes.
 * Color-coded by OS guess. Clicking a node selects it.
 */
import React, { useEffect, useRef, useState } from "react";
import * as d3 from "d3";

const OS_COLORS = {
  Windows:    "#3b82f6",
  Linux:      "#22c55e",
  macOS:      "#a855f7",
  "Cisco/BSD":"#f97316",
  unknown:    "#6b7280",
};

function getColor(os) {
  for (const key of Object.keys(OS_COLORS)) {
    if (os && os.includes(key)) return OS_COLORS[key];
  }
  return OS_COLORS.unknown;
}

export default function NetworkMap({ hosts = [], onSelectHost }) {
  const svgRef    = useRef(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (!svgRef.current) return;
    const width  = svgRef.current.clientWidth  || 800;
    const height = svgRef.current.clientHeight || 500;

    // Clear previous render
    d3.select(svgRef.current).selectAll("*").remove();

    const svg = d3.select(svgRef.current)
      .attr("width", width)
      .attr("height", height);

    // Add zoom support
    const g = svg.append("g");
    svg.call(d3.zoom().scaleExtent([0.3, 3]).on("zoom", (e) => {
      g.attr("transform", e.transform);
    }));

    // Build nodes: scanner at center + discovered hosts
    const nodes = [
      { id: "scanner", label: "Scanner", os: "scanner", type: "scanner" },
      ...hosts.map((h) => ({
        id:    h.ip,
        label: h.ip,
        mac:   h.mac,
        os:    h.os_guess || "unknown",
        type:  "host",
      })),
    ];

    const links = hosts.map((h) => ({
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
      .attr("stroke", "#374151")
      .attr("stroke-width", 1.5)
      .attr("stroke-dasharray", "4 2");

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
      });

    // Circles
    node.append("circle")
      .attr("r", (d) => d.type === "scanner" ? 22 : 18)
      .attr("fill", (d) => d.type === "scanner" ? "#1d4ed8" : getColor(d.os))
      .attr("stroke", "#fff")
      .attr("stroke-width", 2)
      .attr("opacity", 0.9);

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
      .attr("y", 28)
      .attr("text-anchor", "middle")
      .attr("font-size", "11px")
      .attr("fill", "#d1d5db")
      .text((d) => d.label);

    // OS sub-label
    node.filter((d) => d.type === "host")
      .append("text")
      .attr("y", 40)
      .attr("text-anchor", "middle")
      .attr("font-size", "9px")
      .attr("fill", "#9ca3af")
      .text((d) => d.os);

    // Tooltip
    node.append("title")
      .text((d) => `IP: ${d.label}\nMAC: ${d.mac || "?"}\nOS: ${d.os}`);

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    return () => simulation.stop();
  }, [hosts]);

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700 p-4 h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-white font-semibold text-sm tracking-wide uppercase">Network Map</h2>
        <div className="flex gap-3">
          {Object.entries(OS_COLORS).map(([os, color]) => (
            <span key={os} className="flex items-center gap-1 text-xs text-gray-400">
              <span className="w-2 h-2 rounded-full inline-block" style={{ background: color }} />
              {os}
            </span>
          ))}
        </div>
      </div>
      <div className="flex-1 relative">
        {hosts.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center text-gray-600 text-sm">
            No hosts discovered yet — run a host discovery scan
          </div>
        )}
        <svg ref={svgRef} className="w-full h-full" style={{ minHeight: 400 }} />
      </div>
    </div>
  );
}
