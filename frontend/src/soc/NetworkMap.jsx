// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

// Network topology on Cytoscape.js. Compound zone containers (External → IT → OT),
// orthogonal "taxi" edge routing, labeled node chips. Edges are live Zeek
// conversations (red dashed = unauthorized OT). External/unmanaged hosts are shown
// by IP (a real SOC sees an unknown external IP, not a node labelled "attacker").

const DOMAIN = { external: "--high", IT: "--low", OT: "--crit" };
const ZONE_LABEL = { external: "EXTERNAL", IT: "IT NETWORK", OT: "OT · CONTROL" };
const COLS = { external: 0, IT: 380, OT: 760 };
const ROW = 118;
// CSS vars hold space-separated RGB channels ("245 165 36"); Cytoscape's color
// parser needs comma form — rgb(245,165,36).
const cssvar = (v) => {
  const raw = (getComputedStyle(document.documentElement).getPropertyValue(v).trim() || "120 120 120").split(/\s+/).join(",");
  return `rgb(${raw})`;
};

function buildElements(assets, edges, selected) {
  const byZone = { external: [], IT: [], OT: [] };
  assets.forEach((a) => (byZone[a.domain] || byZone.external).push(a));
  const present = new Set(assets.map((a) => a.name));
  const anom = new Set();
  edges.forEach((e) => { if (e.anomalous) { anom.add(e.src); anom.add(e.dst); } });

  const els = [];
  ["external", "IT", "OT"].forEach((dom) => {
    if (!byZone[dom].length) return;
    els.push({ data: { id: `z-${dom}`, label: ZONE_LABEL[dom], kind: "zone", dom } });
    byZone[dom].forEach((a, i) => {
      const y = (i - (byZone[dom].length - 1) / 2) * ROW;
      const ip = a.ips?.[0] || "";
      const ext = dom === "external";
      const label = ext ? `${ip || a.name}\nexternal` : `${a.name}${ip ? `\n${ip}` : ""}`;
      els.push({
        data: {
          id: a.name, parent: `z-${dom}`, kind: "asset", dom, label,
          anom: anom.has(a.name), auth: !!a.authorized_ot, sel: selected === a.name,
          crit: a.criticality === "critical",
        },
        position: { x: COLS[dom], y },
      });
    });
  });
  const maxB = Math.max(1, ...edges.map((e) => e.bytes || 0));
  edges.filter((e) => present.has(e.src) && present.has(e.dst)).forEach((e, i) => {
    els.push({ data: { id: `e${i}`, source: e.src, target: e.dst, anom: !!e.anomalous, w: e.anomalous ? 2 : 1 + (e.bytes / maxB) * 3 } });
  });
  return els;
}

function buildStyle() {
  const text = cssvar("--text"), crit = cssvar("--crit"), brand = cssvar("--brand");
  const COL = { external: cssvar("--high"), IT: cssvar("--low"), OT: cssvar("--crit") };
  const s = [
    { selector: 'node[kind="zone"]', style: {
      shape: "round-rectangle", "background-opacity": 0.05, "border-width": 1, "border-opacity": 0.3,
      label: "data(label)", "text-valign": "top", "text-halign": "center", "text-margin-y": 4,
      "font-size": 10, "font-family": "JetBrains Mono", "text-transform": "uppercase", padding: "30px", "z-index": 1,
    } },
    { selector: 'node[kind="asset"]', style: {
      shape: "round-rectangle", width: "label", height: "label", padding: "9px",
      "background-opacity": 0.18, "border-width": 1.6,
      label: "data(label)", "text-wrap": "wrap", "text-valign": "center", "text-halign": "center",
      color: text, "font-size": 10, "font-family": "JetBrains Mono", "line-height": 1.35, "z-index": 10,
    } },
    // edges: teal by default, red dashed for unauthorized OT flows.
    { selector: "edge", style: {
      "curve-style": "taxi", "taxi-direction": "rightward", "taxi-turn": "45%", "taxi-turn-min-distance": "14px",
      width: "data(w)", "line-color": brand, "line-opacity": 0.5,
      "target-arrow-shape": "triangle", "target-arrow-color": brand, "arrow-scale": 0.85, "z-index": 5,
    } },
    { selector: "edge[?anom]", style: {
      "line-color": crit, "target-arrow-color": crit, "line-opacity": 0.9, "line-style": "dashed", "line-dash-pattern": [6, 4],
    } },
  ];
  // concrete per-domain colors (function mappers don't take in this build).
  for (const d of ["external", "IT", "OT"]) {
    s.push({ selector: `node[dom="${d}"]`, style: { "background-color": COL[d], "border-color": COL[d] } });
    s.push({ selector: `node[kind="zone"][dom="${d}"]`, style: { color: COL[d] } });
  }
  // state styles last so they win over the domain colors.
  s.push({ selector: 'node[?auth]', style: { "background-opacity": 0.34, "border-width": 2.2 } });
  s.push({ selector: 'node[?anom]', style: { "border-color": crit, "overlay-color": crit, "overlay-opacity": 0.1, "overlay-padding": 5 } });
  s.push({ selector: 'node[?sel]', style: { "border-color": brand, "border-width": 2.6, "overlay-color": brand, "overlay-opacity": 0.16, "overlay-padding": 6 } });
  return s;
}

export default function NetworkMap({ assets = [], edges = [], onSelect, selected, height = 480 }) {
  const ref = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    const cy = cytoscape({
      container: ref.current, elements: [], style: buildStyle(),
      minZoom: 0.25, maxZoom: 2.6, wheelSensitivity: 0.2,
      boxSelectionEnabled: false, autounselectify: true,
    });
    cyRef.current = cy;
    cy.on("tap", 'node[kind="asset"]', (e) => onSelect?.(e.target.id()));
    cy.on("tap", (e) => { if (e.target === cy) onSelect?.(null); });
    return () => cy.destroy();
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps

  // Rebuild elements/layout when data or selection changes.
  useEffect(() => {
    const cy = cyRef.current; if (!cy) return;
    cy.elements().remove();
    cy.add(buildElements(assets, edges, selected));
    cy.style(buildStyle());
    cy.layout({ name: "preset", fit: false }).run();
    cy.fit(undefined, 36);
  }, [assets, edges, selected]);

  // Restyle + refit on theme change (CSS vars change).
  useEffect(() => {
    const obs = new MutationObserver(() => { const cy = cyRef.current; if (cy) { cy.style(buildStyle()); } });
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => obs.disconnect();
  }, []);

  return <div ref={ref} style={{ height }} className="rounded-md overflow-hidden border border-edge bg-bg/30" />;
}
