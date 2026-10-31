// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Panel } from "../ui/primitives.jsx";
import Icon from "../ui/Icon.jsx";

// Purdue-model topology, inferred from real Zeek flows + the asset inventory.
// Zones are the SAME OT/IT/external the rest of the system uses; a red edge is a
// real authorization finding (an unauthorized IT->OT pivot), not a cosmetic line.

const BAND_TONE = {
  "External": "border-edge bg-panel2/40",
  "IT · Enterprise": "border-low/25 bg-low/5",
  "IT · Operations": "border-low/25 bg-low/5",
  "IT/OT DMZ": "border-high/30 bg-high/5",
  "OT · Supervisory": "border-brand/25 bg-brand/5",
  "OT · Control": "border-crit/25 bg-crit/5",
  "OT · Process": "border-crit/25 bg-crit/5",
};
const ZONE_DOT = { OT: "bg-crit", IT: "bg-low", external: "bg-muted" };
const SEV = { critical: "text-crit border-crit/50 bg-crit/10", high: "text-high border-high/50 bg-high/10", medium: "text-warn border-warn/50 bg-warn/10" };
const critTone = (c) => (c === "critical" ? "text-crit" : c === "high" ? "text-high" : "text-muted");

function Stat({ label, value, tone = "" }) {
  return (
    <div className="panel px-3 py-2">
      <div className="text-[10px] uppercase tracking-[0.14em] text-faint">{label}</div>
      <div className={`text-lg font-semibold tabular-nums mt-0.5 ${tone}`}>{value}</div>
    </div>
  );
}

export default function Purdue() {
  const [data, setData] = useState(null);
  const wrapRef = useRef(null);
  const nodeRefs = useRef({});
  const [geom, setGeom] = useState([]);

  useEffect(() => {
    let stop = false;
    const tick = () => fetch("/api/topology").then((r) => r.json()).then((d) => !stop && d.nodes && setData(d)).catch(() => {});
    tick(); const t = setInterval(tick, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  // Anchor SVG edges to the actual rendered node positions (robust to wrapping).
  useLayoutEffect(() => {
    const measure = () => {
      const wrap = wrapRef.current;
      if (!wrap || !data) return;
      const wr = wrap.getBoundingClientRect();
      const center = (id) => {
        const el = nodeRefs.current[id];
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { x: r.left - wr.left + r.width / 2, y: r.top - wr.top + r.height / 2 };
      };
      setGeom((data.edges || []).map((e) => {
        const a = center(e.src), b = center(e.dst);
        return a && b ? { ...e, a, b } : null;
      }).filter(Boolean));
    };
    measure();
    const ro = new ResizeObserver(measure);
    if (wrapRef.current) ro.observe(wrapRef.current);
    window.addEventListener("resize", measure);
    return () => { ro.disconnect(); window.removeEventListener("resize", measure); };
  }, [data]);

  if (!data) return <div className="p-6 text-xs text-muted">Inferring topology from observed flows…</div>;
  if (data.error) return <div className="p-6 text-xs text-crit">Topology unavailable.</div>;

  const s = data.summary || {};
  const bands = (data.bands || []).map((b) => b.band);
  const byBand = Object.fromEntries(bands.map((b) => [b, []]));
  (data.nodes || []).forEach((n) => { (byBand[n.purdue.band] || (byBand[n.purdue.band] = [])).push(n); });
  const vioNodes = new Set();
  (data.edges || []).forEach((e) => { if (e.violation) { vioNodes.add(e.src); vioNodes.add(e.dst); } });

  const edgeStroke = (e) => e.violation ? "rgb(var(--crit))" : e.boundary_crossing ? "rgb(var(--high))" : "rgb(var(--edge2))";
  const path = (a, b) => { const my = (a.y + b.y) / 2; return `M ${a.x} ${a.y} C ${a.x} ${my}, ${b.x} ${my}, ${b.x} ${b.y}`; };

  return (
    <div className="p-2 h-full overflow-auto space-y-2">
      <div className="flex items-center gap-2 px-1">
        <h1 className="text-sm font-semibold text-text">Purdue model · inferred topology</h1>
        <span className="text-2xs text-muted">zones + authorization from the same source detection uses · a red edge is a real finding</span>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-2">
        <Stat label="Assets" value={s.nodes ?? "—"} />
        <Stat label="Observed flows" value={s.edges ?? "—"} />
        <Stat label="Boundary crossings" value={s.boundary_crossings ?? "—"} />
        <Stat label="Violations" value={s.violations ?? "—"} tone={s.violations ? "text-crit" : ""} />
        <Stat label="Unmanaged" value={s.unmanaged ?? "—"} tone={s.unmanaged ? "text-crit" : ""} />
      </div>

      <div className="flex gap-2 items-start">
        {/* layered map */}
        <Panel title="Zone topology" bodyClass="p-3"
          right={
            <div className="flex items-center gap-3 text-2xs text-muted">
              <span className="flex items-center gap-1"><span className="inline-block w-4 h-0.5" style={{ background: "rgb(var(--crit))" }} /> violation</span>
              <span className="flex items-center gap-1"><span className="inline-block w-4 h-0.5 border-t border-dashed" style={{ borderColor: "rgb(var(--high))" }} /> authorized crossing</span>
              <span className="flex items-center gap-1"><span className="inline-block w-4 h-0.5" style={{ background: "rgb(var(--edge2))" }} /> intra-zone</span>
            </div>
          }
          className="flex-1 min-w-0">
          <div ref={wrapRef} className="relative">
            {/* edges under the node chips */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 0 }}>
              <defs>
                <marker id="vio" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                  <path d="M0,0 L6,3 L0,6 Z" fill="rgb(var(--crit))" />
                </marker>
              </defs>
              {geom.map((e, i) => (
                <path key={i} d={path(e.a, e.b)} fill="none" stroke={edgeStroke(e)}
                  strokeWidth={e.violation ? 2 : e.boundary_crossing ? 1.5 : 1}
                  strokeDasharray={e.violation ? "6 4" : e.boundary_crossing ? "4 4" : "0"}
                  markerEnd={e.violation ? "url(#vio)" : undefined}
                  className={e.violation ? "topo-flow" : ""} opacity={e.violation ? 0.95 : e.boundary_crossing ? 0.7 : 0.4} />
              ))}
            </svg>

            <div className="relative space-y-2" style={{ zIndex: 1 }}>
              {bands.filter((b) => (byBand[b] || []).length).map((b) => (
                <div key={b} className={`rounded-md border ${BAND_TONE[b] || "border-edge"} px-2.5 py-2 flex gap-3 items-center`}>
                  <div className="w-32 shrink-0">
                    <div className="text-2xs uppercase tracking-wider text-muted leading-tight">{b}</div>
                  </div>
                  <div className="flex flex-wrap gap-2 flex-1">
                    {byBand[b].map((n) => {
                      const flagged = vioNodes.has(n.id);
                      return (
                        <div key={n.id} ref={(el) => (nodeRefs.current[n.id] = el)}
                          className={`rounded-sm border px-2.5 py-1.5 bg-panel min-w-[120px] ${flagged ? "border-crit/70 shadow-[0_0_0_1px_rgb(var(--crit)/0.4)]" : n.unmanaged ? "border-crit/50" : "border-edge2"}`}>
                          <div className="flex items-center gap-1.5">
                            <span className={`dot ${ZONE_DOT[n.zone] || "bg-muted"}`} />
                            <span className="mono text-xs text-text truncate">{n.id}</span>
                            {flagged && <span className="ml-auto text-2xs text-crit" title="endpoint of an unauthorized flow"><Icon name="bolt" size={11} /></span>}
                          </div>
                          <div className="text-2xs text-faint truncate mt-0.5">{n.device_type || n.role || "—"}</div>
                          <div className="flex items-center gap-1.5 mt-1">
                            <span className="pill text-[9px] text-muted border-edge">{n.purdue.label}</span>
                            {n.unmanaged && <span className="pill text-[9px] text-crit border-crit/50">unmanaged</span>}
                            {n.unzoneable && <span className="pill text-[9px] text-warn border-warn/50">unzoneable</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <style>{`.topo-flow{animation:topodash 0.6s linear infinite}@keyframes topodash{to{stroke-dashoffset:-10}}`}</style>
        </Panel>

        {/* findings */}
        <Panel title={`Topology findings · ${(data.findings || []).length}`} bodyClass="p-2 space-y-1.5" className="w-80 shrink-0">
          {(data.findings || []).length === 0 && <div className="text-2xs text-muted p-3">No boundary violations. Run the attack from the Range Console to surface the IT→OT pivot.</div>}
          {(data.findings || []).map((f, i) => (
            <div key={i} className="rounded-sm border border-edge bg-panel px-2.5 py-2">
              <div className="flex items-center gap-2">
                <span className={`pill text-2xs ${SEV[f.severity] || "text-muted border-edge"}`}>{f.severity}</span>
                <span className="mono text-2xs text-muted">{f.type}</span>
              </div>
              <div className="text-xs text-text mt-1 leading-snug">{f.detail}</div>
            </div>
          ))}
          <div className="text-2xs text-faint leading-snug pt-1">
            Inferred from observed flows; zones and authorization come from the same source detection and access-control use.
            Read-only — no action is taken from this view.
          </div>
        </Panel>
      </div>
    </div>
  );
}
