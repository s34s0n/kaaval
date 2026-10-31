// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { PRODUCT_NAME } from "../config";
import { useRange } from "./rangeStore.js";

// Attack stages are protocol-generic (IT pivot + OT writes) — same for any plant.
const STAGES = [
  ["initial_access", "SSH access", "T0822"],
  ["c2_beacon", "C2 beacon", "T0869"],
  ["discovery", "OT scan", "T0846"],
  ["boundary_recon", "OPC UA browse", "T0888"],
  ["impact", "S7 write", "T0855/T0836/T0831"],
];

function tone(v, hi, danger, interlock) {
  if (danger != null && v >= danger) return "#ff4d4f";
  if (!interlock) return "#ff4d4f";
  if (hi != null && v > hi) return "#e6c84b";
  return "#22c55e";
}

function fmt(state, t) {
  const v = state?.[t.tag];
  if (v == null) return "—";
  if (t.kind === "bool") return v ? "ON" : "OFF";
  return typeof v === "number" ? v.toFixed(t.unit === "bar" || t.unit === "°C" ? 1 : 0) : String(v);
}

function Box({ label, value, sub, color }) {
  return (
    <div className="border border-edge2 bg-panel2 px-3 py-2" style={color ? { borderColor: color } : undefined}>
      <div className="text-2xs uppercase tracking-wider text-muted">{label}</div>
      <div className="text-lg leading-tight mt-0.5" style={color ? { color } : undefined}>{value}</div>
      {sub && <div className="text-2xs text-muted mt-0.5">{sub}</div>}
    </div>
  );
}

export default function RangeApp() {
  const r = useRange();
  const s = r.state;
  const prof = r.profile;
  const sa = prof?.safety || {};
  const pv = prof?.process_view || {};
  const [sp, setSp] = useState(80);
  const [lsp, setLsp] = useState(50);

  const sv = sa.variable;                              // safety variable tag
  const val = (s && sv) ? (s[sv] ?? 0) : 0;
  const [bandLo, bandHi] = sa.band || [];
  const danger = sa.danger;
  const interlock = (s && sa.interlock_tag) ? (s[sa.interlock_tag] ?? true) : true;
  const c = tone(val, bandHi, danger, interlock);
  const scale = danger ? danger * 1.15 : 15;
  const viewTags = (pv.tags || []).filter((t) => t.tag !== sv).slice(0, 4);

  return (
    <div className="h-full bg-bg text-text flex flex-col font-mono">
      <header className="h-10 shrink-0 border-b border-edge2 flex items-center px-4 gap-3 bg-panel">
        <span className="text-sm font-semibold tracking-wide">RANGE CONSOLE</span>
        <span className="text-2xs text-muted">cyber-physical test environment · {PRODUCT_NAME} demo</span>
        <span className="ml-3 text-2xs text-accent">{prof?.name || "—"}</span>
        <span className={`ml-auto text-2xs ${r.connected ? "text-ok" : "text-muted"}`}>{r.connected ? "● live" : "○ offline"}</span>
        <a href="/" className="text-2xs text-accent hover:underline ml-3">→ Kaaval SOC</a>
      </header>

      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-2 gap-3 p-3 overflow-auto">
        {/* Process schematic — driven by the active profile */}
        <section className="border border-edge2 p-3">
          <div className="text-2xs uppercase tracking-wider text-muted mb-3">Process · {pv.title || prof?.name || "plant"}</div>
          <div className="grid grid-cols-4 gap-2">
            {viewTags.map((t) => (
              <Box key={t.tag} label={t.label || t.tag}
                value={`${fmt(s, t)}${t.kind === "bool" ? "" : (t.unit ? ` ${t.unit}` : "")}`} />
            ))}
            <Box label={sa.label || sv || "Process"}
              value={`${val.toFixed(1)}${sa.unit ? ` ${sa.unit}` : ""}`}
              sub={bandHi != null ? `band ${bandLo}–${bandHi} · danger ${danger}` : ""} color={c} />
          </div>
          <div className="mt-3 flex items-center gap-2 text-xs">
            <span className="dot" style={{ background: interlock ? "#22c55e" : "#ff4d4f" }} />
            interlock {interlock ? "ARMED" : "DISABLED"}
            <span className="ml-4 text-muted">{s?.status ? `status: ${s.status}` : ""}</span>
          </div>
          <div className="mt-3 h-2.5 bg-panel2 border border-edge2">
            <div className="h-full transition-all duration-300" style={{ width: `${Math.min(100, (val / scale) * 100)}%`, background: c }} />
          </div>
          <div className="text-2xs text-muted mt-1">
            live {sa.label?.toLowerCase() || "process"} vs {scale.toFixed(0)} {sa.unit || ""} scale
            {danger != null && val >= danger && <span className="text-crit"> · ⚠ DANGER</span>}
          </div>

          <div className="mt-4 text-2xs uppercase tracking-wider text-muted mb-1">Operator action log</div>
          <div className="text-2xs text-muted space-y-0.5 max-h-28 overflow-auto">
            {r.log.length === 0 && <div>—</div>}
            {r.log.map((l, i) => (
              <div key={i} className={l.tone === "err" ? "text-crit" : l.tone === "ok" ? "text-ok" : ""}>
                <span className="text-edge2">{l.t}</span> {l.msg}
              </div>
            ))}
          </div>
        </section>

        {/* Attack panel */}
        <section className="border border-edge2 p-3">
          <div className="text-2xs uppercase tracking-wider text-muted mb-3">Attack campaigns · each forms its own incident</div>
          <div className="grid gap-1.5 mb-3">
            {(r.scenarios?.length ? r.scenarios : [{ name: "full_chain", label: "Full IT→OT chain", summary: "" }]).map((sc) => {
              const crit = sc.name === "full_chain" || sc.name === "ot_tamper";
              return (
                <button key={sc.name} onClick={() => r.scenario(sc.name, sc.label || sc.name)}
                  className={`w-full text-left border px-2 py-1.5 hover:bg-panel2 ${crit ? "border-crit/60" : "border-edge2"}`}>
                  <div className={`text-xs font-semibold ${crit ? "text-crit" : "text-text"}`}>▶ {sc.label || sc.name}</div>
                  {sc.summary && <div className="text-2xs text-muted mt-0.5 leading-snug">{sc.summary}</div>}
                </button>
              );
            })}
          </div>
          <div className="text-2xs uppercase tracking-wider text-muted mb-1.5">Granular stages (no new incident)</div>
          <div className="grid gap-1.5">
            {STAGES.map(([name, label, atk], i) => (
              <button key={name} onClick={() => r.stage(name, label)}
                className="flex items-center justify-between border border-edge2 px-2 h-8 text-xs hover:bg-panel2">
                <span>{i + 1}. {label}</span><span className="text-muted">{atk}</span>
              </button>
            ))}
          </div>
        </section>

        {/* Dual-path manual control */}
        <section className="border border-edge2 p-3 lg:col-span-2">
          <div className="text-2xs uppercase tracking-wider text-muted mb-3">Manual control · same effect, two paths</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {/* Malicious */}
            <div className="border border-crit/40 p-3">
              <div className="text-xs font-semibold text-crit mb-2">MALICIOUS · direct register write (ews → PLC, unauthorized)</div>
              {s?.ews_isolated && (
                <div className="text-2xs text-warn border border-warn/40 bg-warn/10 px-2 py-1.5 mb-2">
                  ⚠ ews is ISOLATED — IT containment is active, so these writes are blackholed and raise no incident. Reset to restore the path.
                </div>
              )}
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <input type="number" value={sp} onChange={(e) => setSp(+e.target.value)}
                  className="w-16 bg-panel2 border border-edge2 h-7 px-1 text-center" />
                <button onClick={() => r.malicious("setpoint", sp, `setpoint ${sp}`)} className="border border-edge2 px-2 h-7 hover:bg-panel2">set control</button>
                <button onClick={() => r.malicious("unsafe", null, "force unsafe")} className="border border-edge2 px-2 h-7 hover:bg-panel2">force unsafe</button>
                <button onClick={() => r.malicious("interlock", "off", "disable interlock")} className="border border-edge2 px-2 h-7 hover:bg-panel2">disable interlock</button>
              </div>
              <div className="text-2xs text-crit/90 mt-2">Crosses the ews → captured by the sensor. Kaaval MUST catch this.</div>
            </div>
            {/* Legitimate */}
            <div className="border border-ok/40 p-3">
              <div className="text-xs font-semibold text-ok mb-2">LEGITIMATE · operator setpoint via gateway (authorized)</div>
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <input type="number" value={lsp} onChange={(e) => setLsp(+e.target.value)}
                  className="w-16 bg-panel2 border border-edge2 h-7 px-1 text-center" />
                <button onClick={() => r.legitimate(lsp)} className="border border-edge2 px-2 h-7 hover:bg-panel2">set setpoint via HMI</button>
              </div>
              <div className="text-2xs text-ok/90 mt-2">Goes operator → gateway (OPC UA), never the ews. Kaaval must NOT alert.</div>
            </div>
          </div>
          <button onClick={r.reset} className="mt-3 h-8 px-3 border border-edge2 text-xs hover:bg-panel2">↺ Reset to clean baseline</button>
        </section>
      </div>
    </div>
  );
}
