// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { Panel, SeverityTag } from "../ui/primitives.jsx";
import { useSoc } from "./store.jsx";
import RuleSlideOver from "./RuleSlideOver.jsx";

// ATT&CK ICS techniques we track coverage against.
const COVERAGE_TECH = [
  ["T0822", "External Remote Services"], ["T0869", "App Layer Protocol"],
  ["T0846", "Remote System Discovery"], ["T0888", "Remote System Info Disc."],
  ["T0855", "Unauthorized Cmd Msg"], ["T0836", "Modify Parameter"],
  ["T0831", "Manipulation of Control"],
];

export default function Detections() {
  const { capabilities, rules, toggleRule, deleteRule } = useSoc();
  const [slide, setSlide] = useState(false);

  const covered = new Set(rules.filter((r) => r.enabled).flatMap((r) => r.attack || []));

  return (
    <div className="p-2 h-full grid grid-rows-[auto_auto_1fr] gap-2">
      <Panel title="Capabilities · loaded analyzers / parsers">
        <div className="p-3 flex flex-wrap gap-2 text-xs">
          {(capabilities?.analyzers || []).map((a) => (
            <span key={a.analyzer} className="chip text-text" title={(a.fields || []).join(", ")}>
              <span className={`dot ${a.active ? "dot-ok" : "dot-degraded"}`} />{a.analyzer}
              <span className="text-muted ml-1">{a.logs.join(",")}</span>
            </span>
          ))}
          {!capabilities && <span className="text-muted">loading…</span>}
        </div>
      </Panel>

      <Panel title="Coverage · ATT&CK for ICS">
        <div className="p-3 flex flex-wrap gap-1.5 text-xs">
          {COVERAGE_TECH.map(([id, name]) => {
            const on = covered.has(id);
            return (
              <span key={id} className={`chip ${on ? "text-ok border-ok/40" : "text-muted"}`} title={name}>
                <span className="mono">{id}</span>{on ? " ✓" : " ·"}
              </span>
            );
          })}
        </div>
      </Panel>

      <Panel title="Detection rules" className="min-h-0"
        right={<button onClick={() => setSlide(true)} className="text-2xs text-accent border border-accent/50 px-2 h-6 hover:bg-accent/10">+ Add rule</button>}
        bodyClass="overflow-auto">
        <table className="tbl text-xs">
          <thead><tr><th>id</th><th>type</th><th>log</th><th>condition</th><th>att&ck</th><th>sev</th><th>enabled</th><th></th></tr></thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id}>
                <td className="mono">{r.id}</td>
                <td className="text-muted">{r.builtin ? "builtin" : "user"}</td>
                <td className="mono text-muted">{r.log}</td>
                <td className="text-muted">{r.condition || `${r.field} ${r.op} ${r.value ?? ""}`}</td>
                <td className="mono text-muted">{(r.attack || []).join(",")}</td>
                <td><SeverityTag level={r.severity} /></td>
                <td>
                  <button onClick={() => toggleRule(r.id)}
                    className={`text-2xs font-semibold ${r.enabled ? "text-ok" : "text-muted"}`}>
                    {r.enabled ? "ON" : "OFF"}
                  </button>
                </td>
                <td>{!r.builtin && <button onClick={() => deleteRule(r.id)} className="text-2xs text-muted hover:text-crit">del</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      {slide && <RuleSlideOver onClose={() => setSlide(false)} />}
    </div>
  );
}
