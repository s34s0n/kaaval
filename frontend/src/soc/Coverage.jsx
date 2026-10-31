// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { Panel } from "../ui/primitives.jsx";
import { useSoc } from "./store.jsx";

// ATT&CK for ICS coverage matrix — the techniques our detection rules map to,
// grouped by tactic, lit by what's been OBSERVED in current incidents.
const MATRIX = [
  ["Initial Access", [["T0822", "External Remote Services"], ["T0886", "Remote Services"]]],
  ["Discovery", [["T0846", "Remote System Discovery"], ["T0888", "Remote System Information Discovery"], ["T0840", "Network Connection Enumeration"]]],
  ["Command & Control", [["T0869", "Standard Application Layer Protocol"], ["T0884", "Connection Proxy"]]],
  ["Lateral Movement", [["T0859", "Valid Accounts"], ["T0867", "Lateral Tool Transfer"]]],
  ["Inhibit Response Fn", [["T0878", "Alarm Suppression"], ["T0duplicate", "Block Reporting"]]],
  ["Impair Process Control", [["T0855", "Unauthorized Command Message"], ["T0836", "Modify Parameter"], ["T0831", "Manipulation of Control"]]],
  ["Impact", [["T0826", "Loss of Availability"], ["T0837", "Loss of Protection"]]],
];

export default function Coverage() {
  const { incidents } = useSoc();
  const [rules, setRules] = useState([]);
  useEffect(() => { fetch("/api/rules").then((r) => r.json()).then((d) => setRules(d.rules || [])).catch(() => {}); }, []);

  const observed = new Set();
  incidents.forEach((c) => (c.incident?.techniques || []).forEach((t) => observed.add(t.id)));
  const allTech = MATRIX.flatMap(([, ts]) => ts.map(([id]) => id)).filter((id) => !id.includes("dup"));
  const covered = allTech.filter((id) => observed.has(id)).length;
  const activeRules = rules.filter((r) => r.enabled !== false).length;

  return (
    <div className="p-2 h-full overflow-auto space-y-2">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
        {[["Active rules", activeRules], ["Techniques in matrix", allTech.length],
          ["Observed (live)", observed.size], ["Tactics", MATRIX.length]].map(([k, v]) => (
          <div key={k} className="panel px-3 py-2">
            <div className="text-[10px] uppercase tracking-[0.14em] text-faint">{k}</div>
            <div className="text-lg font-semibold tabular-nums mt-0.5">{v}</div>
          </div>
        ))}
      </div>
      <Panel title="ATT&CK for ICS · coverage matrix" bodyClass="p-3">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2 items-start">
          {MATRIX.map(([tactic, techs]) => (
            <div key={tactic} className="space-y-1.5">
              <div className="text-[10px] uppercase tracking-wider text-faint h-7 leading-tight">{tactic}</div>
              {techs.filter(([id]) => !id.includes("dup")).map(([id, name]) => {
                const seen = observed.has(id);
                return (
                  <div key={id} className={`rounded-sm border px-1.5 py-1 ${seen ? "border-crit/50 bg-crit/10" : "border-edge bg-panel2/40"}`}>
                    <div className={`mono text-2xs ${seen ? "text-crit" : "text-muted"}`}>{id}</div>
                    <div className={`text-[10px] leading-tight ${seen ? "text-text" : "text-faint"}`}>{name}</div>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
        <div className="text-2xs text-muted mt-3">
          {covered} of {allTech.length} mapped techniques observed in live incidents · red = detected this session.
        </div>
      </Panel>
    </div>
  );
}
