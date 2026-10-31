// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { useSoc } from "./store.jsx";

const OPS = ["eq", "ne", "contains", "gt", "ge", "lt", "le", "exists"];
const SEVS = ["critical", "high", "medium", "low", "info"];

export default function RuleSlideOver({ onClose }) {
  const { capabilities, createRule, assistRule } = useSoc();
  const palette = capabilities?.field_palette || {};
  const logs = Object.keys(palette);
  const [f, setF] = useState({
    name: "", log: logs[0] || "ssl", field: "", op: "contains", value: "",
    severity: "high", domain: "IT", attack: "",
  });
  const [err, setErr] = useState("");
  const set = (k, v) => setF((s) => ({ ...s, [k]: v }));

  // --- AI assist: describe intent -> LLM proposes a rule -> fills the form ---
  const [intent, setIntent] = useState("");
  const [busy, setBusy] = useState(false);
  const [hint, setHint] = useState(null);     // {rationale, warning, valid}
  const assist = async () => {
    if (!intent.trim()) return;
    setBusy(true); setHint(null); setErr("");
    const r = await assistRule(intent.trim());
    setBusy(false);
    if (!r || !r.proposed) { setHint({ warning: r?.warning || "no proposal — rephrase" }); return; }
    const p = r.proposed;
    setF({
      name: p.name || "", log: p.log, field: p.field, op: p.op, value: p.value ?? "",
      severity: p.severity, domain: p.domain, attack: (p.attack || []).join(", "),
    });
    setHint({ rationale: r.rationale, warning: r.warning, valid: r.valid });
  };

  const save = async () => {
    const rule = {
      name: f.name || `${f.log} ${f.field} ${f.op}`, log: f.log, field: f.field,
      op: f.op, value: f.value, severity: f.severity, domain: f.domain,
      attack: f.attack.split(",").map((s) => s.trim()).filter(Boolean),
    };
    const r = await createRule(rule);
    if (r && r.ok === false) { setErr(r.error || "failed"); return; }
    onClose();
  };

  return (
    <div className="fixed inset-0 z-20 flex justify-end" onClick={onClose}>
      <div className="absolute inset-0 scrim" />
      <div className="relative w-96 h-full bg-panel border-l border-edge pop p-4 overflow-auto" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold">Add detection rule</h3>
          <button onClick={onClose} className="text-muted hover:text-text">✕</button>
        </div>

        {/* AI assist — describe the intent; the local LLM drafts a rule you review */}
        <div className="mb-3 border border-accent/30 bg-accent/5 p-2.5 rounded">
          <div className="text-2xs uppercase tracking-wider text-accent mb-1">✦ Assist with AI</div>
          <textarea className="inp !h-auto py-1.5" rows={2} value={intent}
            onChange={(e) => setIntent(e.target.value)}
            placeholder="Describe in plain words, e.g. 'flag inbound RDP to a plant host' or 'TLS to an unrecognized SNI'" />
          <button onClick={assist} disabled={busy || !intent.trim()}
            className="mt-1.5 w-full h-7 border border-accent text-accent text-xs font-semibold hover:bg-accent/10 disabled:opacity-40">
            {busy ? "Drafting…" : "Draft rule from intent"}
          </button>
          {hint?.rationale && <div className="text-2xs text-muted mt-1.5">{hint.rationale}</div>}
          {hint?.warning && <div className="text-2xs text-warn mt-1">⚠ {hint.warning}</div>}
          {hint && !hint.warning && <div className="text-2xs text-ok mt-1">✓ drafted below — review, edit, then save</div>}
        </div>

        <div className="space-y-3 text-sm">
          <Labeled label="Name"><input className="inp" value={f.name} onChange={(e) => set("name", e.target.value)} placeholder="optional" /></Labeled>
          <Labeled label="Log"><select className="inp" value={f.log} onChange={(e) => { set("log", e.target.value); set("field", ""); }}>
            {logs.map((l) => <option key={l} value={l}>{l}</option>)}</select></Labeled>
          <Labeled label="Field"><select className="inp" value={f.field} onChange={(e) => set("field", e.target.value)}>
            <option value="">— pick field —</option>
            {(palette[f.log] || []).map((fld) => <option key={fld} value={fld}>{fld}</option>)}</select></Labeled>
          <div className="grid grid-cols-2 gap-2">
            <Labeled label="Operator"><select className="inp" value={f.op} onChange={(e) => set("op", e.target.value)}>
              {OPS.map((o) => <option key={o}>{o}</option>)}</select></Labeled>
            <Labeled label="Value"><input className="inp mono" value={f.value} onChange={(e) => set("value", e.target.value)} disabled={f.op === "exists"} /></Labeled>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Labeled label="Severity"><select className="inp" value={f.severity} onChange={(e) => set("severity", e.target.value)}>
              {SEVS.map((s) => <option key={s}>{s}</option>)}</select></Labeled>
            <Labeled label="Domain"><select className="inp" value={f.domain} onChange={(e) => set("domain", e.target.value)}>
              <option>IT</option><option>OT</option></select></Labeled>
          </div>
          <Labeled label="ATT&CK ids (comma-sep)"><input className="inp mono" value={f.attack} onChange={(e) => set("attack", e.target.value)} placeholder="T0869" /></Labeled>
          {err && <div className="text-2xs text-crit">{err}</div>}
          <button onClick={save} disabled={!f.field || (f.op !== "exists" && !f.value)}
            className="w-full h-8 border border-accent text-accent text-sm font-semibold hover:bg-accent/10 disabled:opacity-40">
            Save rule (fires live)
          </button>
          <p className="text-2xs text-muted">Saved to the rules store and hot-reloaded — it evaluates on the next detection cycle (~2s), no restart.</p>
        </div>
      </div>
      <style>{`.inp{width:100%;background:rgb(var(--panel2));border:1px solid rgb(var(--edge));height:30px;padding:0 8px;color:rgb(var(--text));outline:none;font-size:13px}`}</style>
    </div>
  );
}

function Labeled({ label, children }) {
  return (
    <label className="block">
      <div className="text-2xs uppercase tracking-wider text-muted mb-1">{label}</div>
      {children}
    </label>
  );
}
