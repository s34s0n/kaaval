// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { Panel, SeverityTag } from "../ui/primitives.jsx";
import Icon from "../ui/Icon.jsx";
import { useSoc } from "./store.jsx";

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function caseTitle(c) {
  return c.agents?.triage?.headline
    || (c.incident?.cross_domain ? "Cross-domain IT→OT incident"
        : `${(c.incident?.domains || []).join("+") || "Security"} incident`);
}

function Bars({ title, rows }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div>
      <div className="text-2xs uppercase tracking-wider text-muted mb-1.5">{title}</div>
      <div className="space-y-1">
        {rows.map((r) => (
          <div key={r.label} className="flex items-center gap-2 text-2xs">
            <span className="w-24 shrink-0 text-muted">{r.label}</span>
            <div className="flex-1 h-3 bg-panel2 rounded-sm overflow-hidden">
              <div className="h-full rounded-sm" style={{ width: `${(r.value / max) * 100}%`, background: r.color, minWidth: r.value ? "4px" : 0 }} />
            </div>
            <span className="w-5 text-right mono text-text">{r.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SafetyMeter({ state, safety, status }) {
  const v = safety?.variable ? state?.[safety.variable] : null;
  const [lo, hi] = safety?.band || [];
  const danger = safety?.danger;
  const scale = danger ? danger * 1.1 : 100;
  const pct = v != null ? Math.min(100, (v / scale) * 100) : 0;
  const color = status === "ok" ? "#2EE6A6" : status === "warning" ? "#F5A524" : "#FF5C5C";
  return (
    <Panel title="Process safety" bodyClass="p-3">
      {v == null ? <div className="text-2xs text-muted">No live process value.</div> : (
        <>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-semibold leading-none" style={{ color }}>{(+v).toFixed(1)}</span>
            <span className="text-xs text-muted">{safety?.unit} · {safety?.label}</span>
          </div>
          <div className="relative mt-3 h-3 bg-panel2 rounded-sm overflow-hidden">
            <div className="h-full rounded-sm transition-all" style={{ width: `${pct}%`, background: color }} />
            {hi != null && <span className="absolute top-0 bottom-0 w-px bg-muted" style={{ left: `${(hi / scale) * 100}%` }} />}
            {danger != null && <span className="absolute top-0 bottom-0 w-px bg-crit" style={{ left: `${(danger / scale) * 100}%` }} />}
          </div>
          <div className="flex justify-between text-2xs text-muted mt-1">
            <span>safe band {lo}–{hi}</span><span className="text-crit">danger {danger}</span>
          </div>
          <div className="text-2xs mt-2 font-semibold" style={{ color }}>Status: {String(status).toUpperCase()}</div>
        </>
      )}
    </Panel>
  );
}

function Stat({ label, value, sub, tone = "text-text" }) {
  return (
    <div className="panel px-3.5 py-3 flex flex-col gap-2 min-h-[84px]">
      <div className="text-[10px] uppercase tracking-[0.16em] text-faint">{label}</div>
      <div className={`text-[26px] font-semibold leading-none tracking-tight tabular-nums ${tone}`}>{value}</div>
      {sub && <div className="text-2xs text-muted mt-auto">{sub}</div>}
    </div>
  );
}

// --- executive text report (assembled from the live data; deterministic) -----
function buildReport({ profile, incidents, assets, health, autonomy }) {
  const now = new Date().toISOString().replace("T", " ").slice(0, 19) + "Z";
  const crit = assets.filter((a) => a.criticality === "critical").length;
  const techs = new Set();
  incidents.forEach((c) => (c.incident?.techniques || []).forEach((t) => techs.add(t.id)));
  const highest = incidents.reduce((m, c) => Math.max(m, SEV_RANK[c.incident?.severity] || 0), 0);
  const highestName = Object.keys(SEV_RANK).find((k) => SEV_RANK[k] === highest) || "none";
  const resolved = incidents.filter((c) => c.status === "resolved").length;

  const L = [];
  L.push("KAAVAL — EXECUTIVE SECURITY REPORT");
  L.push("=".repeat(52));
  L.push(`Generated:        ${now}`);
  L.push(`Site / profile:   ${profile?.name || "—"}`);
  L.push(`Protected asset:  ${profile?.safety?.label || "—"} (band ${(profile?.safety?.band || []).join("–")}, danger ${profile?.safety?.danger ?? "—"})`);
  L.push(`AI analyst:       ${health?.llm_model || "local model"} (${health?.llm_offline ? "on-prem / offline" : "external API"})`);
  L.push(`Autonomy:         ${autonomy ? "ENABLED (reversible IT auto-contained)" : "manual (operator approves all actions)"}`);
  L.push("");
  L.push("POSTURE");
  L.push("-".repeat(52));
  L.push(`Active incidents: ${incidents.length}  (resolved: ${resolved})`);
  L.push(`Highest severity: ${highestName.toUpperCase()}`);
  L.push(`Assets monitored: ${assets.length}  (critical: ${crit})`);
  L.push(`ATT&CK for ICS techniques observed: ${techs.size}${techs.size ? " — " + [...techs].join(", ") : ""}`);
  L.push("");

  if (!incidents.length) {
    L.push("No active incidents. The monitored process is within its safe operating band");
    L.push("and the sensor has flagged no unauthorized activity.");
  }
  incidents.forEach((c) => {
    const inc = c.incident || {}, m = c.metrics || {}, ag = c.agents || {};
    L.push(`INCIDENT ${c.id} — ${(inc.severity || "").toUpperCase()} — ${caseTitle(c)}`);
    L.push("-".repeat(52));
    L.push(`Status:     ${c.status}${m.resolved ? " (verified resolved on fresh telemetry)" : ""}`);
    L.push(`Scope:      ${(inc.domains || []).join(" + ")}${inc.cross_domain ? " (cross-domain)" : ""}, pivot ${inc.pivot}`);
    L.push(`Detection:  ${(inc.event_ids || []).length} stages · time-to-detect ${m.time_to_detect_s ?? "—"}s · time-to-contain ${m.time_to_contain_s ?? "—"}s`);
    if (ag.triage?.process_at_risk) L.push(`At risk:    ${ag.triage.process_at_risk}`);
    if (ag.investigation?.narrative) L.push(`What happened: ${ag.investigation.narrative}`);
    else if (inc.summary) L.push(`What happened: ${inc.summary}`);
    if (ag.investigation?.it_ot_link) L.push(`IT→OT link: ${ag.investigation.it_ot_link}`);
    const acts = c.actions || [];
    if (acts.length) {
      L.push("Response:");
      acts.forEach((a) => {
        const gate = a.requires_human_approval ? "human-approved" : "auto (reversible IT)";
        L.push(`   • ${a.title || a.name} — ${gate} — ${a.status || "pending"}`);
      });
    }
    L.push("");
  });
  L.push("RECOMMENDATION");
  L.push("-".repeat(52));
  L.push(incidents.length
    ? "Containment actions above are recommended; control-plane (OT) actions are held for"
    + " human approval per the OT-safety policy. Approve to recover and verify."
    : "Maintain monitoring. No action required.");
  return L.join("\n");
}

function ReportModal({ text, onClose }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => { try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* ignore */ } };
  const download = () => {
    const blob = new Blob([text], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `kaaval-report-${new Date().toISOString().slice(0, 10)}.md`;
    a.click(); URL.revokeObjectURL(a.href);
  };
  return (
    <div className="fixed inset-0 z-30 flex items-center justify-center p-6" onClick={onClose}>
      <div className="absolute inset-0 scrim" />
      <div className="relative panel pop w-full max-w-3xl max-h-[85vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        <header className="panel-head">
          <h2 className="panel-title">Executive report · text</h2>
          <div className="flex items-center gap-2">
            <button onClick={copy} className="btn">{copied ? "copied ✓" : "Copy"}</button>
            <button onClick={download} className="btn btn-brand">Download .md</button>
            <button onClick={onClose} className="btn">Close</button>
          </div>
        </header>
        <pre className="overflow-auto p-4 text-xs mono leading-relaxed whitespace-pre-wrap">{text}</pre>
      </div>
    </div>
  );
}

export default function Overview() {
  const { incidents, assets, profile, state, autonomy } = useSoc();
  const [health, setHealth] = useState(null);
  const [report, setReport] = useState(null);
  useEffect(() => {
    let stop = false;
    const tick = () => fetch("/api/health").then((r) => r.json()).then((h) => !stop && setHealth(h)).catch(() => {});
    tick(); const t = setInterval(tick, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  const open = incidents.length;
  const resolved = incidents.filter((c) => c.status === "resolved").length;
  const highest = incidents.reduce((m, c) => Math.max(m, SEV_RANK[c.incident?.severity] || 0), 0);
  const highestName = Object.keys(SEV_RANK).find((k) => SEV_RANK[k] === highest) || "—";
  const techs = new Set();
  incidents.forEach((c) => (c.incident?.techniques || []).forEach((t) => techs.add(t.id)));
  const crit = assets.filter((a) => a.criticality === "critical").length;
  const ttds = incidents.map((c) => c.metrics?.time_to_detect_s).filter((x) => x != null);
  const ttd = ttds.length ? (ttds.reduce((a, b) => a + b, 0) / ttds.length).toFixed(1) : "—";
  const status = state?.status || "—";
  const postureTone = status === "ok" ? "text-ok" : status === "burst" || status === "danger" ? "text-crit" : "text-high";
  const sevTone = highestName === "critical" ? "text-crit" : highestName === "high" ? "text-high" : "text-text";

  const techMap = new Map();
  incidents.forEach((c) => (c.incident?.techniques || []).forEach((t) => techMap.set(t.id, t)));
  const sc = { critical: 0, high: 0, medium: 0, low: 0 };
  incidents.forEach((c) => { const s = c.incident?.severity; if (s in sc) sc[s]++; });
  const sevBars = [
    { label: "Critical", value: sc.critical, color: "#FF5C5C" },
    { label: "High", value: sc.high, color: "#F5A524" },
    { label: "Medium", value: sc.medium, color: "#E6C84B" },
  ];
  const ac = { critical: 0, high: 0, medium: 0, low: 0 };
  assets.forEach((a) => { const k = a.criticality; if (k in ac) ac[k]++; });
  const critBars = [
    { label: "Critical", value: ac.critical, color: "#FF5C5C" },
    { label: "High", value: ac.high, color: "#F5A524" },
    { label: "Medium / Low", value: ac.medium + ac.low, color: "#4AA3FF" },
  ];

  const reportData = { profile, incidents, assets, health, autonomy };

  return (
    <div className="h-full overflow-auto p-3 space-y-3">
      {/* Posture banner */}
      <div className="panel p-4 flex items-center gap-4 flex-wrap">
        <div className="grid place-items-center w-11 h-11 rounded-md text-bg shrink-0"
          style={{ background: "linear-gradient(145deg,#2DD4BF,#1B8E80)", boxShadow: "0 0 16px -2px rgba(45,212,191,0.6)" }}>
          <Icon name="shield" size={22} />
        </div>
        <div>
          <div className="text-lg font-semibold tracking-tight">{profile?.name || "Kaaval"} · Security Posture</div>
          <div className="text-xs text-muted">
            Process status <span className={`font-semibold ${postureTone}`}>{status.toUpperCase()}</span>
            {state?.[profile?.safety?.variable] != null &&
              <> · {profile?.safety?.label}: <span className="mono">{(+state[profile.safety.variable]).toFixed(1)} {profile?.safety?.unit}</span></>}
            {" · "}AI: <span className="text-brand">{health?.llm_model || "local"}</span>
            <span className={health?.llm_offline ? "text-ok" : "text-high"}> ({health?.llm_offline ? "on-prem" : "external API"})</span>
          </div>
        </div>
        <button onClick={() => setReport(buildReport(reportData))}
          className="btn btn-brand ml-auto h-8"><Icon name="report" size={14} /> Executive report (text)</button>
      </div>

      {/* KPI tiles */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Stat label="Active incidents" value={open} sub={`${resolved} resolved`} tone={open ? "text-crit" : "text-ok"} />
        <Stat label="Highest severity" value={highestName.toUpperCase()} tone={sevTone} />
        <Stat label="Avg time to detect" value={ttd === "—" ? "—" : `${ttd}s`} sub="from first event" />
        <Stat label="ATT&CK techniques" value={techs.size} sub="ICS, observed" />
        <Stat label="Assets monitored" value={assets.length} sub={`${crit} critical`} />
        <Stat label="Autonomy" value={autonomy ? "ON" : "Manual"} sub="OT always gated" tone={autonomy ? "text-ok" : "text-muted"} />
      </div>

      {/* Visuals row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <SafetyMeter state={state} safety={profile?.safety} status={status} />
        <Panel title="Detection coverage · ATT&CK ICS" bodyClass="p-3">
          {techs.size === 0
            ? <div className="text-2xs text-muted">No techniques observed — baseline.</div>
            : <div className="flex flex-wrap gap-1.5">
                {[...techMap.values()].map((t) => (
                  <span key={t.id} className="chip">
                    <span className="mono text-text">{t.id}</span> <span className="text-muted">{t.name}</span>
                  </span>
                ))}
              </div>}
        </Panel>
        <Panel title="Risk distribution" bodyClass="p-3 space-y-3">
          <Bars title="Incidents by severity" rows={sevBars} />
          <Bars title="Assets by criticality" rows={critBars} />
        </Panel>
      </div>

      {/* Incident summaries (exec-friendly) */}
      <Panel title={`Incidents · ${open}`} bodyClass="p-3">
        {open === 0
          ? <div className="text-sm text-muted">No active incidents. The process is within its safe band and the sensor has flagged nothing.</div>
          : <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
              {[...incidents].reverse().map((c) => {
                const inc = c.incident || {}, m = c.metrics || {};
                const applied = (c.actions || []).filter((a) => ["executed", "approved"].includes(a.status)).length;
                return (
                  <div key={c.id} className="panel p-3">
                    <div className="flex items-center gap-2">
                      <SeverityTag level={inc.severity} />
                      <span className="mono text-2xs text-muted">{c.id}</span>
                      <span className="ml-auto text-2xs uppercase text-muted">{c.status}</span>
                    </div>
                    <div className="text-sm font-medium mt-1.5">{caseTitle(c)}</div>
                    <div className="text-2xs text-muted mt-1">
                      {(inc.domains || []).join(" + ")}{inc.cross_domain ? " · cross-domain" : ""} · pivot {inc.pivot}
                      {" · "}TTD {m.time_to_detect_s ?? "—"}s
                    </div>
                    <div className="mt-2 text-2xs">
                      Response: <span className="text-text">{applied}/{(c.actions || []).length} actions taken</span>
                      {m.resolved && <span className="text-ok"> · verified resolved</span>}
                    </div>
                  </div>
                );
              })}
            </div>}
      </Panel>

      {report && <ReportModal text={report} onClose={() => setReport(null)} />}
    </div>
  );
}
