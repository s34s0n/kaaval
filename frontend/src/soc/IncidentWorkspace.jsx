// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Panel, SeverityTag } from "../ui/primitives.jsx";
import Icon from "../ui/Icon.jsx";
import { useSoc } from "./store.jsx";
import AnalystChat from "./AnalystChat.jsx";
import CasePanel from "./CasePanel.jsx";

// Canonical kill-chain (lit by which ATT&CK techniques the live events carry).
// Tactic label per detection rule (display only; the chain is built from the
// events that ACTUALLY fired — Kaaval does not predict undetected stages).
const TACTIC = {
  external_remote_access: "Initial Access",
  c2_beaconing: "Command & Control",
  ot_network_scan: "Discovery",
  unauthorized_opcua_access: "Discovery",
  unauthorized_s7_command: "Execution / Impact",
};

function prettyRule(rule) {
  return (rule || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// Honest title derived from what was actually detected (no overclaiming).
function incidentTitle(inc) {
  if (!inc) return "Incident detail";
  if (inc.cross_domain) return "IT→OT intrusion";
  const d = inc.domains || [];
  if (d.length === 1 && d[0] === "OT") return "Unauthorized OT activity";
  if (d.length === 1 && d[0] === "IT") return "Suspicious IT activity";
  return "Security incident";
}

function Field({ k, v, mono }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-2xs uppercase tracking-wider text-muted">{k}</span>
      <span className={`text-sm ${mono ? "mono" : ""}`}>{v ?? "—"}</span>
    </div>
  );
}

// Built only from detected events, ordered by time. No predicted/ghost stages.
function KillChain({ events }) {
  const nodes = [...(events || [])].sort((a, b) => (a.ts || 0) - (b.ts || 0));
  if (!nodes.length) return null;
  const firstOt = nodes.findIndex((e) => e.domain === "OT");
  const hasIT = nodes.some((e) => e.domain === "IT");
  const hasOT = firstOt !== -1;
  const title = hasIT && hasOT ? "Cross-domain kill chain · detected stages"
    : "Detected attack stages";

  return (
    <div className="px-3 py-3 border-b border-edge">
      <div className="text-2xs uppercase tracking-wider text-muted mb-2">{title}</div>
      <div className="flex items-stretch gap-1 overflow-x-auto pb-1">
        <AnimatePresence initial={true}>
        {nodes.map((e, i) => {
          const ot = e.domain === "OT";
          const tids = (e.techniques || []).map((t) => t.id).join(", ");
          const name = e.techniques?.[0]?.name || prettyRule(e.rule);
          const showPivot = hasIT && hasOT && i === firstOt;   // mark the IT→OT crossing only
          return (
            <div key={e.id} className="flex items-stretch gap-1 shrink-0">
              {showPivot && (
                <motion.div initial={{ opacity: 0, scale: 0.6 }} animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: i * 0.08 + 0.04 }}
                  className="flex flex-col items-center justify-center px-1 text-accent">
                  <Icon name="pivot" /><span className="text-[9px] uppercase tracking-wide mt-0.5">ews pivot</span>
                </motion.div>
              )}
              <motion.div layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.08, type: "spring", stiffness: 320, damping: 26 }}
                className={`panel px-2 py-1.5 w-40 border-t-2 ${ot ? "border-t-crit" : "border-t-low"}`}>
                <div className="flex items-center justify-between">
                  <span className={`text-2xs font-semibold ${ot ? "text-crit" : "text-low"}`}>{e.domain}</span>
                  <span className="mono text-2xs text-muted">{tids}</span>
                </div>
                <div className="text-xs mt-1 leading-tight">{name}</div>
                <div className="text-2xs text-muted mt-0.5">{TACTIC[e.rule] || "detected"} · detected</div>
              </motion.div>
            </div>
          );
        })}
        </AnimatePresence>
      </div>
    </div>
  );
}

function EventRow({ e }) {
  const [open, setOpen] = useState(false);
  const { cite, setCite } = useSoc();
  const rowRef = useRef(null);
  // A chat citation "lands" here if it names this rule or one of its techniques.
  const hit = !!cite && (cite === e.rule || (e.techniques || []).some((t) => t.id === cite));
  useEffect(() => {
    if (hit) {
      setOpen(true);
      rowRef.current?.scrollIntoView({ block: "center", behavior: "smooth" });
      const t = setTimeout(() => setCite(null), 2200);   // clear the focus after the flash
      return () => clearTimeout(t);
    }
  }, [hit, setCite]);
  return (
    <>
      <tr ref={rowRef} onClick={() => setOpen((v) => !v)}
        className={`cursor-pointer transition-colors ${hit ? "outline outline-1 outline-accent bg-accent/10" : ""}`}>
        <td><SeverityTag level={e.severity} /></td>
        <td>{e.rule || e.id}</td>
        <td className="text-muted">{e.src} → {e.dst}</td>
        <td className="text-muted">{(e.techniques || []).map((t) => t.id).join(",")}</td>
        <td className="text-muted">{e.evidence_count}×</td>
      </tr>
      {open && (
        <tr><td colSpan={5} className="bg-panel2">
          <pre className="text-2xs mono text-muted whitespace-pre-wrap p-2 max-h-48 overflow-auto">
            {JSON.stringify(e.evidence || {}, null, 2)}
          </pre>
        </td></tr>
      )}
    </>
  );
}

// Pipeline state for the three agents, derived from which results have streamed in.
// run_agents() pushes triage → investigation → response in order, so a missing
// result that follows a present one is the agent currently *running*.
function pipelineStates(agents, hasEvents) {
  const order = [
    ["triage", "Triage"],
    ["investigation", "Investigation"],
    ["response", "Response"],
  ];
  let runningAssigned = false;
  return order.map(([key, label]) => {
    const data = agents?.[key] || null;
    let state;
    if (data) state = data?._meta?.degraded ? "failed" : "done";
    else if (!runningAssigned && hasEvents) { state = "running"; runningAssigned = true; }
    else state = "queued";
    return { key, label, state, data };
  });
}

const AGENT_STATE = {
  done: { dot: "bg-ok", text: "text-ok", label: "done" },
  running: { dot: "bg-accent animate-pulse", text: "text-accent", label: "running" },
  queued: { dot: "bg-edge2", text: "text-muted", label: "queued" },
  failed: { dot: "bg-crit", text: "text-crit", label: "degraded" },
};

function AgentCard({ title, state, data, render }) {
  const s = AGENT_STATE[state] || AGENT_STATE.queued;
  return (
    <motion.div layout className={`panel p-2 flex flex-col ${state === "running" ? "ring-1 ring-accent/40" : ""}`}>
      <div className="flex items-center gap-1.5 mb-1 shrink-0">
        <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
        <span className="text-xs font-semibold">{title}</span>
        <span className={`ml-auto text-[10px] uppercase tracking-wide ${s.text}`}>
          {s.label}{state === "done" && data?._meta?.latency_s != null ? ` · ${data._meta.latency_s}s` : ""}
        </span>
      </div>
      <div className="max-h-56 overflow-auto pr-1">
        <AnimatePresence mode="wait">
          {data ? (
            <motion.div key="content" initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>
              {render(data)}
            </motion.div>
          ) : state === "running" ? (
            <motion.div key="run" className="space-y-1 pt-1">
              {[0, 1, 2].map((i) => (
                <motion.div key={i} className="h-2 rounded bg-edge2/60"
                  animate={{ opacity: [0.25, 0.6, 0.25] }}
                  transition={{ duration: 1.1, repeat: Infinity, delay: i * 0.18 }}
                  style={{ width: `${90 - i * 18}%` }} />
              ))}
              <div className="text-2xs text-accent/80 pt-0.5">reasoning…</div>
            </motion.div>
          ) : (
            <div key="idle" className="text-2xs text-muted">waiting for prior stage…</div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

function ActionRow({ a, busy, onApply, onRequestApprove, canApprove, canApply }) {
  const gated = a.requires_human_approval;
  const done = a.status === "executed" || a.status === "approved";
  const failed = a.status === "failed";
  return (
    <div className={`panel p-2 border-l-2 ${gated ? "border-l-crit" : "border-l-low"}`}>
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`sev ${gated ? "sev-critical" : "sev-low"}`}>{gated ? "gated" : "auto"}</span>
        <span className="text-sm font-medium">{a.title || a.name}</span>
        <span className="chip">{a.domain}</span>
        <span className={`ml-auto text-2xs ${done ? "text-ok" : failed ? "text-crit" : "text-muted"}`}>
          {done ? "✓ " + a.status : failed ? "✕ failed" : a.status}
        </span>
      </div>
      <div className="text-2xs text-muted mt-1">{a.rationale}</div>
      {gated && a.gating_reason && <div className="text-2xs text-crit/90 mt-1">⚠ {a.gating_reason}</div>}
      {done && "verified" in a && (
        <div className={`text-2xs mt-1 ${a.verified ? "text-ok" : "text-crit"}`}>
          {a.verified ? "✓ verified — " : "⚠ NOT verified — "}{a.verify_detail}
        </div>
      )}
      {!done && (
        gated
          ? (canApprove
              ? <button disabled={busy} onClick={() => onRequestApprove(a)}
                  className="mt-2 h-6 px-2 text-2xs font-semibold border border-ok/60 text-ok hover:bg-ok/10 disabled:opacity-50">
                  {busy ? "executing…" : "Approve & execute"}</button>
              : <button disabled title="Requires the approver role — separation of duties (sign in as approver)"
                  className="mt-2 h-6 px-2 text-2xs font-semibold border border-edge text-muted cursor-not-allowed">
                  Approve · requires approver</button>)
          : (canApply
              ? <button disabled={busy} onClick={() => onApply(a.name)}
                  className="mt-2 h-6 px-2 text-2xs font-semibold border border-accent/60 text-accent hover:bg-accent/10 disabled:opacity-50">
                  {busy ? "applying…" : "Apply"}</button>
              : <button disabled title="Sign in as an operator to apply containment"
                  className="mt-2 h-6 px-2 text-2xs font-semibold border border-edge text-muted cursor-not-allowed">
                  Apply · sign in</button>)
      )}
    </div>
  );
}

// The approval "ceremony" — a deliberate confirm step before an irreversible OT
// control action runs. Restates what will happen and why it was gated, shows the
// VERIFIED approver (the authenticated principal recorded in the audit log; the
// server ignores any client-supplied name), and only then fires.
function ConfirmApproval({ action, onConfirm, onCancel }) {
  const { principal } = useSoc();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape" && !busy) onCancel(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onCancel]);
  if (!action) return null;
  const go = async () => {
    setBusy(true);
    await onConfirm();           // parent runs approve(); server records the verified principal
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center scrim"
      role="dialog" aria-modal="true" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onCancel(); }}>
      <motion.div initial={{ opacity: 0, scale: 0.96, y: 8 }} animate={{ opacity: 1, scale: 1, y: 0 }}
        className="panel pop w-[440px] max-w-[92vw] p-4 border-l-2 border-l-crit">
        <div className="flex items-center gap-2">
          <span className="sev sev-critical">gated OT action</span>
          <span className="text-sm font-semibold">{action.title || action.name}</span>
        </div>
        <p className="text-xs text-muted mt-2">{action.rationale}</p>
        {action.gating_reason && (
          <div className="text-2xs text-crit/90 mt-2 border border-crit/30 bg-crit/5 rounded px-2 py-1.5">
            ⚠ Why this needs you: {action.gating_reason}
          </div>
        )}
        <div className="mt-3 flex items-center justify-between border border-edge bg-panel2/50 rounded px-2.5 py-2">
          <span className="text-2xs uppercase tracking-wider text-muted">Approving as (recorded in audit)</span>
          <span className="text-xs"><span className="text-text font-medium">{principal?.name || "—"}</span>
            <span className="text-2xs text-brand uppercase ml-1.5">{principal?.role}</span></span>
        </div>
        <div className="flex items-center gap-2 mt-4">
          <button onClick={go} disabled={busy}
            className="h-7 px-3 text-2xs font-semibold border border-ok/60 text-ok hover:bg-ok/10 disabled:opacity-50">
            {busy ? "executing…" : "Confirm & execute OT action"}</button>
          <button onClick={onCancel} disabled={busy}
            className="h-7 px-3 text-2xs font-semibold border border-edge text-muted hover:text-text disabled:opacity-50">Cancel</button>
          <span className="ml-auto text-2xs text-faint">Esc to cancel</span>
        </div>
      </motion.div>
    </div>
  );
}

// Compact progress strip: Triage ─ Investigation ─ Response, lit by live state.
function PipelineRail({ states }) {
  return (
    <div className="flex items-center gap-1 ml-1">
      {states.map((s, i) => {
        const c = AGENT_STATE[s.state] || AGENT_STATE.queued;
        return (
          <div key={s.key} className="flex items-center gap-1">
            {i > 0 && <span className={`w-4 h-px ${states[i - 1].state === "done" ? "bg-ok/60" : "bg-edge2"}`} />}
            <motion.span layout className={`w-1.5 h-1.5 rounded-full ${c.dot}`}
              title={`${s.label}: ${c.label}`} />
            <span className={`text-[10px] ${c.text}`}>{s.label}</span>
          </div>
        );
      })}
    </div>
  );
}

// Immutable approval/decision audit trail for the selected incident (P2 backend).
function DecisionLog({ incidentId, version }) {
  const { getApprovals } = useSoc();
  const [rows, setRows] = useState([]);
  useEffect(() => {
    let live = true;
    if (!incidentId) { setRows([]); return; }
    getApprovals(incidentId).then((d) => { if (live && d?.approvals) setRows(d.approvals); });
    return () => { live = false; };
  }, [incidentId, version, getApprovals]);
  if (!rows.length) return null;
  return (
    <div className="px-3 py-3 border-b border-edge">
      <div className="text-2xs uppercase tracking-wider text-muted mb-2">Decision log · audit trail</div>
      <div className="flex flex-col gap-1">
        {rows.map((r, i) => (
          <div key={i} className="flex items-center gap-2 text-2xs">
            <span className={`sev ${r.gated ? "sev-critical" : "sev-low"}`}>{r.gated ? "gated" : "auto"}</span>
            <span className="mono">{r.action}</span>
            <span className={r.result_ok ? "text-ok" : "text-crit"}>{r.decision}{r.result_ok ? "" : " · failed"}</span>
            <span className="text-muted">by {r.approver}</span>
            <span className="ml-auto text-muted">{new Date((r.ts || 0) * 1000).toLocaleTimeString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const STATUS_TONE = {
  resolved: "text-ok", remediating: "text-accent", contained: "text-ok",
  triaged: "text-warn", open: "text-muted",
};

// Response playbook = an ordered PROPOSAL. Investigation steps are guidance; action
// steps reuse the EXACT same ActionRow + approve/apply handlers as the manual list,
// so a gated OT step is still an individual approver decision through the existing
// gate (recorded in the decision log). The playbook only orders + pre-fills.
function PlaybookPanel({ incidentId, actions, busyAction, onApply, onRequestApprove, canApprove, canApply }) {
  const [data, setData] = useState(null);
  const [picked, setPicked] = useState(null);
  useEffect(() => {
    if (!incidentId) return;
    let live = true;
    fetch(`/api/playbooks/suggest?incident=${encodeURIComponent(incidentId)}`)
      .then((r) => r.json()).then((d) => { if (live) { setData(d); setPicked(d.recommended); } }).catch(() => {});
    return () => { live = false; };
  }, [incidentId]);
  if (!data || !data.candidates?.length) return null;
  const pb = data.candidates.find((c) => c.id === picked) || data.candidates[0];
  const statusOf = (name) => (actions.find((a) => a.name === name) || {}).status;

  return (
    <div className="px-3 py-3 border-t border-edge">
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <span className="text-2xs uppercase tracking-wider text-muted">Response playbook · proposal</span>
        {data.candidates.map((c) => (
          <button key={c.id} onClick={() => setPicked(c.id)}
            className={`pill text-2xs ${c.id === pb.id ? "text-brand border-brand/60 bg-brand/10" : "text-muted border-edge hover:text-text"}`}>
            {c.name}
            {c.id === data.recommended && <span className="ml-1 text-[9px] text-high uppercase">★ {data.recommended_source}</span>}
          </button>
        ))}
      </div>
      {data.recommended === pb.id && data.why && (
        <div className="text-2xs text-muted mb-2 italic">Suggested ({data.recommended_source}): {data.why}</div>
      )}
      <ol className="space-y-1.5">
        {pb.steps.map((s) => s.kind === "investigate" ? (
          <li key={s.order} className="flex gap-2 text-xs items-start">
            <span className="mono text-faint shrink-0 w-4 text-right">{s.order}</span>
            <div>
              <span className="text-text">{s.title}</span>
              {s.detail && <div className="text-2xs text-muted leading-snug">{s.detail}</div>}
            </div>
          </li>
        ) : (
          <li key={s.order} className="flex gap-2 items-start">
            <span className="mono text-faint shrink-0 w-4 text-right pt-2">{s.order}</span>
            <div className="flex-1 min-w-0">
              {s.available
                ? <ActionRow
                    a={{ name: s.action, title: s.title, domain: s.domain, status: statusOf(s.action),
                         requires_human_approval: s.requires_human_approval, rationale: s.rationale,
                         gating_reason: s.gating_reason }}
                    busy={busyAction === s.action} onApply={onApply} onRequestApprove={onRequestApprove}
                    canApprove={canApprove} canApply={canApply} />
                : <div className="panel p-2 border-l-2 border-l-edge text-2xs">
                    <span className="mono text-muted">{s.action}</span>
                    <span className="text-crit ml-1">· unavailable</span>
                    <div className="text-faint mt-0.5">{s.reason}</div>
                  </div>}
            </div>
          </li>
        ))}
      </ol>
      <div className="text-2xs text-faint mt-2 leading-snug">
        A playbook proposes the order; each gated OT step is still an individual approver decision through the
        same server-side gate, recorded in the decision log.
      </div>
    </div>
  );
}

export default function IncidentWorkspace() {
  const { incident, events, agents, actions, scoreboard, apply, approve,
          incidents, selectedId, selectIncident, principal } = useSoc();
  const canApprove = !!principal?.can?.approve;
  const canApply = !!principal?.authenticated;   // operator+ (backend enforces operator)
  const [busyAction, setBusyAction] = useState(null);   // per-action, not one shared lock
  const [confirm, setConfirm] = useState(null);         // gated action awaiting the ceremony
  const [chatOpen, setChatOpen] = useState(true);

  // Resizable analyst chat — drag the handle to size it; persisted across reloads.
  const [chatW, setChatW] = useState(() => {
    const v = +(localStorage.getItem("kaaval.chatW") || 0);
    return v >= 300 && v <= 720 ? v : 380;
  });
  useEffect(() => { localStorage.setItem("kaaval.chatW", String(chatW)); }, [chatW]);
  const startDrag = (e) => {
    e.preventDefault();
    const startX = e.clientX, startW = chatW;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    const move = (ev) => setChatW(Math.min(720, Math.max(300, startW + (startX - ev.clientX))));
    const up = () => {
      document.removeEventListener("mousemove", move);
      document.removeEventListener("mouseup", up);
      document.body.style.cursor = ""; document.body.style.userSelect = "";
    };
    document.addEventListener("mousemove", move);
    document.addEventListener("mouseup", up);
  };

  const doApply = async (name) => { setBusyAction(name); await apply(name); setBusyAction(null); };
  const confirmApprove = async () => {
    const name = confirm.name;
    setBusyAction(name);
    await approve(name);
    setBusyAction(null);
    setConfirm(null);
  };

  return (
    <div className="flex gap-2 p-2 h-full min-h-0">
      {/* Queue — every correlated incident; each is triaged + remediated on its own */}
      <Panel title={`Incident Queue${incidents?.length ? ` · ${incidents.length}` : ""}`}
        className="w-64 shrink-0" bodyClass="overflow-auto">
        {incidents && incidents.length ? (
          <div className="divide-y divide-edge">
            {[...incidents].reverse().map((c) => {
              const inc = c.incident || {};
              const sel = c.id === selectedId;
              const gated = (c.actions || []).filter((a) => a.requires_human_approval).length;
              return (
                <button key={c.id} onClick={() => selectIncident(c.id)}
                  className={`w-full text-left px-3 py-2 ${sel ? "border-l-2 border-l-accent bg-panel2" : "border-l-2 border-l-transparent hover:bg-panel2/50"}`}>
                  <div className="flex items-center gap-2">
                    <SeverityTag level={inc.severity} />
                    <span className="mono text-2xs text-muted">{c.id}</span>
                    <span className={`ml-auto text-2xs uppercase ${STATUS_TONE[c.status] || "text-muted"}`}>{c.status}</span>
                  </div>
                  <div className="text-xs mt-1 leading-snug">{incidentTitle(inc)}</div>
                  <div className="text-2xs text-muted mt-0.5">
                    {inc.cross_domain ? "cross-domain" : "single-domain"}
                    {(c.actions || []).length ? ` · fix: ${c.actions.length} (${gated} gated)` : ""}
                  </div>
                </button>
              );
            })}
          </div>
        ) : <div className="p-3 text-xs text-muted">No active incidents. Launch the attack from the Range Console.</div>}
      </Panel>

      {/* Detail */}
      <Panel className="flex-1 min-w-0" bodyClass="overflow-auto"
        title={incident ? `${incident.id} · ${incidentTitle(incident)}` : "Incident detail"}
        right={incident && <SeverityTag level={incident.severity} />}>
        {!incident ? (
          <div className="p-6 text-sm text-muted">Waiting for a detected incident…</div>
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 px-3 py-3 border-b border-edge">
              <Field k="Status" v={
                scoreboard?.resolved ? "Resolved · detection quiet"
                  : scoreboard?.remediated ? "Containment applied · verifying…"
                    : scoreboard?.time_to_contain_s ? "Contained"
                      : "Open · pending"} />
              <Field k="Pivot" v={`ews · ${incident.pivot}`} mono />
              <Field k="Time to detect" v={scoreboard?.time_to_detect_s != null ? `${scoreboard.time_to_detect_s}s` : "—"} mono />
              <Field k="Time to contain" v={scoreboard?.time_to_contain_s != null ? `${scoreboard.time_to_contain_s}s` : "—"} mono />
              <Field k="Domains" v={(incident.domains || []).join(" + ")} />
              <Field k="Techniques" v={`${incident.techniques?.length || 0}`} />
              <Field k="Events" v={`${scoreboard?.it_events ?? 0} IT / ${scoreboard?.ot_events ?? 0} OT`} />
              <Field k="Detector" v="Zeek + ICSNPP" />
            </div>

            <KillChain events={events} />

            <div className="px-3 py-3 border-b border-edge">
              <div className="text-2xs uppercase tracking-wider text-muted mb-2">Correlated events ({events.length})</div>
              <table className="tbl mono text-xs">
                <thead><tr><th>sev</th><th>rule</th><th>src → dst</th><th>att&ck</th><th>n</th></tr></thead>
                <tbody>{events.map((e) => <EventRow key={e.id} e={e} />)}</tbody>
              </table>
            </div>

            <div className="px-3 py-3 border-b border-edge">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-2xs uppercase tracking-wider text-muted">AI agent pipeline</span>
                <PipelineRail states={pipelineStates(agents, events.length > 0)} />
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-2">
                {(() => {
                  const st = pipelineStates(agents, events.length > 0);
                  const by = Object.fromEntries(st.map((s) => [s.key, s]));
                  return (
                    <>
                      <AgentCard title="Triage" state={by.triage.state} data={by.triage.data} render={(t) => (
                        <div><div className="flex items-center gap-2"><SeverityTag level={t.severity} /><span className="chip">{t.priority}</span>
                          {t.confidence != null && <span className="ml-auto text-2xs text-muted">conf {Math.round(t.confidence * 100)}%</span>}</div>
                          <div className="text-xs mt-1 font-medium">{t.headline}</div>
                          <div className="text-2xs text-muted mt-0.5">At risk: {t.process_at_risk}</div>
                          <div className="text-2xs text-muted mt-1 whitespace-pre-wrap">{t.rationale}</div></div>
                      )} />
                      <AgentCard title="Investigation" state={by.investigation.state} data={by.investigation.data} render={(i) => (
                        <div><div className="text-2xs text-muted whitespace-pre-wrap">{i.narrative}</div>
                          {i.it_ot_link && <div className="text-2xs mt-1"><span className="text-accent">IT/OT link: </span>{i.it_ot_link}</div>}
                          <div className="mt-1 flex flex-col gap-0.5">
                            {(i.attack_chain || []).map((c, n) => (
                              <div key={n} className="text-2xs"><span className="mono text-muted">{c.technique_id}</span> {c.technique_name} <span className="text-muted">· {c.tactic}</span></div>
                            ))}
                          </div></div>
                      )} />
                      <AgentCard title="Response" state={by.response.state} data={by.response.data} render={(r) => (
                        <div className="text-2xs text-muted whitespace-pre-wrap">{r.summary}</div>
                      )} />
                    </>
                  );
                })()}
              </div>
            </div>

            <div className="px-3 py-3">
              <div className="text-2xs uppercase tracking-wider text-muted mb-2">Response actions · human gate</div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
                {actions.map((a) => (
                  <ActionRow key={a.name} a={a} busy={busyAction === a.name}
                    onApply={doApply} onRequestApprove={setConfirm}
                    canApprove={canApprove} canApply={canApply} />
                ))}
                {actions.length === 0 && <div className="text-2xs text-muted">No actions yet — response agent running…</div>}
              </div>
            </div>

            <PlaybookPanel incidentId={incident.id} actions={actions} busyAction={busyAction}
              onApply={doApply} onRequestApprove={setConfirm} canApprove={canApprove} canApply={canApply} />

            <DecisionLog incidentId={incident.id}
              version={actions.filter((a) => a.status === "approved" || a.status === "executed").length} />

            <div className="px-3 py-3 border-t border-edge">
              <CasePanel incidentId={incident.id} />
            </div>
          </>
        )}
      </Panel>

      {/* Drag handle to resize the analyst chat (only when open) */}
      {chatOpen && (
        <div onMouseDown={startDrag} title="Drag to resize · double-click to reset"
          onDoubleClick={() => setChatW(380)}
          className="w-1.5 shrink-0 rounded cursor-col-resize bg-edge hover:bg-brand/70 active:bg-brand transition-colors" />
      )}
      <AnalystChat open={chatOpen} width={chatW} onToggle={() => setChatOpen((v) => !v)} />

      <AnimatePresence>
        {confirm && (
          <ConfirmApproval action={confirm} onConfirm={confirmApprove} onCancel={() => setConfirm(null)} />
        )}
      </AnimatePresence>
    </div>
  );
}
