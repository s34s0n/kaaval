// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { Panel } from "../ui/primitives.jsx";
import Icon from "../ui/Icon.jsx";
import { useSoc } from "./store.jsx";

// Case management for a NON-EXPERT operator: a plain-language status, who-it's-
// assigned-to, simple lifecycle buttons, a readable chain-of-custody timeline, and
// a one-click AI-drafted report they edit + sign off. No jargon where avoidable.

const STATE_TONE = {
  open: "text-high border-high/50 bg-high/10",
  investigating: "text-brand border-brand/50 bg-brand/10",
  contained: "text-low border-low/50 bg-low/10",
  resolved: "text-ok border-ok/50 bg-ok/10",
  closed: "text-muted border-edge bg-panel2/50",
};
const STATE_WORDS = { open: "Open", investigating: "Being investigated", contained: "Contained",
  resolved: "Resolved", closed: "Closed" };
const HKIND = { assign: "assets", comment: "chevron", transition: "pivot", close: "shield",
  reopen: "reset", report: "report", rogue: "bolt" };
const DISPOSITIONS = [
  ["true_positive_remediated", "Real attack — fixed"],
  ["true_positive_unresolved", "Real attack — not yet fixed"],
  ["false_positive", "False alarm"],
  ["benign", "Benign / expected activity"],
  ["duplicate", "Duplicate of another case"],
];

function fmt(ts) { try { return ts ? new Date(ts * 1000).toLocaleString() : ""; } catch { return ""; } }

function TimelineItem({ h }) {
  return (
    <div className="flex gap-2.5">
      <div className="flex flex-col items-center">
        <span className="w-6 h-6 rounded-full bg-panel2 border border-edge2 flex items-center justify-center text-faint shrink-0">
          <Icon name={HKIND[h.kind] || "chevron"} size={12} />
        </span>
        <span className="w-px flex-1 bg-edge my-1" />
      </div>
      <div className="pb-3 min-w-0">
        <div className="text-xs text-text leading-snug">{h.detail}</div>
        <div className="text-2xs text-faint mt-0.5">
          <span className="text-muted">{h.actor}</span>
          <span className="ml-1 uppercase text-[9px] text-brand">{h.role}</span>
          <span className="ml-2">{fmt(h.ts)}</span>
        </div>
      </div>
    </div>
  );
}

export default function CasePanel({ incidentId }) {
  const soc = useSoc();
  const { principal } = soc;
  const canApprove = !!principal?.can?.approve;
  const canWork = !!principal?.authenticated;
  const [cw, setCw] = useState(null);
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [reason, setReason] = useState("");
  const [toState, setToState] = useState("contained");
  const [disp, setDisp] = useState(DISPOSITIONS[0][0]);
  const [report, setReport] = useState(null);
  const [reportMd, setReportMd] = useState("");
  const [rogue, setRogue] = useState([]);
  const [busy, setBusy] = useState("");

  const refresh = async () => { const d = await soc.getCase(incidentId); if (d) { setCw(d.case); setRogue(d.incident?.rogue_devices || []); } };
  useEffect(() => { refresh(); soc.getReport(incidentId).then((r) => { if (r) { setReport(r); setReportMd(r.markdown || ""); } }); /* eslint-disable-next-line */ }, [incidentId]);
  if (!cw) return null;

  const act = async (key, fn) => { setBusy(key); try { const r = await fn(); if (r?.history) setCw(r); else if (r?.case) setCw(r.case); } finally { setBusy(""); setReason(""); setNote(""); } };
  const draft = async () => {
    setBusy("draft");
    const r = await soc.draftReport(incidentId);
    if (r?.markdown) { setReportMd(r.markdown); setReport({ markdown: r.markdown, status: "draft", source: r.narrative_source }); if (r.case) setCw(r.case); }
    setBusy("");
  };
  const saveReport = async () => { setBusy("save"); await soc.saveReport(incidentId, reportMd); setReport((p) => ({ ...p, markdown: reportMd, status: "draft" })); setBusy(""); };
  const signoff = async () => { setBusy("signoff"); const r = await soc.signoffReport(incidentId); if (r?.case) setCw(r.case); setReport((p) => ({ ...p, status: "final" })); setBusy(""); };
  const dl = (kind) => window.open(`/api/cases/${encodeURIComponent(incidentId)}/report.${kind}`, "_blank");

  const tone = STATE_TONE[cw.state] || STATE_TONE.open;
  const closed = cw.state === "closed";

  return (
    <Panel title="Case management" bodyClass="p-3 space-y-3"
      right={<span className={`pill text-2xs ${tone}`}>{STATE_WORDS[cw.state] || cw.state}</span>}>
      {/* durable rogue-device attribute — survives after the transient alert ages out */}
      {rogue.length > 0 && (
        <div className="rounded-sm border border-crit/40 bg-crit/5 px-3 py-2">
          <div className="flex items-center gap-1.5 text-2xs uppercase tracking-wider text-crit">
            <Icon name="bolt" size={12} /> Rogue devices involved
          </div>
          <div className="flex flex-wrap gap-1.5 mt-1.5">
            {rogue.map((ip) => <span key={ip} className="pill text-2xs mono text-crit border-crit/50">{ip}</span>)}
          </div>
          <div className="text-2xs text-faint mt-1">Unmanaged host(s) on the segment, not in the asset inventory — recorded at formation; persists for the case lifecycle.</div>
        </div>
      )}
      {/* status + assignee */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-muted">Assigned to:</span>
        <span className="text-text">{cw.assignee || "nobody yet"}</span>
        {canWork && (
          <span className="flex items-center gap-1 ml-auto">
            <input value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder={principal?.name || "name"}
              className="bg-panel2 border border-edge h-6 px-2 text-2xs outline-none w-28" />
            <button disabled={busy} onClick={() => act("assign", () => soc.assignCase(incidentId, assignee || principal?.name))}
              className="btn h-6 text-2xs">Assign</button>
          </span>
        )}
      </div>
      {closed && <div className="text-2xs text-muted">Closed by <span className="text-text">{cw.closed_by}</span> · {DISPOSITIONS.find((d) => d[0] === cw.disposition)?.[1] || cw.disposition} · {fmt(cw.closed_ts)}</div>}

      {/* lifecycle controls — plain language, role-aware */}
      {canWork && !closed && (
        <div className="rounded-sm border border-edge bg-panel2/40 p-2 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-2xs text-muted">Move to:</span>
            <select value={toState} onChange={(e) => setToState(e.target.value)} className="bg-panel2 border border-edge h-6 px-1 text-2xs outline-none">
              <option value="investigating">Being investigated</option>
              <option value="contained">Contained</option>
              <option value="resolved">Resolved</option>
            </select>
            <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="reason (logged)"
              className="bg-panel2 border border-edge h-6 px-2 text-2xs outline-none flex-1 min-w-[120px]" />
            <button disabled={busy} onClick={() => act("trans", () => soc.transitionCase(incidentId, toState, reason))} className="btn h-6 text-2xs">Update</button>
          </div>
          <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-edge/60">
            <span className="text-2xs text-muted">Close as:</span>
            <select value={disp} onChange={(e) => setDisp(e.target.value)} className="bg-panel2 border border-edge h-6 px-1 text-2xs outline-none">
              {DISPOSITIONS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
            {canApprove
              ? <button disabled={busy} onClick={() => act("close", () => soc.closeCase(incidentId, disp, reason))} className="btn h-6 text-2xs border-ok/60 text-ok">Close case</button>
              : <button disabled title="Closing a case requires the approver role" className="btn h-6 text-2xs opacity-50 cursor-not-allowed">Close · requires approver</button>}
          </div>
        </div>
      )}
      {canApprove && closed && (
        <button disabled={busy} onClick={() => act("reopen", () => soc.reopenCase(incidentId, reason || "reopened for review"))} className="btn h-6 text-2xs">Reopen case</button>
      )}

      {/* add a note */}
      {canWork && (
        <div className="flex gap-2">
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note to the case…"
            onKeyDown={(e) => { if (e.key === "Enter" && note.trim()) act("note", () => soc.commentCase(incidentId, note)); }}
            className="bg-panel2 border border-edge h-7 px-2 text-xs outline-none flex-1" />
          <button disabled={busy || !note.trim()} onClick={() => act("note", () => soc.commentCase(incidentId, note))} className="btn h-7 text-2xs">Add note</button>
        </div>
      )}

      {/* chain-of-custody timeline */}
      <div>
        <div className="text-2xs uppercase tracking-wider text-muted mb-2">Case activity · who did what, when</div>
        {cw.history?.length
          ? <div className="pl-0.5">{cw.history.map((h, i) => <TimelineItem key={i} h={h} />)}</div>
          : <div className="text-2xs text-faint">No activity yet — assign the case and add a note to start the record.</div>}
      </div>

      {/* incident report — AI draft → edit → sign off */}
      <div className="rounded-sm border border-edge bg-panel2/40 p-2 space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-2xs uppercase tracking-wider text-muted">Incident report</span>
          {report?.status && <span className={`pill text-2xs ${report.status === "final" ? "text-ok border-ok/50" : "text-high border-high/50"}`}>{report.status === "final" ? `signed off · ${cw.report_by}` : "draft"}</span>}
          {report?.source && <span className="text-[9px] text-faint">{report.source}</span>}
          <span className="ml-auto flex items-center gap-1.5">
            {canWork && <button disabled={busy} onClick={draft} className="btn h-6 text-2xs">{busy === "draft" ? "drafting…" : "Generate draft (AI)"}</button>}
            {report?.markdown && <button onClick={() => dl("pdf")} className="btn h-6 text-2xs"><Icon name="report" size={11} /> PDF</button>}
            {report?.markdown && <button onClick={() => dl("docx")} className="btn h-6 text-2xs"><Icon name="report" size={11} /> DOCX</button>}
          </span>
        </div>
        {report?.markdown != null && (
          <>
            <textarea value={reportMd} onChange={(e) => setReportMd(e.target.value)} disabled={report.status === "final"}
              className="w-full h-44 bg-panel border border-edge rounded-sm p-2 text-2xs mono text-text outline-none disabled:opacity-70" />
            <div className="flex items-center gap-2">
              {canWork && report.status !== "final" && <button disabled={busy} onClick={saveReport} className="btn h-6 text-2xs">{busy === "save" ? "saving…" : "Save edits"}</button>}
              {report.status !== "final" && (canApprove
                ? <button disabled={busy} onClick={signoff} className="btn h-6 text-2xs border-ok/60 text-ok">{busy === "signoff" ? "…" : "Sign off (final)"}</button>
                : <button disabled title="Signing off requires the approver role" className="btn h-6 text-2xs opacity-50 cursor-not-allowed">Sign off · requires approver</button>)}
              <span className="text-2xs text-faint">Facts &amp; timeline are from the incident store; the prose is AI-assisted and editable — a draft until signed off.</span>
            </div>
          </>
        )}
      </div>

      {/* one-click evidence trace (F2 / F4) */}
      <div className="flex items-center gap-3 text-2xs">
        <span className="text-muted">Evidence trace:</span>
        <a href="?view=compliance" className="text-brand hover:underline">Compliance evidence →</a>
        <a href="?view=purdue" className="text-brand hover:underline">Network pivot (Purdue) →</a>
      </div>
    </Panel>
  );
}
