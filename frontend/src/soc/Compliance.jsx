// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useMemo, useState } from "react";
import { Panel } from "../ui/primitives.jsx";
import Icon from "../ui/Icon.jsx";

// Compliance reporting. Statuses are computed server-side from recorded evidence
// (detections, the immutable approval/egress audit logs, the asset inventory) —
// never from the model. The convincing moment: click a control to reveal the
// actual records its MET/GAP/NOT-ASSESSED claim is traced to.

const STATUS = {
  MET:          { label: "MET",          cls: "text-ok border-ok/50 bg-ok/10",        dot: "dot-ok" },
  GAP:          { label: "GAP",          cls: "text-crit border-crit/50 bg-crit/10",  dot: "dot-breached" },
  NOT_ASSESSED: { label: "NOT ASSESSED", cls: "text-muted border-edge bg-panel2/40",  dot: "" },
};

const EV_LABEL = {
  approval: "approval record", incident: "incident", asset: "asset", event: "detection event",
  audit: "audit channel", config: "configuration",
};

function fmtTs(ts) {
  if (!ts) return null;
  try { return new Date(ts * 1000).toLocaleString(); } catch { return null; }
}

function EvidenceRecord({ e }) {
  const ts = fmtTs(e.ts);
  return (
    <div className="rounded-sm border border-edge bg-panel2/50 px-2.5 py-1.5">
      <div className="flex items-center gap-2">
        <span className="pill text-2xs text-brand border-brand/40">{EV_LABEL[e.type] || e.type}</span>
        <span className="mono text-2xs text-text truncate">{e.ref}</span>
        {ts && <span className="ml-auto text-2xs text-faint mono shrink-0">{ts}</span>}
      </div>
      <div className="text-xs text-muted mt-1 leading-snug">{e.detail}</div>
    </div>
  );
}

function ControlRow({ c, open, onToggle }) {
  const s = STATUS[c.status] || STATUS.NOT_ASSESSED;
  const hasEvidence = (c.evidence || []).length > 0;
  return (
    <div className={`rounded-sm border ${open ? "border-edge2" : "border-edge"} bg-panel`}>
      <button onClick={onToggle}
        className="w-full flex items-start gap-3 px-3 py-2 text-left hover:bg-panel2/50 transition-colors">
        <span className={`mt-0.5 shrink-0 transition-transform ${open ? "rotate-90" : ""} text-faint`}>
          <Icon name="chevron" size={12} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="mono text-2xs text-muted shrink-0">{c.id}</span>
            <span className="text-sm text-text truncate">{c.title}</span>
          </div>
          <div className="text-2xs text-faint mt-0.5">{c.family}</div>
        </div>
        <span className={`shrink-0 pill text-2xs ${s.cls}`}>
          {s.dot && <span className={`dot ${s.dot}`} />}{s.label}
        </span>
      </button>
      {open && (
        <div className="px-3 pb-3 pl-8 space-y-2">
          <div className="text-xs text-muted leading-snug">{c.rationale}</div>
          {hasEvidence ? (
            <div className="space-y-1.5">
              <div className="text-2xs uppercase tracking-wider text-faint">
                Traced to {c.evidence.length} record{c.evidence.length > 1 ? "s" : ""}
              </div>
              {c.evidence.map((e, i) => <EvidenceRecord key={i} e={e} />)}
            </div>
          ) : (
            <div className="text-2xs text-faint italic">
              Not observable from network/SOC telemetry — assess by separate review.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function Compliance() {
  const [frameworks, setFrameworks] = useState([]);
  const [fw, setFw] = useState(null);
  const [aiSummary, setAiSummary] = useState(false);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [openIds, setOpenIds] = useState(() => new Set());
  const [busy, setBusy] = useState("");

  useEffect(() => {
    fetch("/api/compliance/frameworks").then((r) => r.json())
      .then((d) => { setFrameworks(d.frameworks || []); setFw((d.frameworks || [])[0]?.id || null); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!fw) return;
    setLoading(true); setReport(null);
    fetch(`/api/compliance/report?framework=${encodeURIComponent(fw)}&narrative=${aiSummary ? 1 : 0}`)
      .then((r) => r.json())
      .then((d) => {
        setReport(d);
        // auto-open the first MET control so the evidence trace is visible immediately
        const firstMet = (d.controls || []).find((c) => c.status === "MET");
        setOpenIds(new Set(firstMet ? [firstMet.id] : []));
      })
      .catch(() => setReport({ error: "report unavailable" }))
      .finally(() => setLoading(false));
  }, [fw, aiSummary]);

  const download = async (kind) => {
    if (!fw) return;
    setBusy(kind);
    try {
      const res = await fetch(`/api/compliance/report.${kind}?framework=${encodeURIComponent(fw)}&narrative=${aiSummary ? 1 : 0}`);
      if (!res.ok) throw new Error();
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `kaaval-compliance-${fw}.${kind}`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(a.href);
    } catch { /* surfaced by the disabled state; keep silent */ }
    setBusy("");
  };

  const toggle = (id) => setOpenIds((prev) => {
    const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next;
  });

  const s = report?.summary || {};
  const meta = report?.framework || {};
  const tiles = useMemo(() => ([
    ["Met", s.MET || 0, "text-ok"], ["Gaps", s.GAP || 0, "text-crit"],
    ["Not assessed", s.NOT_ASSESSED || 0, "text-muted"], ["Controls", s.total || 0, "text-text"],
  ]), [s]);

  return (
    <div className="p-2 h-full overflow-auto space-y-2">
      {/* framework picker + actions */}
      <div className="panel px-3 py-2.5 flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap gap-1.5">
          {frameworks.map((f) => (
            <button key={f.id} onClick={() => setFw(f.id)}
              className={`pill text-xs ${fw === f.id ? "text-brand border-brand/60 bg-brand/10" : "text-muted border-edge hover:text-text"}`}>
              {f.name}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-2xs text-muted cursor-pointer select-none">
            <input type="checkbox" checked={aiSummary} onChange={(e) => setAiSummary(e.target.checked)}
              className="accent-brand" />
            AI executive summary
          </label>
          <button disabled={!report || report.error || busy} onClick={() => download("pdf")}
            className="pill text-xs text-text border-edge hover:border-brand/60 hover:text-brand disabled:opacity-40">
            <Icon name="report" size={12} /> {busy === "pdf" ? "…" : "PDF"}
          </button>
          <button disabled={!report || report.error || busy} onClick={() => download("docx")}
            className="pill text-xs text-text border-edge hover:border-brand/60 hover:text-brand disabled:opacity-40">
            <Icon name="report" size={12} /> {busy === "docx" ? "…" : "DOCX"}
          </button>
        </div>
      </div>

      {loading && <div className="text-xs text-muted px-1 py-6 text-center">Assessing controls against recorded evidence…</div>}
      {report?.error && <div className="text-xs text-crit px-1 py-6 text-center">Report unavailable.</div>}

      {report && !report.error && (
        <>
          {/* header + posture */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
            {tiles.map(([k, v, col]) => (
              <div key={k} className="panel px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.14em] text-faint">{k}</div>
                <div className={`text-lg font-semibold tabular-nums mt-0.5 ${col}`}>{v}</div>
              </div>
            ))}
          </div>

          <Panel
            title={`${meta.name} · ${meta.version || ""}`}
            right={<span className="text-2xs text-faint">{meta.authority} · {report.site}</span>}
            bodyClass="p-3 space-y-2">
            <div className="rounded-sm border border-edge bg-panel2/40 px-3 py-2">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-2xs uppercase tracking-wider text-faint">Executive summary</span>
                <span className={`pill text-2xs ${report.narrative?.source?.startsWith("llm") ? "text-high border-high/50" : "text-muted border-edge"}`}>
                  {report.narrative?.source?.startsWith("llm") ? "AI-assisted prose" : "deterministic"}
                </span>
              </div>
              <div className="text-xs text-text leading-relaxed">{report.narrative?.text}</div>
            </div>
            <div className="text-2xs text-muted leading-snug">
              Statuses are computed from recorded evidence, not the model. Click any control to trace its claim to the
              source record. <span className="text-faint">"Not assessed" is not a pass — it marks controls not observable from telemetry.</span>
            </div>
          </Panel>

          {/* controls with evidence click-through */}
          <Panel title="Control assessment · evidence-traced" bodyClass="p-2 space-y-1.5">
            {(report.controls || []).map((c) => (
              <ControlRow key={c.id} c={c} open={openIds.has(c.id)} onToggle={() => toggle(c.id)} />
            ))}
          </Panel>
        </>
      )}
    </div>
  );
}
