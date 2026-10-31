// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useRef, useState, useEffect } from "react";
import { Panel } from "../ui/primitives.jsx";
import Icon from "../ui/Icon.jsx";
import { useSoc } from "./store.jsx";
import { streamChat } from "./chatClient.js";

// Attack-specific prompts only make sense once an incident exists; at baseline the
// chat must NOT presuppose an attack. Pick the set based on whether a case is loaded.
const STARTERS_INCIDENT = [
  "Which host is the pivot and why is this critical?",
  "Walk me through the IT→OT kill chain.",
  "What should we do to contain this?",
  "Which actions need human approval and why?",
];
const STARTERS_BASELINE = [
  "What assets are in this environment?",
  "Which detection rules are active?",
  "What is the live process state right now?",
  "Is there any active incident?",
];

// Render rule-name / ATT&CK citations as CLICKABLE chips that focus the matching
// evidence row in the incident's event table (grounded, not just colored text).
function renderCited(text, onCite, kp = "") {
  const parts = text.split(/(\b[a-z]+\.[a-z_]+\b|\bT0\d{3}\b)/g);
  return parts.map((p, i) => {
    const isCite = /^[a-z]+\.[a-z_]+$/.test(p) || /^T0\d{3}$/.test(p);
    if (!isCite) return <span key={`${kp}c${i}`}>{p}</span>;
    // The rules carry an "ot."/"it." prefix the events drop — match on the bare name.
    const token = p.replace(/^(ot|it)\./, "");
    return (
      <button key={`${kp}c${i}`} onClick={() => onCite?.(token)} title="Show the evidence for this"
        className="mono text-accent hover:underline underline-offset-2 decoration-dotted cursor-pointer">
        {p}
      </button>
    );
  });
}

// Inline markdown: **bold**, `code`, then citations inside the plain runs.
function renderInline(text, onCite, kp) {
  const toks = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return toks.map((t, i) => {
    if (/^\*\*[^*]+\*\*$/.test(t))
      return <strong key={`${kp}b${i}`} className="font-semibold text-text">{renderCited(t.slice(2, -2), onCite, `${kp}b${i}`)}</strong>;
    if (/^`[^`]+`$/.test(t))
      return <code key={`${kp}k${i}`} className="mono text-2xs bg-panel2 border border-edge rounded px-1 py-0.5">{t.slice(1, -1)}</code>;
    return <span key={`${kp}t${i}`}>{renderCited(t, onCite, `${kp}t${i}`)}</span>;
  });
}

// Block-level markdown: headings, bullet + numbered lists, paragraphs. Parses the
// CURRENT text each render, so it formats correctly as the reply streams in.
function renderMarkdown(text, onCite) {
  const lines = (text || "").split("\n");
  const out = [];
  let list = null;   // { ordered, items: [] }
  const flush = () => {
    if (!list) return;
    const Tag = list.ordered ? "ol" : "ul";
    out.push(
      <Tag key={`l${out.length}`} className={`${list.ordered ? "list-decimal" : "list-disc"} pl-5 my-1 space-y-1 marker:text-faint`}>
        {list.items.map((it, j) => <li key={j} className="pl-0.5">{renderInline(it, onCite, `l${out.length}-${j}-`)}</li>)}
      </Tag>);
    list = null;
  };
  lines.forEach((line) => {
    const bullet = line.match(/^\s*[-*]\s+(.*)/);
    const numbered = line.match(/^\s*\d+[.)]\s+(.*)/);
    const heading = line.match(/^\s*(#{1,3})\s+(.*)/);
    if (bullet) {
      if (!list || list.ordered) { flush(); list = { ordered: false, items: [] }; }
      list.items.push(bullet[1]);
    } else if (numbered) {
      if (!list || !list.ordered) { flush(); list = { ordered: true, items: [] }; }
      list.items.push(numbered[1]);
    } else if (heading) {
      flush();
      out.push(<div key={`h${out.length}`} className="font-semibold text-text mt-2 mb-0.5">{renderInline(heading[2], onCite, `h${out.length}-`)}</div>);
    } else if (line.trim() === "") {
      flush();
      out.push(<div key={`s${out.length}`} className="h-1.5" />);
    } else {
      flush();
      out.push(<p key={`p${out.length}`} className="my-0.5">{renderInline(line, onCite, `p${out.length}-`)}</p>);
    }
  });
  flush();
  return out;
}

function ProposedAction({ a }) {
  const { apply, approve } = useSoc();
  const [status, setStatus] = useState(null);
  const [verify, setVerify] = useState(null);
  const gated = a.requires_human_approval;
  const run = async () => {
    setStatus("running");
    const r = await (gated ? approve(a.name) : apply(a.name));
    setStatus(r?.ok ? "done" : "failed");
    if (r?.verified) setVerify(r.verified);
  };
  return (
    <div className={`panel p-2 mt-2 border-l-2 ${gated ? "border-l-crit" : "border-l-low"}`}>
      <div className="flex items-center gap-2">
        <span className={`sev ${gated ? "sev-critical" : "sev-low"}`}>{gated ? "gated" : "auto"}</span>
        <span className="text-xs font-medium">{a.title || a.name}</span>
        <span className="ml-auto text-2xs text-muted">{status === "done" ? "✓ executed" : status || ""}</span>
      </div>
      {a.note && <div className="text-2xs text-muted mt-1">{a.note}</div>}
      {verify && <div className={`text-2xs mt-1 ${verify.ok ? "text-ok" : "text-crit"}`}>
        {verify.ok ? "✓ verified — " : "⚠ NOT verified — "}{verify.detail}</div>}
      {status !== "done" && (
        <button onClick={run} disabled={status === "running"}
          className={`mt-2 h-6 px-2 text-2xs font-semibold border disabled:opacity-50 ${
            gated ? "border-ok/60 text-ok hover:bg-ok/10" : "border-accent/60 text-accent hover:bg-accent/10"}`}>
          {status === "running" ? "…" : gated ? "Approve & execute" : "Apply"}
        </button>
      )}
    </div>
  );
}

function Turn({ m }) {
  const [showThink, setShowThink] = useState(false);
  const { setCite } = useSoc();
  if (m.role === "user")
    return <div className="panel p-2 text-sm bg-panel2">{m.content}</div>;
  return (
    <div className="text-sm">
      {m.tools?.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-1">
          {m.tools.map((t, i) => <span key={i} className="chip text-2xs">⚙ {t.name || t.error}</span>)}
        </div>
      )}
      {m.thinking && (
        <button onClick={() => setShowThink((v) => !v)} className="text-2xs text-muted hover:text-text mb-1">
          {showThink ? "▾ hide reasoning" : "▸ reasoning"}
        </button>
      )}
      {showThink && <pre className="text-2xs mono text-muted whitespace-pre-wrap mb-1 max-h-40 overflow-auto border-l border-edge pl-2">{m.thinking}</pre>}
      <div className="leading-relaxed">
        {m.content ? renderMarkdown(m.content, setCite) : (m.streaming
          ? <span className="text-muted animate-pulse">{m.thinking ? "analyzing…" : "…"}</span> : null)}
        {m.content && m.streaming && <span className="inline-block w-1.5 h-3.5 -mb-0.5 ml-0.5 bg-brand/70 animate-pulse" />}
      </div>
      {m.actions?.map((a) => <ProposedAction key={a.name} a={a} />)}
    </div>
  );
}

export default function AnalystChat({ open, onToggle, width = 360 }) {
  const { incident } = useSoc();
  const [msgs, setMsgs] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [plain, setPlain] = useState(true);   // plain-language (non-technical) by default
  const endRef = useRef(null);
  useEffect(() => { endRef.current?.scrollIntoView(); }, [msgs]);

  // Optional deep-link: /?ask=<question> auto-sends once the incident is loaded
  // (handy for demos/screenshots). Fires a single time.
  const asked = useRef(false);
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get("ask");
    if (q && incident?.id && !asked.current) { asked.current = true; send(q); }
  }, [incident]);   // eslint-disable-line react-hooks/exhaustive-deps

  const ctrlRef = useRef(null);
  const stop = () => ctrlRef.current?.abort();

  const send = async (text) => {
    if (!text.trim() || busy) return;
    setBusy(true);
    setInput("");
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    const history = msgs.filter((m) => m.content).map((m) => ({ role: m.role, content: m.content }));
    setMsgs((prev) => [...prev, { role: "user", content: text },
                       { role: "assistant", content: "", thinking: "", tools: [], actions: [], streaming: true }]);
    const upd = (fn) => setMsgs((prev) => { const n = prev.slice(); n[n.length - 1] = fn(n[n.length - 1]); return n; });
    try {
      await streamChat({
        message: text, history, incidentId: incident?.id, plain, signal: ctrl.signal,
        onThink: (t) => upd((m) => ({ ...m, thinking: m.thinking + t })),
        onTool: (t) => upd((m) => ({ ...m, tools: [...m.tools, t] })),
        onToken: (t) => upd((m) => ({ ...m, content: m.content + t })),
        onActions: (a) => upd((m) => ({ ...m, actions: a })),
        onDone: () => upd((m) => ({ ...m, streaming: false })),
      });
    } catch (e) {
      if (e?.name === "AbortError") {
        upd((m) => ({ ...m, content: m.content + " ⏹ stopped", streaming: false }));
      } else {
        upd((m) => ({ ...m, content: m.content || `⚠ chat unavailable — ${e?.message || "request failed"}`, streaming: false }));
      }
    }
    ctrlRef.current = null;
    setBusy(false);
  };

  if (!open) {
    return (
      <button onClick={onToggle} title="Open analyst chat"
        className="w-8 shrink-0 panel flex flex-col items-center justify-center text-muted hover:text-brand">
        <Icon name="chevron" />
        <span className="text-2xs [writing-mode:vertical-rl] mt-2 tracking-wider uppercase">Analyst</span>
      </button>
    );
  }
  return (
    <Panel className="shrink-0" style={{ width }} title="Analyst Chat"
      right={
        <div className="flex items-center gap-2">
          <div className="flex rounded-sm overflow-hidden border border-edge2 text-2xs">
            <button onClick={() => setPlain(true)}
              className={`px-2 h-5 ${plain ? "bg-brand/15 text-brand" : "text-muted hover:text-text"}`}>Plain</button>
            <button onClick={() => setPlain(false)}
              className={`px-2 h-5 border-l border-edge2 ${!plain ? "bg-brand/15 text-brand" : "text-muted hover:text-text"}`}>Analyst</button>
          </div>
          <button onClick={onToggle} className="text-muted hover:text-text rotate-180"><Icon name="chevron" /></button>
        </div>
      }
      bodyClass="flex flex-col flex-1 min-h-0">
      <div className="flex-1 overflow-auto p-3 space-y-3 min-h-0">
        {msgs.length === 0 && (
          <div className="space-y-2">
            <div className="text-xs text-muted">
              {incident?.id
                ? <>Grounded in <span className="mono text-brand">{incident.id}</span> with read-only tools (events, assets, rules, live state).</>
                : "No active incident — the plant is at baseline. Ask about assets, rules, or live process state (read-only)."}
            </div>
            <div className="flex flex-col gap-1">
              {(incident?.id ? STARTERS_INCIDENT : STARTERS_BASELINE).map((q) => (
                <button key={q} onClick={() => send(q)} className="text-left chip hover:border-brand hover:text-text">{q}</button>
              ))}
            </div>
          </div>
        )}
        {msgs.map((m, i) => <Turn key={i} m={m} />)}
        <div ref={endRef} />
      </div>
      <form className="p-2 border-t border-edge flex gap-2" onSubmit={(e) => { e.preventDefault(); send(input); }}>
        <input value={input} onChange={(e) => setInput(e.target.value)} disabled={busy}
          placeholder={busy ? "thinking…" : "Ask the analyst…"}
          className="flex-1 bg-panel2 border border-edge px-2 h-8 text-sm outline-none placeholder:text-muted disabled:opacity-60" />
        {busy
          ? <button type="button" onClick={stop} title="Stop generating"
              className="shrink-0 h-8 px-3 text-2xs font-semibold border border-crit/60 text-crit hover:bg-crit/10">Stop</button>
          : <button type="submit" disabled={!input.trim()} title="Send"
              className="shrink-0 h-8 px-3 text-2xs font-semibold border border-brand/60 text-brand hover:bg-brand/10 disabled:opacity-40">Send</button>}
      </form>
    </Panel>
  );
}
