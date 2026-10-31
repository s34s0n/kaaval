// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { Panel } from "../ui/primitives.jsx";
import { useSoc } from "./store.jsx";

function LLMSettings() {
  const { getLLM, setLLM } = useSoc();
  const [s, setS] = useState(null);          // server status
  const [provider, setProvider] = useState("local");
  const [model, setModel] = useState("");
  const [key, setKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  const load = async () => {
    const d = await getLLM();
    if (!d) return;
    setS(d); setProvider(d.provider);
    setModel(d.provider === "local" ? (d.options?.local?.[0] || "") : d.model);
  };
  useEffect(() => { load(); }, []);          // eslint-disable-line react-hooks/exhaustive-deps

  const save = async () => {
    setSaving(true); setMsg("");
    const patch = { provider };
    if (provider === "anthropic") {
      patch.anthropic_model = model || s?.options?.anthropic?.[0];
      if (key.trim()) patch.anthropic_api_key = key.trim();
    } else if (provider === "openrouter") {
      patch.openrouter_model = model || s?.options?.openrouter?.[0];
      if (key.trim()) patch.openrouter_api_key = key.trim();
    } else {
      patch.local_model = model || s?.options?.local?.[0];
    }
    const r = await setLLM(patch);
    setSaving(false);
    if (r?.ok) {
      setKey("");
      const t = r.test || {};
      setMsg(t.ok ? `Saved · ${t.detail || "ready"}` : `Saved, but the provider test FAILED — ${t.detail || "unknown error"}`);
      await load();
    } else setMsg(r?.error || "failed");
  };

  const opts = s?.options?.[provider] || s?.options?.local || [];
  const needsKey = provider === "anthropic" || provider === "openrouter";
  const keyLabel = provider === "openrouter" ? "OpenRouter API key" : "Anthropic API key";
  const keyPlaceholder = provider === "openrouter" ? "sk-or-v1-…" : "sk-ant-…";
  return (
    <Panel title="AI Model · provider" bodyClass="p-3 space-y-3 text-sm">
      <div className="text-xs text-muted">
        Active: <span className="mono text-brand">{s?.model || "…"}</span>
        <span className={`ml-2 pill ${s?.ready ? "text-ok border-ok/50" : "text-crit border-crit/50"}`}>
          <span className={`dot ${s?.ready ? "dot-ok" : "dot-breached"}`} />{s?.ready ? "ready" : "not configured"}
        </span>
        <span className={`ml-2 pill ${s?.offline ? "text-ok border-ok/40" : "text-high border-high/50"}`}>
          {s?.offline ? "offline / on-prem" : "⚠ sends data off-box"}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <button onClick={() => { setProvider("local"); setModel(s?.options?.local?.[0] || ""); }}
          className={`text-left panel p-3 border ${provider === "local" ? "border-brand bg-brand/5" : "border-edge hover:border-edge2"}`}>
          <div className="font-medium flex items-center gap-2">
            <span className="dot" style={{ background: provider === "local" ? "#2EE6A6" : "#4A5670" }} />
            Local (Ollama)
          </div>
          <div className="text-2xs text-muted mt-1">On-device, fully offline / air-gapped. The default and safe choice for OT.</div>
        </button>
        <button onClick={() => { setProvider("openrouter"); setModel(s?.options?.openrouter?.[0] || ""); }}
          className={`text-left panel p-3 border ${provider === "openrouter" ? "border-brand bg-brand/5" : "border-edge hover:border-edge2"}`}>
          <div className="font-medium flex items-center gap-2">
            <span className="dot" style={{ background: provider === "openrouter" ? "#2EE6A6" : "#4A5670" }} />
            OpenRouter
          </div>
          <div className="text-2xs text-muted mt-1">Free hosted models with just an API key — no GPU needed. <span className="text-high">Sends data off-box.</span></div>
        </button>
        <button onClick={() => { setProvider("anthropic"); setModel(s?.options?.anthropic?.[0] || ""); }}
          className={`text-left panel p-3 border ${provider === "anthropic" ? "border-brand bg-brand/5" : "border-edge hover:border-edge2"}`}>
          <div className="font-medium flex items-center gap-2">
            <span className="dot" style={{ background: provider === "anthropic" ? "#2EE6A6" : "#4A5670" }} />
            Claude API
          </div>
          <div className="text-2xs text-high mt-1">⚠ Sends incident data to Anthropic — breaks the offline guarantee.</div>
        </button>
      </div>

      <label className="block">
        <div className="text-2xs uppercase tracking-wider text-muted mb-1">Model</div>
        <select className="inp" value={model} onChange={(e) => setModel(e.target.value)}>
          {opts.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
        {provider === "openrouter" && (
          <div className="text-2xs text-muted mt-1">Free models carry the <span className="mono">:free</span> suffix. Get a key at <span className="mono text-brand">openrouter.ai/keys</span>.</div>
        )}
      </label>

      {needsKey && (
        <label className="block">
          <div className="text-2xs uppercase tracking-wider text-muted mb-1">
            {keyLabel} {s?.has_key && <span className="text-ok">· a key is already set (leave blank to keep)</span>}
          </div>
          <input type="password" className="inp mono" value={key} onChange={(e) => setKey(e.target.value)}
            placeholder={s?.has_key ? "•••••••• (saved)" : keyPlaceholder} autoComplete="off" />
        </label>
      )}

      <div className="flex items-center gap-3">
        <button onClick={save} disabled={saving} className="btn btn-brand">{saving ? "saving…" : "Save & apply"}</button>
        {msg && <span className="text-2xs text-muted">{msg}</span>}
      </div>
      <div className="text-2xs text-muted">
        Applies to all three agents (triage / investigation / response) and the analyst chat. The
        OT-safety gate is enforced in code regardless of which model is used.
      </div>
      <style>{`.inp{width:100%;background:rgb(var(--panel2));border:1px solid rgb(var(--edge));border-radius:3px;height:30px;padding:0 8px;color:rgb(var(--text));outline:none;font-size:13px}`}</style>
    </Panel>
  );
}

function SiemSettings() {
  const { getSiem, setSiem, testSiem, previewSiem, incidentId } = useSoc();
  const [s, setS] = useState(null);
  const [msg, setMsg] = useState("");
  const [cef, setCef] = useState("");
  const load = async () => { const d = await getSiem(); if (d) setS(d); };
  useEffect(() => { load(); }, []);   // eslint-disable-line react-hooks/exhaustive-deps
  if (!s) return null;
  const set = (k) => (e) => setS({ ...s, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const save = async () => {
    setMsg("");
    const r = await setSiem({ enabled: s.enabled, host: s.host, port: +s.port, protocol: s.protocol,
                              facility: +s.facility, verify_tls: s.verify_tls, ca_cert: s.ca_cert });
    if (r && !r.ok && r.error) setMsg(r.error); else { setMsg("Saved"); load(); }
  };
  const test = async () => { setMsg("testing…"); const r = await testSiem(); setMsg(r?.detail || (r?.ok ? "ok" : "failed")); };
  const preview = async () => { const r = await previewSiem(incidentId); setCef(r?.syslog || r?.cef || r?.error || "no incident to preview"); };

  return (
    <Panel title="SIEM / syslog forwarding · CEF" bodyClass="p-3 space-y-3 text-sm">
      <div className="text-2xs text-muted leading-snug">
        Forwards incidents + approvals to your on-prem SIEM as CEF over syslog. This is an INTERNAL destination, so it
        carries <span className="text-text">real asset identity</span> (unlike the cloud LLM feed, which is pseudonymized).
        Off until configured. One-way out — the SIEM cannot send anything back.
      </div>
      <label className="flex items-center gap-2 text-xs">
        <input type="checkbox" checked={!!s.enabled} onChange={set("enabled")} className="accent-brand" />
        Enable forwarding
        <span className={`ml-2 pill text-2xs ${s.last?.ok ? "text-ok border-ok/50" : s.last?.ok === false ? "text-crit border-crit/50" : "text-muted border-edge"}`}>
          {s.last?.ok ? "last send ok" : s.last?.ok === false ? "last send failed" : "no sends yet"}
          {s.queued ? ` · ${s.queued} queued` : ""}
        </span>
      </label>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        <label className="block md:col-span-2"><div className="text-2xs uppercase tracking-wider text-muted mb-1">SIEM host</div>
          <input className="inp mono" value={s.host || ""} onChange={set("host")} placeholder="siem.corp.local" /></label>
        <label className="block"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Port</div>
          <input className="inp mono" value={s.port} onChange={set("port")} /></label>
        <label className="block"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Transport</div>
          <select className="inp" value={s.protocol} onChange={set("protocol")}><option value="udp">UDP</option><option value="tcp">TCP</option><option value="tls">TLS</option></select></label>
        <label className="block"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Facility</div>
          <input className="inp mono" value={s.facility} onChange={set("facility")} /></label>
        <label className="block md:col-span-2"><div className="text-2xs uppercase tracking-wider text-muted mb-1">TLS CA cert (path, optional)</div>
          <input className="inp mono" value={s.ca_cert || ""} onChange={set("ca_cert")} placeholder="/etc/kaaval/siem-ca.pem" disabled={s.protocol !== "tls"} /></label>
        <label className="flex items-center gap-2 text-xs mt-5">
          <input type="checkbox" checked={!!s.verify_tls} onChange={set("verify_tls")} disabled={s.protocol !== "tls"} className="accent-brand" />
          Verify TLS cert
        </label>
      </div>
      <div className="flex items-center gap-2">
        <button onClick={save} className="btn btn-brand">Save</button>
        <button onClick={test} className="btn">Send test heartbeat</button>
        <button onClick={preview} className="btn">Preview CEF (current incident)</button>
        {msg && <span className="text-2xs text-muted">{msg}</span>}
      </div>
      {cef && <pre className="text-2xs text-text bg-panel2/60 border border-edge rounded-sm p-2 overflow-x-auto whitespace-pre-wrap break-all">{cef}</pre>}
      <style>{`.inp{width:100%;background:rgb(var(--panel2));border:1px solid rgb(var(--edge));border-radius:3px;height:30px;padding:0 8px;color:rgb(var(--text));outline:none;font-size:13px}`}</style>
    </Panel>
  );
}

// Which executor adapter actually runs an approved action. Read-only display —
// selection is admin config/profile-driven. Makes the lab vs real distinction visible.
function ExecutorSettings() {
  const [d, setD] = useState(null);
  useEffect(() => { fetch("/api/executors").then((r) => r.json()).then(setD).catch(() => {}); }, []);
  if (!d) return null;
  const tone = (k) => k === "real-integration" ? "text-ok border-ok/50" : "text-high border-high/50";
  return (
    <Panel title="Executor adapters · how an approved action runs" bodyClass="p-3 space-y-2 text-sm">
      <div className="text-2xs text-muted leading-snug">
        Selecting an adapter changes only HOW an approved action executes — never whether/when. The gate stays in
        front: detection → proposal → human approval → then the adapter runs. OT writes are human-gated regardless of adapter.
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {["it", "ot"].map((slot) => (
          <div key={slot} className="rounded-sm border border-edge bg-panel2/40 px-3 py-2">
            <div className="text-2xs uppercase tracking-wider text-muted">{slot.toUpperCase()} executor</div>
            <div className="text-text mt-0.5">{d[slot].label}</div>
            <span className={`pill text-2xs mt-1 inline-block ${tone(d[slot].kind)}`}>{d[slot].kind}</span>
          </div>
        ))}
      </div>
      <div className="text-2xs text-muted">
        Available: {d.available.map((a) => `${a.name} (${a.kind})`).join(" · ")}
      </div>
    </Panel>
  );
}

export function Settings() {
  const { autonomy } = useSoc();
  return (
    <div className="p-2 h-full overflow-auto space-y-2">
      <LLMSettings />
      <ExecutorSettings />
      <SiemSettings />
      <Panel title="Environment" bodyClass="p-3 text-sm text-muted space-y-1">
        <div>Autonomy: <span className="text-text">{autonomy ? "Enabled" : "Disabled"}</span> — when enabled, reversible IT containment auto-applies; OT actions always require human approval.</div>
        <div>Sensor: <span className="mono text-text">Zeek + ICSNPP (opcua-binary, s7comm)</span></div>
        <div>Detection store: <span className="mono text-text">backend/rules.json</span> (hot-reloaded)</div>
        <div>Deployment profile: <span className="mono text-text">profiles/*.yaml</span> — swap to retarget a different plant.</div>
      </Panel>
    </div>
  );
}
