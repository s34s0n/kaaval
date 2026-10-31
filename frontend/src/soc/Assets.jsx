// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useMemo, useState } from "react";
import { Panel, SeverityTag } from "../ui/primitives.jsx";
import Icon from "../ui/Icon.jsx";
import { useSoc } from "./store.jsx";
import NetworkMap from "./NetworkMap.jsx";

const critLevel = (c) => (c === "critical" ? "critical" : c === "high" ? "high" : c === "medium" ? "medium" : "low");
const DOMAIN_TONE = { OT: "text-crit border-crit/40", IT: "text-low border-low/40", external: "text-high border-high/40" };
const fmtBytes = (n) => { if (!n) return "—"; const u = ["B", "KB", "MB", "GB"]; let i = 0, v = n; while (v >= 1024 && i < 3) { v /= 1024; i++; } return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`; };

function Stat({ label, value, tone = "" }) {
  return (
    <div className="panel px-3 py-2">
      <div className="text-[10px] uppercase tracking-[0.14em] text-faint">{label}</div>
      <div className={`text-lg font-semibold tabular-nums mt-0.5 ${tone}`}>{value}</div>
    </div>
  );
}

function DomainTag({ d }) {
  return <span className={`text-[9px] uppercase tracking-wide px-1 py-px rounded-sm border ${DOMAIN_TONE[d] || "text-muted border-edge"}`}>{d}</span>;
}

// --- CVE exposure (F3). Asset->CPE resolves locally; only the CPE is sent to NVD
// (cloud) or matched offline (local). CVE data is INFORMATIONAL — it never triggers
// an action. "Not assessed" (unknown firmware) is shown as such, never as "safe".
const CVE_TONE = { CRITICAL: "text-crit border-crit/50 bg-crit/10", HIGH: "text-high border-high/50 bg-high/10", MEDIUM: "text-warn border-warn/50 bg-warn/10", LOW: "text-low border-low/40 bg-low/10" };
const CVE_STATUS = {
  vulnerable: { label: "vulnerable", cls: "text-crit border-crit/50 bg-crit/10" },
  none_known: { label: "no known CVEs", cls: "text-ok border-ok/50 bg-ok/10" },
  not_assessed: { label: "not assessed", cls: "text-muted border-edge bg-panel2/40" },
};
const STATUS_RANK = { vulnerable: 0, none_known: 1, not_assessed: 2 };

function CveRow({ id, severity, cvss, summary, affected }) {
  const tone = CVE_TONE[(severity || "").toUpperCase()] || "text-muted border-edge";
  return (
    <div className="rounded-sm border border-edge bg-panel2/50 px-2.5 py-1.5">
      <div className="flex items-center gap-2">
        <a href={`https://nvd.nist.gov/vuln/detail/${id}`} target="_blank" rel="noreferrer" className="mono text-2xs text-brand hover:underline">{id}</a>
        <span className={`pill text-2xs ${tone}`}>{severity || "—"}{cvss ? ` · ${cvss}` : ""}</span>
        {affected && <span className="ml-auto text-2xs text-faint mono shrink-0">{affected}</span>}
      </div>
      <div className="text-xs text-muted mt-1 leading-snug">{summary}</div>
    </div>
  );
}

function EnrichmentPanel() {
  const [data, setData] = useState(null);
  const [open, setOpen] = useState(() => new Set(["plc"]));
  useEffect(() => { fetch("/api/enrichment").then((r) => r.json()).then((d) => d.assets && setData(d)).catch(() => {}); }, []);
  if (!data) return null;
  const s = data.summary || {};
  const rows = [...(data.assets || [])].sort((a, b) =>
    (STATUS_RANK[a.cve.status] - STATUS_RANK[b.cve.status]) || (b.cve.max_cvss || 0) - (a.cve.max_cvss || 0));
  const toggle = (n) => setOpen((p) => { const x = new Set(p); x.has(n) ? x.delete(n) : x.add(n); return x; });
  const srcLabel = data.mode === "cloud" ? "live NVD · via egress boundary" : "offline NVD snapshot · air-gapped";

  return (
    <Panel title="Vulnerability exposure · CVE" bodyClass="p-2 space-y-1.5"
      right={<span className="text-2xs text-muted">{srcLabel}</span>}>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 mb-1">
        <Stat label="Vulnerable" value={s.vulnerable ?? "—"} tone={s.vulnerable ? "text-crit" : ""} />
        <Stat label="Not assessed" value={s.not_assessed ?? "—"} tone="text-muted" />
        <Stat label="CVEs found" value={s.cve_count ?? "—"} />
        <Stat label="Max CVSS" value={s.max_cvss || "—"} tone={s.max_cvss >= 9 ? "text-crit" : s.max_cvss >= 7 ? "text-high" : ""} />
      </div>
      {rows.map((a) => {
        const st = CVE_STATUS[a.cve.status] || CVE_STATUS.not_assessed;
        const opened = open.has(a.name);
        return (
          <div key={a.name} className="rounded-sm border border-edge bg-panel">
            <button onClick={() => toggle(a.name)} className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-panel2/50">
              <span className={`shrink-0 transition-transform ${opened ? "rotate-90" : ""} text-faint`}><Icon name="chevron" size={12} /></span>
              <span className="mono text-xs text-text shrink-0 w-24 truncate">{a.name}</span>
              <DomainTag d={a.domain} />
              <span className="mono text-2xs text-muted truncate flex-1">{a.cpe || (a.vendor ? `${a.vendor} · firmware unknown` : "no product identified")}</span>
              <span className={`shrink-0 pill text-2xs ${st.cls}`}>
                {st.label}{a.cve.status === "vulnerable" ? ` · ${a.cve.cves.length}` : ""}
              </span>
            </button>
            {opened && (
              <div className="px-3 pb-3 pl-8 space-y-2">
                <div className="text-2xs text-faint mono">
                  {a.oui_vendor && <>OUI → {a.oui_vendor} · </>}{a.cpe ? <>CPE {a.cpe} · src {a.cve.source}</> : a.cve.reason}
                </div>
                {a.cve.cves?.length
                  ? a.cve.cves.map((c) => <CveRow key={c.id} {...c} />)
                  : <div className="text-2xs text-muted italic">{a.cve.status === "none_known"
                      ? "Assessed against NVD for this CPE — no known CVEs."
                      : "Firmware/version not identified — not assessed for CVEs (this is not the same as safe)."}</div>}
              </div>
            )}
          </div>
        );
      })}
      <div className="text-2xs text-faint leading-snug pt-1">
        Asset→CPE resolves locally; only the CPE string is sent to NVD — never an asset name, IP, MAC, or count.
        CVE data is informational and never triggers a response action.
      </div>
    </Panel>
  );
}

function AddAssetForm({ initial, onAdd, onClose }) {
  const [f, setF] = useState({ id: initial?.id || "", domain: initial?.domain || "IT", criticality: initial?.criticality || "medium", ips: initial?.ip || "", role: initial?.device_type || "" });
  const [msg, setMsg] = useState("");
  const submit = async () => {
    const r = await onAdd({ ...f, ips: f.ips.split(",").map((s) => s.trim()).filter(Boolean) });
    if (r?.ok) onClose(); else setMsg(r?.error || "failed");
  };
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  return (
    <Panel title={initial ? `Promote ${initial.ip} to managed inventory` : "Add managed asset"} bodyClass="p-3 grid grid-cols-2 md:grid-cols-3 gap-2 text-sm"
      right={<button onClick={onClose} className="text-muted hover:text-text"><Icon name="chevron" className="rotate-90" size={12} /></button>}>
      <label className="block"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Host id</div>
        <input className="inp mono" value={f.id} onChange={set("id")} placeholder="historian01" /></label>
      <label className="block"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Zone</div>
        <select className="inp" value={f.domain} onChange={set("domain")}><option>IT</option><option>OT</option><option>external</option></select></label>
      <label className="block"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Criticality</div>
        <select className="inp" value={f.criticality} onChange={set("criticality")}><option>critical</option><option>high</option><option>medium</option><option>low</option></select></label>
      <label className="block"><div className="text-2xs uppercase tracking-wider text-muted mb-1">IP(s)</div>
        <input className="inp mono" value={f.ips} onChange={set("ips")} placeholder="172.30.0.20" /></label>
      <label className="block md:col-span-2"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Role / device type</div>
        <input className="inp" value={f.role} onChange={set("role")} placeholder="Process historian" /></label>
      <div className="col-span-2 md:col-span-3 flex items-center gap-3">
        <button onClick={submit} disabled={!f.id.trim()} className="btn btn-brand">Save to inventory</button>
        {msg && <span className="text-2xs text-crit">{msg}</span>}
      </div>
      <style>{`.inp{width:100%;background:rgb(var(--panel2));border:1px solid rgb(var(--edge));border-radius:3px;height:30px;padding:0 8px;color:rgb(var(--text));outline:none;font-size:13px}`}</style>
    </Panel>
  );
}

function NetworkSettings({ onClose }) {
  const { getNetwork, setNetwork } = useSoc();
  const [n, setN] = useState(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => { getNetwork().then((d) => d && setN({ ...d, monitored_ranges: (d.monitored_ranges || []).join(", ") })); }, [getNetwork]);
  if (!n) return null;
  const save = async () => {
    await setNetwork({ subnet: n.subnet, sensor_placement: n.sensor_placement, notes: n.notes,
      monitored_ranges: (n.monitored_ranges || "").split(",").map((s) => s.trim()).filter(Boolean) });
    setSaved(true); setTimeout(() => setSaved(false), 1500);
  };
  const set = (k) => (e) => setN({ ...n, [k]: e.target.value });
  return (
    <Panel title="Network settings · discovery scope" bodyClass="p-3 grid grid-cols-2 gap-2 text-sm"
      right={<button onClick={onClose} className="text-muted hover:text-text"><Icon name="chevron" className="rotate-90" size={12} /></button>}>
      <label className="block"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Plant subnet (CIDR) — defines internal vs external</div>
        <input className="inp mono" value={n.subnet} onChange={set("subnet")} placeholder="172.30.0.0/24" /></label>
      <label className="block"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Sensor placement</div>
        <input className="inp" value={n.sensor_placement} onChange={set("sensor_placement")} placeholder="ews namespace (SPAN)" /></label>
      <label className="block col-span-2"><div className="text-2xs uppercase tracking-wider text-muted mb-1">Monitored ranges (comma-sep)</div>
        <input className="inp mono" value={n.monitored_ranges} onChange={set("monitored_ranges")} placeholder="172.30.0.0/24, 10.0.0.0/8" /></label>
      <div className="col-span-2 flex items-center gap-3">
        <button onClick={save} className="btn btn-brand">Save</button>
        {saved && <span className="text-2xs text-ok">saved ✓</span>}
      </div>
      <style>{`.inp{width:100%;background:rgb(var(--panel2));border:1px solid rgb(var(--edge));border-radius:3px;height:30px;padding:0 8px;color:rgb(var(--text));outline:none;font-size:13px}`}</style>
    </Panel>
  );
}

const FILTERS = [["all", "All"], ["OT", "OT"], ["IT", "IT"], ["external", "External"], ["unmanaged", "Unmanaged"]];

export default function Assets() {
  const { addAsset } = useSoc();
  const [data, setData] = useState(null);
  const [sel, setSel] = useState(null);
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const [showNet, setShowNet] = useState(false);
  const [promote, setPromote] = useState(null);

  useEffect(() => {
    let stop = false;
    const tick = () => fetch("/api/discovery").then((r) => r.json()).then((d) => !stop && d.assets && setData(d)).catch(() => {});
    tick(); const t = setInterval(tick, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);
  // also pull live edges for the topology map
  const [edges, setEdges] = useState([]);
  useEffect(() => {
    let stop = false;
    const tick = () => fetch("/api/zeek/overview").then((r) => r.json()).then((d) => !stop && d.edges && setEdges(d.edges)).catch(() => {});
    tick(); const t = setInterval(tick, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  const all = data?.assets || [];
  const mapAssets = useMemo(() => all.map((a) => ({ name: a.id, domain: a.domain, ips: a.ip ? [a.ip] : [], criticality: a.criticality, authorized_ot: a.authorized_ot })), [all]);
  const rows = useMemo(() => all.filter((a) => {
    if (filter === "unmanaged" && !a.unmanaged) return false;
    if (["OT", "IT", "external"].includes(filter) && a.domain !== filter) return false;
    if (sel && a.id !== sel) return false;
    if (q && !(`${a.id} ${a.ip} ${a.device_type} ${(a.protocols || []).join(" ")}`.toLowerCase().includes(q.toLowerCase()))) return false;
    return true;
  }), [all, filter, sel, q]);

  const s = data?.summary || {};

  return (
    <div className="p-2 h-full overflow-auto space-y-2">
      <div className="flex items-center gap-2 px-1">
        <h1 className="text-sm font-semibold text-text">Asset discovery</h1>
        <span className="text-2xs text-muted">passive · from Zeek + ICSNPP · subnet {data?.subnet || "—"}</span>
        <button onClick={() => setShowNet((v) => !v)} className="btn gap-1.5 ml-auto"><Icon name="settings" size={13} /> Network settings</button>
      </div>

      <div className="grid grid-cols-3 lg:grid-cols-6 gap-2">
        <Stat label="Discovered" value={s.total ?? "—"} />
        <Stat label="OT assets" value={s.ot ?? "—"} tone="text-crit" />
        <Stat label="IT assets" value={s.it ?? "—"} tone="text-low" />
        <Stat label="External" value={s.external ?? "—"} tone="text-high" />
        <Stat label="Unmanaged" value={s.unmanaged ?? "—"} tone={s.unmanaged ? "text-crit" : ""} />
        <Stat label="Active now" value={s.active ?? "—"} tone="text-ok" />
      </div>

      {showNet && <NetworkSettings onClose={() => setShowNet(false)} />}
      {promote && <AddAssetForm initial={promote} onAdd={addAsset} onClose={() => { setPromote(null); }} />}

      <Panel title="Discovered topology" bodyClass="p-2"
        right={sel ? <button onClick={() => setSel(null)} className="text-2xs text-brand">clear · {sel}</button> : <span className="text-2xs text-muted">click a node to focus</span>}>
        <NetworkMap assets={mapAssets} edges={edges} height={400} onSelect={(n) => setSel(n === sel ? null : n)} selected={sel} />
      </Panel>

      <Panel title={`Asset inventory · ${rows.length}`} bodyClass="overflow-auto"
        right={
          <div className="flex items-center gap-2">
            <div className="flex rounded-sm overflow-hidden border border-edge2 text-2xs">
              {FILTERS.map(([k, l]) => (
                <button key={k} onClick={() => setFilter(k)} className={`px-2 h-5 ${filter === k ? "bg-brand/15 text-brand" : "text-muted hover:text-text"} ${k === "unmanaged" && s.unmanaged ? "text-crit" : ""}`}>{l}{k === "unmanaged" && s.unmanaged ? ` ${s.unmanaged}` : ""}</button>
              ))}
            </div>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="search…" className="bg-panel2 border border-edge h-5 px-2 text-2xs outline-none w-28" />
          </div>
        }>
        <table className="tbl text-xs">
          <thead><tr><th></th><th>asset</th><th>device type</th><th>zone</th><th>crit</th><th>protocols</th><th>role</th><th>peers</th><th>traffic</th><th>status</th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.ip || a.id} className={a.unmanaged ? "bg-crit/5" : ""}>
                <td><span className={`dot ${a.last_seen ? "dot-ok" : ""}`} style={!a.last_seen ? { background: "rgb(var(--edge2))" } : undefined} /></td>
                <td className="mono">{a.name || a.ip}{a.name && a.ip ? <span className="text-faint"> · {a.ip}</span> : ""}</td>
                <td className={a.device_type?.includes("control client") ? "text-high" : ""}>{a.device_type}</td>
                <td><DomainTag d={a.domain} /></td>
                <td><SeverityTag level={critLevel(a.criticality)} /></td>
                <td className="mono text-2xs text-muted">{(a.protocols || []).join(" ") || "—"}</td>
                <td className="text-muted">{a.role}</td>
                <td className="mono tabular-nums text-muted">{a.peers || "—"}</td>
                <td className="mono tabular-nums text-muted">{fmtBytes(a.bytes)}</td>
                <td>
                  {a.unmanaged
                    ? <button onClick={() => setPromote(a)} className="sev sev-critical hover:bg-crit/20">unmanaged · add</button>
                    : <span className="text-2xs text-ok">managed</span>}
                </td>
              </tr>
            ))}
            {!rows.length && <tr><td colSpan={10} className="text-muted text-2xs p-3">No assets match. Run traffic from the Range Console to discover hosts.</td></tr>}
          </tbody>
        </table>
      </Panel>

      <EnrichmentPanel />
    </div>
  );
}
