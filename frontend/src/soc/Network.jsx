// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { Panel } from "../ui/primitives.jsx";

// Protocol-aware network analytics over the Zeek logs (conn/dns/ssl/ssh + the
// ICSNPP OT logs). Read-only; polls /api/zeek/overview. Each sub-view is a tab.

const fmtBytes = (n) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"]; let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`;
};

const DOMAIN_TONE = {
  OT: "text-crit border-crit/40", IT: "text-low border-low/40",
  external: "text-high border-high/40",
};
function DomainTag({ d }) {
  return <span className={`text-[9px] uppercase tracking-wide px-1 py-px rounded-sm border ${DOMAIN_TONE[d] || "text-muted border-edge"}`}>{d}</span>;
}

function Bar({ value, max, tone = "bg-brand" }) {
  return (
    <div className="h-1.5 bg-panel2 rounded-sm overflow-hidden w-full">
      <div className={`h-full ${tone}`} style={{ width: `${max ? Math.max(2, (value / max) * 100) : 0}%` }} />
    </div>
  );
}

function Totals({ t }) {
  const items = [
    ["Connections", t.connections], ["Data", fmtBytes(t.bytes)], ["Hosts", t.hosts],
    ["DNS queries", t.dns_queries], ["TLS sessions", t.tls_sessions], ["OT operations", t.ot_ops],
  ];
  return (
    <div className="grid grid-cols-3 lg:grid-cols-6 gap-2 mb-2">
      {items.map(([k, v]) => (
        <div key={k} className="panel px-3 py-2">
          <div className="text-[10px] uppercase tracking-[0.14em] text-faint">{k}</div>
          <div className="text-lg font-semibold tabular-nums mt-0.5">{v ?? "—"}</div>
        </div>
      ))}
    </div>
  );
}

// --- sub-views --------------------------------------------------------------

function Protocols({ d }) {
  const max = Math.max(1, ...d.protocols.map((p) => p.count));
  const it = d.protocols.filter((p) => p.layer === "IT");
  const ot = d.protocols.filter((p) => p.layer === "OT");
  const Col = ({ title, rows, tone }) => (
    <Panel title={title} bodyClass="p-3 space-y-2.5">
      {rows.map((p) => (
        <div key={p.key} className="space-y-1">
          <div className="flex items-center justify-between text-xs">
            <span className="text-text">{p.label}</span>
            <span className="mono tabular-nums text-muted">{p.count}</span>
          </div>
          <Bar value={p.count} max={max} tone={tone} />
        </div>
      ))}
    </Panel>
  );
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
      <Col title="IT protocols" rows={it} tone="bg-low" />
      <Col title="OT protocols · ICSNPP" rows={ot} tone="bg-crit" />
    </div>
  );
}

function Conversations({ d }) {
  const max = Math.max(1, ...d.conversations.map((c) => c.bytes));
  return (
    <Panel title={`Conversations · top ${d.conversations.length} by volume`} bodyClass="overflow-auto">
      <table className="tbl text-xs">
        <thead><tr><th>source</th><th>→ destination</th><th>service</th><th>conns</th><th>volume</th><th></th><th>state</th></tr></thead>
        <tbody>
          {d.conversations.map((c, i) => (
            <tr key={i} className={c.anomalous ? "bg-crit/5" : ""}>
              <td className="mono">{c.src}</td>
              <td className="mono">{c.dst}<span className="text-faint">:{c.port}</span></td>
              <td><span className={`chip ${c.anomalous ? "text-crit border-crit/40" : ""}`}>{c.service}{c.anomalous && " · unauthorized"}</span></td>
              <td className="mono tabular-nums text-muted">{c.conns}</td>
              <td className="mono tabular-nums text-muted">{fmtBytes(c.bytes)}</td>
              <td className="w-24"><Bar value={c.bytes} max={max} tone={c.anomalous ? "bg-crit" : "bg-brand"} /></td>
              <td className="mono text-2xs text-faint">{c.states.join(",")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}

function CommMap({ d }) {
  // Compact host communication list (edges) with IT/OT/external domains + anomalies.
  return (
    <Panel title="Communication map · host → host" bodyClass="p-2 space-y-1">
      {d.edges.slice(0, 14).map((e, i) => (
        <div key={i} className={`flex items-center gap-2 text-xs px-2 py-1 rounded-sm ${e.anomalous ? "bg-crit/5 border border-crit/20" : "border border-transparent"}`}>
          <DomainTag d={e.src_domain} />
          <span className="mono">{e.src}</span>
          <span className="text-faint">→</span>
          <span className="mono">{e.dst}</span>
          <DomainTag d={e.dst_domain} />
          <span className="ml-auto text-2xs text-muted">{e.services.join(" · ")}</span>
          <span className="mono text-2xs text-faint w-16 text-right">{fmtBytes(e.bytes)}</span>
          {e.anomalous && <span className="sev sev-critical">anomaly</span>}
        </div>
      ))}
    </Panel>
  );
}

function Dns({ d }) {
  return (
    <Panel title={`DNS queries · ${d.dns.length} distinct`} bodyClass="overflow-auto">
      <table className="tbl text-xs">
        <thead><tr><th>query</th><th>type</th><th>count</th><th>answers</th><th></th></tr></thead>
        <tbody>
          {d.dns.map((q, i) => (
            <tr key={i}>
              <td className="mono">{q.query}</td>
              <td className="text-muted">{q.qtype}</td>
              <td className="mono tabular-nums text-muted">{q.count}</td>
              <td className="mono text-2xs text-muted">{q.answers.join(", ") || "—"}</td>
              <td>{q.external && <span className="chip text-high border-high/40">external</span>}</td>
            </tr>
          ))}
          {!d.dns.length && <tr><td colSpan={5} className="text-muted text-2xs">No DNS activity.</td></tr>}
        </tbody>
      </table>
    </Panel>
  );
}

function Tls({ d }) {
  return (
    <Panel title={`TLS / SSL sessions · ${d.tls.length}`} bodyClass="overflow-auto">
      <table className="tbl text-xs">
        <thead><tr><th>source</th><th>→ server</th><th>SNI</th><th>version</th><th>cipher</th><th>state</th></tr></thead>
        <tbody>
          {d.tls.map((s, i) => (
            <tr key={i}>
              <td className="mono">{s.src}</td><td className="mono">{s.dst}</td>
              <td className="mono text-muted">{s.server_name}</td>
              <td className="text-muted">{s.version}</td>
              <td className="mono text-2xs text-muted">{s.cipher}</td>
              <td>{s.established ? <span className="text-ok text-2xs">established</span> : <span className="text-muted text-2xs">—</span>}</td>
            </tr>
          ))}
          {!d.tls.length && <tr><td colSpan={6} className="text-muted text-2xs">No TLS sessions.</td></tr>}
        </tbody>
      </table>
    </Panel>
  );
}

function Ssh({ d }) {
  return (
    <Panel title={`SSH sessions · ${d.ssh.length}`} bodyClass="overflow-auto">
      <table className="tbl text-xs">
        <thead><tr><th>source</th><th>→ destination</th><th>auth</th><th>client</th><th>server</th><th>kex</th><th></th></tr></thead>
        <tbody>
          {d.ssh.map((s, i) => (
            <tr key={i} className={s.inbound_to_ews ? "bg-crit/5" : ""}>
              <td className="mono">{s.src}</td><td className="mono">{s.dst}</td>
              <td className="mono tabular-nums text-muted">{s.auth_attempts ?? "—"}</td>
              <td className="mono text-2xs text-muted">{s.client}</td>
              <td className="mono text-2xs text-muted">{s.server}</td>
              <td className="mono text-2xs text-faint">{s.kex}</td>
              <td>{s.inbound_to_ews && <span className="sev sev-critical">inbound → ews</span>}</td>
            </tr>
          ))}
          {!d.ssh.length && <tr><td colSpan={7} className="text-muted text-2xs">No SSH sessions.</td></tr>}
        </tbody>
      </table>
    </Panel>
  );
}

function Ot({ d }) {
  const s7max = Math.max(1, ...d.ot.s7comm.map((f) => f.count));
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
      <Panel title="S7comm · function codes" bodyClass="p-3 space-y-3">
        {d.ot.s7comm.map((f) => (
          <div key={f.function} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-text">{f.function}</span>
              <span className="mono tabular-nums text-muted">{f.count}{f.unauthorized ? <span className="text-crit"> · {f.unauthorized} unauthorized</span> : ""}</span>
            </div>
            <Bar value={f.count} max={s7max} tone={f.unauthorized ? "bg-crit" : "bg-brand"} />
          </div>
        ))}
        {!d.ot.s7comm.length && <div className="text-2xs text-muted">No S7comm activity.</div>}
      </Panel>
      <Panel title="OPC UA · message types" bodyClass="p-3 space-y-2">
        <table className="tbl text-xs">
          <thead><tr><th>message type</th><th>count</th></tr></thead>
          <tbody>{d.ot.opcua.map((o) => (
            <tr key={o.msg_type}><td className="mono">{o.msg_type}</td><td className="mono tabular-nums text-muted">{o.count}</td></tr>
          ))}</tbody>
        </table>
        {d.ot.endpoints.length > 0 && (
          <div className="text-2xs text-muted pt-1">endpoints: {d.ot.endpoints.map((e, i) => <span key={i} className="mono text-faint block">{e}</span>)}</div>
        )}
        <div className="text-2xs text-faint">COTP setup PDUs: {d.ot.cotp}</div>
      </Panel>
    </div>
  );
}

const TABS = {
  protocols: { title: "Protocols", render: (d) => <Protocols d={d} /> },
  conversations: { title: "Conversations", render: (d) => <div className="space-y-2"><Conversations d={d} /><CommMap d={d} /></div> },
  dns: { title: "DNS", render: (d) => <Dns d={d} /> },
  tls: { title: "TLS / SSL", render: (d) => <Tls d={d} /> },
  ssh: { title: "SSH sessions", render: (d) => <Ssh d={d} /> },
  ot: { title: "OT protocols", render: (d) => <Ot d={d} /> },
};

export default function Network({ tab = "protocols" }) {
  const [d, setD] = useState(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    let stop = false;
    const tick = () => fetch("/api/zeek/overview").then((r) => r.json())
      .then((x) => { if (!stop) { if (x.error) setErr(true); else { setD(x); setErr(false); } } })
      .catch(() => !stop && setErr(true));
    tick(); const t = setInterval(tick, 4000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  const view = TABS[tab] || TABS.protocols;
  return (
    <div className="p-2 h-full overflow-auto">
      <div className="flex items-baseline gap-2 mb-2 px-1">
        <h1 className="text-sm font-semibold text-text">Network · {view.title}</h1>
        <span className="text-2xs text-muted">Zeek + ICSNPP · live</span>
      </div>
      {err && <div className="text-2xs text-crit mb-2">Zeek analytics unavailable.</div>}
      {!d ? <div className="text-xs text-muted p-4">Loading network analytics…</div> : (
        <>
          {tab === "protocols" && <Totals t={d.totals} />}
          {view.render(d)}
        </>
      )}
    </div>
  );
}
