// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useMemo, useRef, useState } from "react";
import { Panel } from "../ui/primitives.jsx";
import { useSoc } from "./store.jsx";

const TABS = ["all", "conn", "ssh", "ssl", "dns", "opcua_binary", "s7comm", "cotp"];

function Row({ r }) {
  const [open, setOpen] = useState(false);
  const summary = Object.entries(r.parsed_fields || {}).map(([k, v]) => `${k}=${v}`).join("  ");
  return (
    <>
      <tr className={`cursor-pointer ${r.flagged ? "text-text" : "text-muted"}`} onClick={() => setOpen((v) => !v)}>
        <td className="text-muted">{typeof r.ts === "number" ? new Date(r.ts * 1000).toISOString().slice(11, 23) : ""}</td>
        <td className={r.flagged ? "text-accent" : ""}>{r.log_type}</td>
        <td>{r.src} → {r.dst || ""}</td>
        <td className="truncate max-w-[520px]">{summary}</td>
        <td>{r.flagged ? <span className="text-crit">●</span> : <span className="text-muted">·</span>}</td>
      </tr>
      {open && (
        <tr><td colSpan={5} className="bg-panel2">
          <pre className="text-2xs mono whitespace-pre-wrap p-2 max-h-56 overflow-auto">{JSON.stringify(r.raw, null, 2)}</pre>
        </td></tr>
      )}
    </>
  );
}

export default function Telemetry() {
  const { logs } = useSoc();
  const [tab, setTab] = useState("all");
  const [q, setQ] = useState("");
  const [follow, setFollow] = useState(true);
  const endRef = useRef(null);

  const rows = useMemo(() => {
    let r = logs;
    if (tab !== "all") r = r.filter((x) => x.log_type === tab);
    if (q.trim()) {
      const s = q.toLowerCase();
      r = r.filter((x) => JSON.stringify(x.raw).toLowerCase().includes(s));
    }
    return r.slice(-400);
  }, [logs, tab, q]);

  useEffect(() => { if (follow) endRef.current?.scrollIntoView(); }, [rows, follow]);

  return (
    <div className="p-2 h-full">
      <Panel title="Telemetry · live Zeek logs" className="h-full" bodyClass="flex flex-col min-h-0"
        right={
          <div className="flex items-center gap-3">
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter…"
              className="bg-panel2 border border-edge px-2 h-6 text-xs mono outline-none w-40" />
            <button onClick={() => setFollow((v) => !v)}
              className={`text-2xs ${follow ? "text-ok" : "text-muted"}`}>{follow ? "● follow-tail" : "○ paused"}</button>
            <span className="text-2xs text-muted mono">{rows.length}</span>
          </div>
        }>
        <div className="flex gap-1 px-2 py-1.5 border-b border-edge shrink-0">
          {TABS.map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`text-2xs px-2 h-6 border ${tab === t ? "border-accent text-accent" : "border-edge text-muted hover:text-text"}`}>{t}</button>
          ))}
        </div>
        <div className="overflow-auto min-h-0 flex-1">
          <table className="tbl mono text-xs">
            <thead><tr><th>ts</th><th>log</th><th>src → dst</th><th>fields</th><th>flag</th></tr></thead>
            <tbody>
              {rows.map((r) => <Row key={r._k} r={r} />)}
            </tbody>
          </table>
          <div ref={endRef} />
          {rows.length === 0 && <div className="p-4 text-xs text-muted">No log lines yet. Traffic appears here as the plant runs / the attack fires.</div>}
        </div>
      </Panel>
    </div>
  );
}
