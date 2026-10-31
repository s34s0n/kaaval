// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useRef, useState } from "react";
import { WS_URL } from "../config";

async function post(path, body) {
  try {
    return await (await fetch(`/api${path}`, {
      method: "POST",
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    })).json();
  } catch { return { ok: false }; }
}

// Lightweight Range hook: live process state over /ws + control post helpers.
export function useRange() {
  const [state, setState] = useState(null);
  const [profile, setProfile] = useState(null);   // active plant profile (safety + view)
  const [connected, setConnected] = useState(false);
  const [log, setLog] = useState([]);          // local action log (what the operator did)
  const [scenarios, setScenarios] = useState([]);  // launchable attack types
  const wsRef = useRef(null);

  useEffect(() => {
    fetch("/api/state").then((r) => r.json()).then((d) => d?.status && setState(d)).catch(() => {});
    fetch("/api/profile").then((r) => r.json()).then((d) => d?.name && setProfile(d)).catch(() => {});
    fetch("/api/attack/scenarios").then((r) => r.json()).then((d) => d?.scenarios && setScenarios(d.scenarios)).catch(() => {});
    let stop = false;
    const connect = () => {
      const ws = new WebSocket(`${WS_URL}/ws`);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => { setConnected(false); if (!stop) setTimeout(connect, 1000); };
      ws.onmessage = (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }  // ignore malformed frames
        if (msg.type === "state") setState(msg.data);
      };
    };
    connect();
    return () => { stop = true; wsRef.current?.close(); };
  }, []);

  const note = (msg, tone) => setLog((p) => [{ t: new Date().toISOString().slice(11, 19), msg, tone }, ...p].slice(0, 12));
  // Surface the backend result so a failed write (e.g. ews isolated) is never silent.
  const report = (label, r) => {
    const ok = r && r.ok !== false;
    note(ok ? `${label} ✓` : `${label} — ${((r && (r.detail || r.error)) || "failed").split("\n")[0].slice(0, 90)}`,
         ok ? "ok" : "err");
    return r;
  };

  return {
    state, profile, connected, log, scenarios,
    launchChain: async () => { note("launch full attack chain"); report("chain", await post("/attack/run")); },
    scenario: async (name, label) => { note(`launch campaign: ${label}`); report(`scenario ${label}`, await post(`/attack/scenario/${name}`)); },
    stage: async (name, label) => { report(`stage: ${label}`, await post(`/attack/stage/${name}`)); },
    malicious: async (op, value, label) => { report(`MALICIOUS ${label}`, await post("/range/malicious", { op, value })); },
    legitimate: async (value) => { report(`LEGITIMATE setpoint ${value} via gateway`, await post("/range/legitimate", { value })); },
    reset: async () => { note("reset to clean baseline"); await post("/reset"); },
  };
}
