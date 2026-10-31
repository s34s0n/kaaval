// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { createContext, useContext, useEffect, useMemo, useRef, useState, useCallback } from "react";
import { WS_URL } from "../config";
import { setToken, whoami } from "../auth.js";

const SocCtx = createContext(null);
export const useSoc = () => useContext(SocCtx);

const LOG_CAP = 500;

async function getJSON(path) {
  try { return await (await fetch(path)).json(); } catch { return null; }
}
async function postJSON(path, body) {
  try { return await (await fetch(path, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  })).json(); } catch { return { ok: false }; }
}

export function SocProvider({ children }) {
  const [connected, setConnected] = useState(false);
  const [state, setState] = useState(null);
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);   // the incident QUEUE (cases)
  const [selectedId, setSelectedId] = useState(null);
  const [scoreboardRaw, setScoreboard] = useState(null);
  const [autonomy, setAutonomyState] = useState(false);
  const [logs, setLogs] = useState([]);
  const [capabilities, setCapabilities] = useState(null);
  const [rules, setRules] = useState([]);
  const [assets, setAssets] = useState([]);
  const [profile, setProfile] = useState(null);
  const [cite, setCite] = useState(null);   // a chat citation the user clicked (focus the evidence)
  const [principal, setPrincipal] = useState(null);   // {name, role, authenticated, can:{approve,admin}}
  const refreshWhoami = useCallback(async () => { setPrincipal(await whoami()); }, []);
  // The signed-in operator — recorded as the approver in the immutable audit log.
  const [operator, setOperatorState] = useState(() => localStorage.getItem("kaaval.operator") || "");
  const setOperator = useCallback((name) => {
    setOperatorState(name);
    localStorage.setItem("kaaval.operator", name || "");
  }, []);

  const refreshRules = useCallback(async () => {
    const r = await getJSON("/api/rules"); if (r?.rules) setRules(r.rules);
  }, []);
  const refreshAssets = useCallback(async () => {
    const r = await getJSON("/api/assets"); if (r?.assets) setAssets(r.assets);
  }, []);

  // REST seed on mount.
  useEffect(() => {
    getJSON("/api/state").then((d) => d?.status && setState(d));
    getJSON("/api/incidents").then((d) => { if (d?.incidents) setIncidents(d.incidents); });
    getJSON("/api/scoreboard").then((d) => d && setScoreboard(d));
    getJSON("/api/capabilities").then((d) => d && setCapabilities(d));
    getJSON("/api/autonomy").then((d) => d && setAutonomyState(!!d.enabled));
    getJSON("/api/assets").then((d) => d?.assets && setAssets(d.assets));
    getJSON("/api/profile").then((d) => d?.name && setProfile(d));
    getJSON("/api/telemetry/recent").then((d) => {
      if (d?.logs) setLogs(d.logs.map((r, i) => ({ ...r, _k: `seed-${r.ts}-${i}` })));
    });
    refreshRules();
    refreshWhoami();
  }, [refreshRules, refreshWhoami]);

  // Main event-bus WS.
  useEffect(() => {
    let stop = false, ws;
    const connect = () => {
      ws = new WebSocket(`${WS_URL}/ws`);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => { setConnected(false); if (!stop) setTimeout(connect, 1000); };
      ws.onmessage = (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }  // ignore malformed frames
        const { type, data } = msg;
        if (type === "state") setState(data);
        else if (type === "events") setEvents(data || []);
        else if (type === "incidents") setIncidents(data || []);
        else if (type === "scoreboard") setScoreboard(data);
        else if (type === "autonomy") setAutonomyState(!!data?.enabled);
      };
    };
    connect();
    return () => { stop = true; ws?.close(); };
  }, []);

  // Telemetry WS (capped ring buffer).
  useEffect(() => {
    let stop = false, ws;
    const connect = () => {
      ws = new WebSocket(`${WS_URL}/ws/telemetry`);
      ws.onclose = () => { if (!stop) setTimeout(connect, 1000); };
      ws.onmessage = (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }  // ignore malformed frames
        const { type, data } = msg;
        if (type !== "log") return;
        setLogs((prev) => {
          const next = prev.length >= LOG_CAP ? prev.slice(prev.length - LOG_CAP + 1) : prev.slice();
          next.push({ ...data, _k: `${data.uid || ""}-${data.ts}-${next.length}` });
          return next;
        });
      };
    };
    connect();
    return () => { stop = true; ws?.close(); };
  }, []);

  // The selected case drives the workspace; default to the most recent incident.
  const activeCase = useMemo(() => {
    if (!incidents.length) return null;
    return incidents.find((c) => c.id === selectedId) || incidents[incidents.length - 1];
  }, [incidents, selectedId]);
  useEffect(() => {
    if (incidents.length && !incidents.some((c) => c.id === selectedId)) {
      setSelectedId(incidents[incidents.length - 1].id);
    }
  }, [incidents, selectedId]);

  const incident = activeCase?.incident || null;
  const agents = activeCase?.agents || null;
  const actions = activeCase?.actions || [];
  const aid = activeCase?.id || "";
  const scoreboard = activeCase
    ? { ...(activeCase.metrics || {}), n_incidents: incidents.length, status: activeCase.status }
    : scoreboardRaw;

  const value = {
    connected, state, events, incident, agents, actions, scoreboard, autonomy,
    logs, capabilities, rules, assets, profile, incidentId: aid || null,
    incidents, selectedId: aid || null, selectIncident: setSelectedId,
    operator, setOperator,
    apply: (name) => postJSON(`/api/actions/${name}/apply?incident_id=${encodeURIComponent(aid)}&approver=${encodeURIComponent(operator || "operator")}`),
    approve: (name) => postJSON(`/api/actions/${name}/approve?incident_id=${encodeURIComponent(aid)}&approver=${encodeURIComponent(operator || "operator")}`),
    setAutonomy: (enabled) => postJSON("/api/autonomy", { enabled }),
    toggleRule: async (id) => { await postJSON(`/api/rules/${id}/toggle`); refreshRules(); },
    createRule: async (rule) => { const r = await postJSON("/api/rules", rule); await refreshRules(); return r; },
    assistRule: async (intent, sample) => postJSON("/api/rules/assist", { intent, sample }),
    getLLM: () => getJSON("/api/llm"),
    setLLM: (patch) => postJSON("/api/llm", patch),
    getApprovals: (id) => getJSON(`/api/approvals${id ? `?incident_id=${encodeURIComponent(id)}` : ""}`),
    getCase: (id) => getJSON(`/api/cases/${encodeURIComponent(id)}`),
    assignCase: (id, assignee) => postJSON(`/api/cases/${encodeURIComponent(id)}/assign`, { assignee }),
    commentCase: (id, text) => postJSON(`/api/cases/${encodeURIComponent(id)}/comment`, { text }),
    transitionCase: (id, state, reason) => postJSON(`/api/cases/${encodeURIComponent(id)}/transition`, { state, reason }),
    closeCase: (id, disposition, reason) => postJSON(`/api/cases/${encodeURIComponent(id)}/close`, { disposition, reason }),
    reopenCase: (id, reason) => postJSON(`/api/cases/${encodeURIComponent(id)}/reopen`, { reason }),
    draftReport: (id) => postJSON(`/api/cases/${encodeURIComponent(id)}/report/draft`),
    getReport: (id) => getJSON(`/api/cases/${encodeURIComponent(id)}/report`),
    saveReport: async (id, markdown) => {
      try { return await (await fetch(`/api/cases/${encodeURIComponent(id)}/report`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ markdown }) })).json(); }
      catch { return { ok: false }; }
    },
    signoffReport: (id) => postJSON(`/api/cases/${encodeURIComponent(id)}/report/signoff`),
    getSiem: () => getJSON("/api/siem"),
    setSiem: async (patch) => {
      try { return await (await fetch("/api/siem", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(patch) })).json(); }
      catch { return { ok: false }; }
    },
    testSiem: () => postJSON("/api/siem/test"),
    previewSiem: (id) => getJSON(`/api/siem/preview${id ? `?incident=${encodeURIComponent(id)}` : ""}`),
    cite, setCite,
    principal,
    login: async (token) => { setToken((token || "").trim()); await refreshWhoami(); return await whoami(); },
    logout: async () => { setToken(""); await refreshWhoami(); },
    refreshAssets,
    addAsset: async (a) => { const r = await postJSON("/api/inventory/assets", a); if (r?.assets) setAssets(r.assets); return r; },
    deleteAsset: async (id) => { const r = await (await fetch(`/api/inventory/assets/${encodeURIComponent(id)}`, { method: "DELETE" })).json().catch(() => null); if (r?.assets) setAssets(r.assets); return r; },
    getNetwork: () => getJSON("/api/inventory/network"),
    setNetwork: async (patch) => {
      try { return await (await fetch("/api/inventory/network", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(patch) })).json(); }
      catch { return { ok: false }; }
    },
    deleteRule: async (id) => { await fetch(`/api/rules/${id}`, { method: "DELETE" }); refreshRules(); },
    reset: () => postJSON("/api/reset"),
  };
  return <SocCtx.Provider value={value}>{children}</SocCtx.Provider>;
}
