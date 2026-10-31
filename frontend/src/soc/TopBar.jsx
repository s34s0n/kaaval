// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useRef, useState } from "react";
import { useSoc } from "./store.jsx";
import Icon from "../ui/Icon.jsx";
import Login from "./Login.jsx";

const ROLE_TONE = { admin: "text-brand", approver: "text-ok", operator: "text-low", viewer: "text-muted" };

function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="mono text-xs text-muted tabular-nums">{now.toISOString().slice(11, 19)}Z</span>;
}

const ENV = {
  ok: ["dot-ok", "NOMINAL"],
  warning: ["dot-degraded", "DEGRADED"],
  danger: ["dot-breached", "UNSAFE"],
  burst: ["dot-breached", "BURST RISK"],
};

// Live, profile-driven process pulse: the safety variable's current value + a
// rolling sparkline + a danger marker. Reads the descriptor (variable/label/unit/
// band/danger) from the active profile, so it renders correctly for ANY plant
// (pump pressure, reactor temperature, …) — no hardcoded tag names.
function ProcessPulse() {
  const { state, profile } = useSoc();
  const safety = profile?.safety;
  const histRef = useRef([]);
  const v = safety?.variable ? state?.[safety.variable] : undefined;

  // Append to a capped rolling history whenever a fresh value arrives.
  const [, force] = useState(0);
  useEffect(() => {
    if (typeof v !== "number") return;
    const h = histRef.current;
    h.push(v);
    if (h.length > 48) h.shift();
    force((n) => n + 1);
  }, [v]);

  if (!safety || typeof v !== "number") {
    return <span className="pill border-edge2 text-muted"><span className="dot dot-degraded" /> process —</span>;
  }

  const hist = histRef.current;
  const danger = safety.danger ?? Math.max(v, 1);
  const lo = (safety.band?.[0] ?? 0) * 0.6;
  const span = Math.max(danger * 1.05 - lo, 1e-6);
  const norm = (y) => Math.min(Math.max((y - lo) / span, 0), 1);
  // Bounded mini sparkline. Inset by 1px so the stroke/endpoint never touch the
  // edges, and the svg clips (no overflow) so nothing spills out of the pill.
  const W = 48, H = 14, PAD = 1;
  const iw = W - PAD * 2, ih = H - PAD * 2;
  const pts = hist.map((y, i) => {
    const x = PAD + (hist.length > 1 ? (i / (hist.length - 1)) * iw : 0);
    const yy = PAD + (1 - norm(y)) * ih;
    return `${x.toFixed(1)},${yy.toFixed(1)}`;
  }).join(" ");
  const dotY = PAD + (1 - norm(v)) * ih;

  const status = state?.status || "ok";
  const tone = status === "burst" || status === "danger" ? "#FF6B6B"
    : status === "warning" ? "#F4C152" : "#2EE6A6";

  return (
    <span className="pill border-edge2 gap-2" title={`${safety.label || safety.variable} · live`}>
      <span className="text-2xs uppercase tracking-wide text-faint hidden lg:inline">{safety.label || safety.variable}</span>
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="shrink-0 overflow-hidden rounded-sm bg-panel2/60" aria-hidden>
        {pts && <polyline points={pts} fill="none" stroke={tone} strokeWidth="1.2"
          strokeLinejoin="round" strokeLinecap="round" />}
        <circle cx={W - PAD} cy={dotY} r="1.3" fill={tone} />
      </svg>
      <span className="mono tabular-nums whitespace-nowrap" style={{ color: tone }}>
        {v.toFixed(1)}<span className="text-faint"> {safety.unit}</span>
      </span>
    </span>
  );
}

export default function TopBar() {
  const { state, autonomy, setAutonomy, connected, reset, principal, logout } = useSoc();
  const [health, setHealth] = useState(null);
  const [resetting, setResetting] = useState(false);
  const [showLogin, setShowLogin] = useState(false);
  const isAdmin = !!principal?.can?.admin;
  const authed = !!principal?.authenticated;
  const [light, setLight] = useState(() => document.documentElement.classList.contains("light"));
  const toggleTheme = () => {
    const next = !light;
    setLight(next);
    document.documentElement.classList.toggle("light", next);
    try { localStorage.setItem("kaaval.theme", next ? "light" : "dark"); } catch { /* ignore */ }
  };

  useEffect(() => {
    let stop = false;
    const tick = () => fetch("/api/health").then((r) => r.json()).then((h) => !stop && setHealth(h)).catch(() => {});
    tick();
    const t = setInterval(tick, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  const [dot, label] = ENV[state?.status] || ["dot-degraded", "—"];
  const model = health?.ollama === "warm" ? ["ok", "warm"]
    : health?.ollama === "loaded" ? ["degraded", "loaded"]
    : health ? ["breached", "down"] : ["degraded", "…"];
  const modelName = health?.llm_model || "model";
  const gwUp = health ? health.gateway === "up" : connected;

  const doReset = async () => { setResetting(true); await reset(); setResetting(false); };

  return (
    <header className="h-14 shrink-0 bg-panel border-b border-edge flex items-center gap-3 px-4">
      {/* Environment status — the headline indicator */}
      <span className="pill border-edge2">
        <span className={`dot ${dot}`} />
        <span className="uppercase tracking-wide">{label}</span>
      </span>

      <ProcessPulse />

      <div className="flex items-center gap-1.5">
        <span className="text-2xs uppercase tracking-wider text-faint hidden sm:inline">Autonomy</span>
        <button onClick={() => isAdmin && setAutonomy(!autonomy)} disabled={!isAdmin}
          title={isAdmin ? "Admin policy: when on, reversible IT containment auto-applies; OT actions always need approval."
                         : "Admin only — sign in as admin to change the autonomy policy."}
          className={`pill ${autonomy ? "text-ok border-ok/50" : "text-muted border-edge"} ${!isAdmin ? "opacity-50 cursor-not-allowed" : ""}`}>
          <span className="dot" style={autonomy ? { background: "#2EE6A6", boxShadow: "0 0 7px -1px rgba(46,230,166,0.8)" } : { background: "#4A5670" }} />
          {autonomy ? "Autonomy on" : "Manual"}
        </button>
      </div>

      <div className="ml-auto flex items-center gap-2">
        <span className="pill" title={`LLM: ${modelName}`}><span className={`dot dot-${model[0]}`} /><span className="hidden md:inline mono">{modelName} ·</span> {model[1]}</span>
        <span className="pill"><span className={`dot ${gwUp ? "dot-ok" : "dot-breached"}`} /> gateway</span>
        <span className="pill"><span className={`dot ${connected ? "dot-ok" : "dot-breached"}`} /> {connected ? "live" : "offline"}</span>
        <button onClick={toggleTheme} title={light ? "Switch to dark" : "Switch to light"}
          className="btn w-8 px-0 justify-center"><Icon name={light ? "moon" : "sun"} size={14} /></button>
        {isAdmin && (
          <button onClick={doReset} disabled={resetting} className="btn gap-1.5">
            <Icon name="reset" size={13} className={resetting ? "animate-spin" : ""} />
            {resetting ? "resetting…" : "Reset"}
          </button>
        )}
        {/* Identity / role + sign in-out */}
        {authed ? (
          <button onClick={logout} title="Sign out"
            className="pill border-edge2 gap-1.5">
            <span className={`dot ${ROLE_TONE[principal.role] === "text-muted" ? "dot-degraded" : "dot-ok"}`} />
            <span className="text-text">{principal.name}</span>
            <span className={`uppercase tracking-wide ${ROLE_TONE[principal.role] || "text-muted"}`}>{principal.role}</span>
            {principal.dev && <span className="text-faint">· dev</span>}
          </button>
        ) : (
          <button onClick={() => setShowLogin(true)} className="btn btn-brand gap-1.5">
            <Icon name="shield" size={13} /> Sign in
          </button>
        )}
        <span className="hidden lg:inline"><Clock /></span>
      </div>
      {showLogin && <Login onClose={() => setShowLogin(false)} />}
    </header>
  );
}
