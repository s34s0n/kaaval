// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import Logo from "../ui/Logo.jsx";
import { useSoc } from "./store.jsx";

// Token-based sign-in. Reads are open; signing in attaches the bearer to every
// request and unlocks role-appropriate actions (operator / approver / admin).
export default function Login({ onClose }) {
  const { login } = useSoc();
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => {
    const k = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setErr("");
    const p = await login(token);
    setBusy(false);
    if (p && p.authenticated) onClose();
    else setErr("Invalid token, or this token has no access.");
  };

  return (
    <div className="fixed inset-0 z-50 grid place-items-center scrim"
      role="dialog" aria-modal="true" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <motion.form initial={{ opacity: 0, scale: 0.96, y: 8 }} animate={{ opacity: 1, scale: 1, y: 0 }}
        onSubmit={submit} className="panel pop w-[400px] max-w-[92vw] p-5">
        <div className="flex items-center gap-2.5 mb-3">
          <Logo size={28} />
          <div className="leading-none">
            <div className="text-sm font-semibold text-text">Sign in to Kaaval</div>
            <div className="text-2xs text-muted">access token · role-based</div>
          </div>
        </div>
        <label className="block">
          <div className="text-2xs uppercase tracking-wider text-muted mb-1">Access token</div>
          <input autoFocus type="password" value={token} onChange={(e) => setToken(e.target.value)}
            placeholder="paste your token…" autoComplete="off"
            className="w-full bg-panel2 border border-edge px-2 h-9 text-sm mono outline-none focus:border-brand" />
        </label>
        {err && <div className="text-2xs text-crit mt-2">{err}</div>}
        <div className="flex items-center gap-2 mt-4">
          <button type="submit" disabled={busy || !token.trim()} className="btn btn-brand">
            {busy ? "signing in…" : "Sign in"}</button>
          <button type="button" onClick={onClose} className="btn">Continue as viewer</button>
          <span className="ml-auto text-2xs text-faint">Esc</span>
        </div>
        <div className="text-2xs text-muted mt-3 leading-snug">
          Viewing is open. An <span className="text-text">operator</span> can investigate and apply
          reversible IT containment; only an <span className="text-text">approver</span> may authorize an
          OT control action (separation of duties).
        </div>
      </motion.form>
    </div>
  );
}
