// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Frontend auth: bearer-token attach on EVERY /api request + whoami.
// We wrap window.fetch once (installAuthFetch) so every call site — the store,
// the chat client, the range store, and component fetches — carries the token
// without per-call changes. Reads are open (the backend only gates mutations),
// so an anonymous user can view but must log in to act.

const KEY = "kaaval.token";

export const getToken = () => localStorage.getItem(KEY) || "";
export const setToken = (t) => (t ? localStorage.setItem(KEY, t) : localStorage.removeItem(KEY));

// One-time bootstrap: a `?token=…` query param (magic-link style) is stored and
// immediately stripped from the URL/history so it doesn't linger.
export function bootstrapTokenFromUrl() {
  try {
    const u = new URL(window.location.href);
    const t = u.searchParams.get("token");
    if (t) {
      setToken(t);
      u.searchParams.delete("token");
      window.history.replaceState({}, "", u.toString());
    }
  } catch { /* ignore */ }
}

let _installed = false;
export function installAuthFetch() {
  if (_installed) return;
  _installed = true;
  const orig = window.fetch.bind(window);
  window.fetch = (input, init = {}) => {
    try {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      if (url.startsWith("/api")) {
        const t = getToken();
        if (t) init = { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${t}` } };
      }
    } catch { /* ignore */ }
    return orig(input, init);
  };
}

// Resolve the current principal (name, role, can.{approve,admin}, authenticated).
export async function whoami() {
  try {
    const r = await fetch("/api/whoami");
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}
