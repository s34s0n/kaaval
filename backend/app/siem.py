# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""SIEM / syslog CEF forwarder (F6) — ONE-WAY OUT, read-only-derived.

This module emits a CEF representation of incidents/approvals that ALREADY exist. It
opens an outbound client socket and only ever SENDS; it never binds a listener and
never reads anything back, so the SIEM cannot push data that reaches an action. It
imports neither `actions` nor `gating` — there is no route from here to execution
(invariant 1).

TRUST BOUNDARY (deliberate; see cef.py + CLAUDE.md): the SIEM is the customer's own,
on-premises destination, so the feed carries REAL asset identity. It does NOT pass
through the cloud pseudonymizer (egress.py) — that boundary exists because cloud LLM
calls LEAVE the premises; the SIEM feed does not.

Reliability: forwarding is best-effort. If the SIEM is unreachable the SOC never
blocks or crashes — the failure is logged, the lines are queued (bounded) for the
next attempt, and oldest entries drop with a log when the queue is full.
"""

from __future__ import annotations

import collections
import json
import logging
import os
import socket
import ssl
import time

from . import cef, config, store

log = logging.getLogger("kaaval.siem")

_DEFAULTS = {
    "enabled": False, "host": "", "port": 514, "protocol": "udp",   # udp | tcp | tls
    "facility": 16, "host_field": "kaaval", "verify_tls": True, "ca_cert": "", "timeout": 5.0,
}
_VALID_PROTO = ("udp", "tcp", "tls")

_cfg_cache = None
_QUEUE = collections.deque(maxlen=2000)        # bounded retry buffer
_LAST = {"ok": None, "ts": None, "detail": "never sent"}
_lock = __import__("threading").Lock()


# --- config (admin-set; off unless configured) ------------------------------

def get_config() -> dict:
    global _cfg_cache
    if _cfg_cache is None:
        cfg = dict(_DEFAULTS)
        try:
            with open(config.SIEM_CONFIG_PATH) as f:
                cfg.update({k: v for k, v in json.load(f).items() if k in _DEFAULTS})
        except (OSError, json.JSONDecodeError):
            pass
        _cfg_cache = cfg
    return dict(_cfg_cache)


def set_config(patch: dict) -> dict:
    global _cfg_cache
    with _lock:
        cfg = get_config()
        for k in _DEFAULTS:
            if k in patch and patch[k] is not None:
                cfg[k] = patch[k]
        if cfg["protocol"] not in _VALID_PROTO:
            cfg["protocol"] = "udp"
        try:
            cfg["port"] = int(cfg["port"])
        except (TypeError, ValueError):
            cfg["port"] = 514
        _cfg_cache = cfg
        try:
            os.makedirs(os.path.dirname(config.SIEM_CONFIG_PATH), exist_ok=True)
            with open(config.SIEM_CONFIG_PATH, "w") as f:
                json.dump(cfg, f, indent=2)
        except OSError:
            log.warning("could not persist SIEM config")
        return dict(cfg)


def status() -> dict:
    cfg = get_config()
    return {**cfg, "configured": bool(cfg.get("host")),
            "last": dict(_LAST), "queued": len(_QUEUE)}


# --- transport (outbound client only; no listener, ever) --------------------

def _send_raw(cfg: dict, lines: list[str]) -> None:
    """Send framed syslog lines. Raises on any transport error (caller handles)."""
    host, port, proto = cfg["host"], int(cfg["port"]), cfg["protocol"]
    timeout = float(cfg.get("timeout", 5.0))
    payload = "".join(l + "\n" for l in lines).encode("utf-8")     # newline-framed (RFC6587 non-transparent)
    if proto == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            for l in lines:
                s.sendto((l + "\n").encode("utf-8"), (host, port))
        finally:
            s.close()
        return
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = raw
        if proto == "tls":
            ctx = ssl.create_default_context()
            if cfg.get("ca_cert"):
                ctx.load_verify_locations(cfg["ca_cert"])
            if not cfg.get("verify_tls", True):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            server_hostname = host if cfg.get("verify_tls", True) else None
            sock = ctx.wrap_socket(raw, server_hostname=server_hostname)
        sock.settimeout(timeout)
        sock.sendall(payload)
        sock.close()
    finally:
        if proto != "tls":
            raw.close()


def _record(kind, signature, incident_id, transport, ok, detail):
    _LAST.update(ok=ok, ts=time.time(), detail=detail)
    try:
        conn = store.connect(); store.init(conn)
        store.add_siem_log(conn, ts=time.time(), kind=kind, signature=signature,
                           incident_id=incident_id, transport=transport, ok=ok, detail=detail)
        conn.close()
    except Exception:
        log.exception("failed to write siem_log")


def _forward(lines: list[str], *, kind: str, signature: str = "", incident_id: str | None = None) -> dict:
    cfg = get_config()
    transport = f"{cfg.get('protocol')}://{cfg.get('host')}:{cfg.get('port')}"
    if not cfg.get("enabled") or not cfg.get("host"):
        return {"ok": False, "skipped": True, "detail": "SIEM forwarding is not enabled/configured"}
    with _lock:
        batch = list(_QUEUE) + lines               # drain any backlog first
        try:
            _send_raw(cfg, batch)
            _QUEUE.clear()
            _record(kind, signature, incident_id, transport, True, f"delivered {len(batch)} line(s)")
            return {"ok": True, "sent": len(batch)}
        except Exception as e:                       # noqa: BLE001 — never propagate to the SOC
            _QUEUE.extend(lines)                      # bounded; oldest drop with the log below
            detail = f"unreachable: {e!r}; queued={len(_QUEUE)}"
            log.warning("SIEM forward failed to %s: %r (queued=%d)", transport, e, len(_QUEUE))
            _record(kind, signature, incident_id, transport, False, detail)
            return {"ok": False, "error": repr(e), "queued": len(_QUEUE)}


# --- public: build + forward (read-only-derived from existing records) ------

def _frame(cef_line: str, cfg: dict, cef_sev: int) -> str:
    return cef.syslog_line(cef_line, host=cfg.get("host_field", "kaaval"),
                           facility=int(cfg.get("facility", 16)), cef_sev=cef_sev)


def preview_incident(inc: dict, events: list[dict] | None = None) -> dict:
    """Build the CEF + syslog line WITHOUT sending (UI preview / validation)."""
    c = cef.incident_to_cef(inc, events)
    cfg = get_config()
    return {"cef": c, "syslog": _frame(c, cfg, cef.cef_severity(inc.get("severity")))}


def forward_incident(inc: dict, events: list[dict] | None = None) -> dict:
    cfg = get_config()
    c = cef.incident_to_cef(inc, events)
    line = _frame(c, cfg, cef.cef_severity(inc.get("severity")))
    return {**_forward([line], kind="incident", signature="incident", incident_id=inc.get("id")), "cef": c}


def forward_approval(ap: dict) -> dict:
    cfg = get_config()
    c = cef.approval_to_cef(ap)
    line = _frame(c, cfg, 8)
    return {**_forward([line], kind="approval", signature="approval", incident_id=ap.get("incident_id")), "cef": c}


def test_connection(cfg: dict | None = None) -> dict:
    """Send a single CEF heartbeat to validate connectivity/transport. Best-effort."""
    cfg = cfg or get_config()
    if not cfg.get("host"):
        return {"ok": False, "detail": "no SIEM host configured"}
    line = _frame(cef.heartbeat_cef(), cfg, 3)
    transport = f"{cfg.get('protocol')}://{cfg.get('host')}:{cfg.get('port')}"
    try:
        _send_raw(cfg, [line])
        _record("test", "heartbeat", None, transport, True, "heartbeat delivered")
        return {"ok": True, "detail": f"heartbeat delivered to {transport}"}
    except Exception as e:                            # noqa: BLE001
        _record("test", "heartbeat", None, transport, False, f"{e!r}")
        return {"ok": False, "detail": f"{transport} unreachable: {e!r}"}
