# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rules store — built-in detection catalog (toggleable) + user-defined rules.

Persists to a JSON file (config.RULES_PATH), hot-reloaded by mtime so a rule
added or toggled via the API takes effect on the next detection cycle without a
restart. The 5 built-in detections are full generic rule specs here (BUILTINS),
evaluated by rules_engine just like user rules — there are no hardcoded detection
functions. `builtin_enabled` flags gate the built-ins; user rules carry their own
`enabled`. active_rules() returns the enabled set the engine runs.

File shape:
  {
    "builtin_enabled": { "<rule_id>": true, ... },   # overrides; default true
    "user_rules": [ { generic rule }, ... ]
  }
"""

from __future__ import annotations

import json
import os
import tempfile
import threading

from . import config

# Built-in detection rules — now full generic specs evaluated by rules_engine
# (no hardcoded detection functions). `rule` is the canonical short name used by
# correlation/agents/UI; `condition`/`log` are display strings for the rules list.
BUILTINS: list[dict] = [
    {"id": "it.external_remote_access", "rule": "external_remote_access",
     "name": "External remote access (inbound SSH from a non-authorized client)",
     "domain": "IT", "severity": "high", "attack": ["T0822"], "action": "alert",
     "log": "ssh", "logs": ["ssh"],
     "where": [{"field": "id.resp_p", "op": "eq", "value": 22}],
     "unauthorized": "ssh",
     "condition": "inbound SSH from a source not in ssh.allowed_clients",
     "summary": "Inbound SSH to {dst} from non-authorized source {src}"},

    {"id": "it.c2_beaconing", "rule": "c2_beaconing",
     "name": "C2 beaconing (TLS/DNS to an external host)",
     "domain": "IT", "severity": "high", "attack": ["T0869"], "action": "alert",
     "log": "ssl,dns", "logs": ["ssl", "dns"], "external_dst": True,
     "aggregate": "count", "min_count": config.BEACON_MIN,
     "condition": f">= {config.BEACON_MIN} TLS/DNS flows from one source to an external host",
     "summary": "Periodic TLS+DNS beacon from {src} to external host {dst} ({n} flows)"},

    {"id": "it.ot_network_scan", "rule": "ot_network_scan",
     "name": "Network scan (one source, many host/port pairs)",
     "domain": "IT", "severity": "medium", "attack": ["T0846"], "action": "alert",
     "log": "conn", "logs": ["conn"],
     "aggregate": "distinct", "distinct_on": ["id.resp_h", "id.resp_p"],
     "min_count": config.SCAN_MIN_TARGETS,
     "condition": f"source touching >= {config.SCAN_MIN_TARGETS} distinct host/port pairs",
     "summary": "Network scan from {src}: {n} host/port pairs"},

    {"id": "ot.unauthorized_opcua_access", "rule": "unauthorized_opcua_access",
     "name": "Unauthorized OPC UA access",
     "domain": "OT", "severity": "high", "attack": ["T0888"], "action": "alert",
     "log": "opcua_binary", "logs": ["opcua_binary"], "unauthorized": "opcua",
     "condition": "OPC UA from a source not in opcua.allowed_clients",
     "summary": "Unauthorized OPC UA session from {src} (not an authorized OPC UA client)"},

    {"id": "ot.unauthorized_s7_command", "rule": "unauthorized_s7_command",
     "name": "Unauthorized direct S7comm",
     "domain": "OT", "severity": "high", "attack": ["T0855"], "action": "alert",
     "log": "s7comm", "logs": ["s7comm"], "unauthorized": "s7comm",
     "escalate": {"where": [{"field": "function_name", "op": "contains", "value": "write"}],
                  "write_proto": "s7comm", "severity": "critical",
                  "add_attack": ["T0836", "T0831"]},
     "condition": "S7comm from a source not in s7comm.allowed_clients; write -> critical",
     "summary": "Unauthorized direct S7comm from {src} (not an authorized S7comm client)"},
]
BUILTIN_IDS = {b["id"] for b in BUILTINS}

# A couple of example user rules seeded so the list/engine are non-empty.
SEED_USER_RULES: list[dict] = [
    {"id": "user.suspicious_tls_sni", "name": "TLS to known-bad C2 SNI", "enabled": False,
     "domain": "IT", "log": "ssl", "field": "server_name", "op": "contains", "value": "kaaval-c2",
     "severity": "medium", "attack": ["T0869"], "action": "alert",
     "description": "TLS handshake whose SNI references the C2 domain."},
]

_VALID_OPS = {"eq", "ne", "contains", "gt", "ge", "lt", "le", "exists"}

_lock = threading.Lock()
_cache: dict = {"mtime": None, "data": None}


# --- persistence ------------------------------------------------------------

def _default() -> dict:
    return {"builtin_enabled": {b["id"]: True for b in BUILTINS},
            "user_rules": list(SEED_USER_RULES)}


def _load() -> dict:
    path = config.RULES_PATH
    if not os.path.exists(path):
        data = _default()
        _atomic_write(data)
        return data
    mtime = os.path.getmtime(path)
    if _cache["data"] is not None and _cache["mtime"] == mtime:
        return _cache["data"]
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        data = _default()
    data.setdefault("builtin_enabled", {})
    data.setdefault("user_rules", [])
    for b in BUILTINS:                       # ensure every builtin has a flag
        data["builtin_enabled"].setdefault(b["id"], True)
    _cache.update(mtime=os.path.getmtime(path), data=data)
    return data


def _atomic_write(data: dict) -> None:
    path = config.RULES_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    _cache.update(mtime=os.path.getmtime(path), data=data)


# --- queries used by the detection engine ----------------------------------

def enabled(rule_id: str) -> bool:
    """Is this rule active? Built-ins default enabled; user rules per their flag."""
    data = _load()
    if rule_id in BUILTIN_IDS:
        return bool(data["builtin_enabled"].get(rule_id, True))
    for r in data["user_rules"]:
        if r.get("id") == rule_id:
            return bool(r.get("enabled", True))
    return False


def active_user_rules() -> list[dict]:
    return [r for r in _load()["user_rules"] if r.get("enabled", True)]


def active_rules() -> list[dict]:
    """All enabled rules — built-in (full specs) + user — for the engine."""
    return [r for r in list_rules() if r.get("enabled", True)]


# --- API surface ------------------------------------------------------------

def list_rules() -> list[dict]:
    """Merged view: built-ins (with live enabled state) + user rules."""
    data = _load()
    out = []
    for b in BUILTINS:
        out.append({**b, "builtin": True, "enabled": data["builtin_enabled"].get(b["id"], True)})
    for r in data["user_rules"]:
        out.append({**r, "builtin": False, "enabled": r.get("enabled", True)})
    return out


def get_rule(rule_id: str) -> dict | None:
    return next((r for r in list_rules() if r["id"] == rule_id), None)


def _validate_user_rule(r: dict) -> str | None:
    for k in ("log", "field", "op", "value", "severity"):
        if k not in r:
            return f"missing required field '{k}'"
    if r["op"] not in _VALID_OPS:
        return f"invalid op '{r['op']}' (allowed: {sorted(_VALID_OPS)})"
    if r["severity"] not in config.SEVERITY_RANK:
        return f"invalid severity '{r['severity']}'"
    return None


def create_rule(rule: dict) -> dict:
    err = _validate_user_rule(rule)
    if err:
        raise ValueError(err)
    with _lock:
        data = _load()
        rid = rule.get("id") or f"user.{_slug(rule.get('name', rule['field']))}"
        if rid in BUILTIN_IDS or any(r["id"] == rid for r in data["user_rules"]):
            raise ValueError(f"rule id '{rid}' already exists")
        new = {"id": rid, "name": rule.get("name", rid), "enabled": rule.get("enabled", True),
               "domain": rule.get("domain", "IT"), "log": rule["log"], "field": rule["field"],
               "op": rule["op"], "value": rule["value"], "severity": rule["severity"],
               "attack": rule.get("attack", []), "action": rule.get("action", "alert"),
               "description": rule.get("description", "")}
        if "min_count" in rule:
            new["min_count"] = int(rule["min_count"])
        data["user_rules"].append(new)
        _atomic_write(data)
        return {**new, "builtin": False}


def update_rule(rule_id: str, patch: dict) -> dict:
    with _lock:
        data = _load()
        if rule_id in BUILTIN_IDS:
            # Only the enabled flag is mutable on built-ins.
            if "enabled" in patch:
                data["builtin_enabled"][rule_id] = bool(patch["enabled"])
                _atomic_write(data)
            return get_rule(rule_id)
        for i, r in enumerate(data["user_rules"]):
            if r["id"] == rule_id:
                merged = {**r, **{k: v for k, v in patch.items() if k != "id"}}
                err = _validate_user_rule(merged)
                if err:
                    raise ValueError(err)
                data["user_rules"][i] = merged
                _atomic_write(data)
                return {**merged, "builtin": False}
        raise KeyError(rule_id)


def toggle_rule(rule_id: str) -> dict:
    cur = get_rule(rule_id)
    if cur is None:
        raise KeyError(rule_id)
    return update_rule(rule_id, {"enabled": not cur["enabled"]})


def delete_rule(rule_id: str) -> None:
    if rule_id in BUILTIN_IDS:
        raise ValueError("cannot delete a built-in rule (toggle it instead)")
    with _lock:
        data = _load()
        n = len(data["user_rules"])
        data["user_rules"] = [r for r in data["user_rules"] if r["id"] != rule_id]
        if len(data["user_rules"]) == n:
            raise KeyError(rule_id)
        _atomic_write(data)


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in s.lower()).strip("_")[:40] or "rule"
