# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Deployment profile — the declared environment (assets + authorization).

The engine is scenario-agnostic; everything specific to a target plant lives in a
single YAML profile (config.PROFILE_PATH, default profiles/pumpstation.yaml).
Detection decides authorized-vs-unauthorized from this inventory — an observed
flow on a protocol from a client not in that protocol's allowed_clients is
unauthorized — instead of a guessed pivot IP or a capture-topology invariant.

Hot-reloaded by mtime so editing the profile takes effect on the next detection
cycle (used to prove authorization is data-driven).
"""

from __future__ import annotations

import os

import yaml

from . import config

_cache: dict = {"mtime": None, "data": None}


def _load() -> dict:
    path = config.PROFILE_PATH
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {"assets": [], "authorization": {}}
    if _cache["data"] is not None and _cache["mtime"] == mtime:
        return _cache["data"]
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        data = {}
    data.setdefault("assets", [])
    data.setdefault("authorization", {})
    _cache.update(mtime=mtime, data=data)
    return data


# --- assets -----------------------------------------------------------------

def assets() -> list[dict]:
    return _load()["assets"]


def asset_for_ip(ip: str | None) -> dict | None:
    if not ip:
        return None
    for a in assets():
        if ip in (a.get("ips") or []):
            return a
    return None


def name_for_ip(ip: str | None) -> str:
    a = asset_for_ip(ip)
    return a["id"] if a else (ip or "unknown")


def asset_context(ip: str | None) -> dict:
    a = asset_for_ip(ip)
    if not a:
        return {"id": ip or "unknown", "criticality": "unknown",
                "process_context": "External / unmanaged host (not in the asset inventory)."}
    return {"id": a["id"], "role": a.get("role"), "domain": a.get("domain"),
            "criticality": a.get("criticality"), "process_context": a.get("process_context")}


# --- authorization ----------------------------------------------------------

def authz(protocol: str) -> dict | None:
    return _load()["authorization"].get(protocol)


def is_authorized_client(protocol: str, ip: str | None) -> bool:
    """Is the asset at `ip` an allowed client for `protocol`? Unknown/unlisted
    sources are NOT authorized (fail safe)."""
    rule = authz(protocol)
    if rule is None:
        return False
    a = asset_for_ip(ip)
    return bool(a and a["id"] in (rule.get("allowed_clients") or []))


def allow_write(protocol: str) -> bool:
    rule = authz(protocol)
    return bool(rule and rule.get("allow_write"))


# --- response action catalog + device map (used only by the executor) -------

def actions() -> list[dict]:
    """The response action catalog declared by the profile (may be empty)."""
    return _load().get("actions") or []


def action(action_id: str) -> dict | None:
    return next((a for a in actions() if a.get("id") == action_id), None)


def executor_config() -> dict:
    """Optional `executors: {it: <adapter>, ot: <adapter>}` selection (F8). The
    profile selects which adapter is active; absent => the config/env default."""
    return _load().get("executors") or {}


def opcua_nodes() -> dict:
    """{namespace_uri, nodes: {tag: NodeId}} — the OPC UA control-path map."""
    m = _load().get("opcua_nodes") or {}
    return {"namespace_uri": m.get("namespace_uri"), "nodes": m.get("nodes") or {}}


# --- physical-safety descriptor + process view (per plant) ------------------

def safety() -> dict:
    """The variable + band + danger threshold that define 'in band' for this
    plant, plus the interlock tag. Drives status/recovery in a scenario-agnostic
    way. Safe defaults (all None) when a profile omits it — callers treat a
    missing safety variable as 'unknown', never crash."""
    s = _load().get("safety") or {}
    band = s.get("band") or [None, None]
    return {
        "variable": s.get("variable"),
        "band": list(band) if isinstance(band, (list, tuple)) else [None, None],
        "danger": s.get("danger"),
        "interlock_tag": s.get("interlock_tag"),
        "control_tag": s.get("control_tag"),
        "control_baseline": s.get("control_baseline"),
        "label": s.get("label"),
        "unit": s.get("unit"),
    }


def process_view() -> dict:
    """UI hint: which tags to surface and how to label them (optional)."""
    return _load().get("process_view") or {}


def name() -> str:
    return _load().get("name") or "Deployment"
