# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Managed-inventory overlay — user-added assets + network config.

Kept separate from the authoritative deployment profile (profiles/*.yaml) so the
Assets view can ADD assets and set network parameters without rewriting the
profile's commented YAML. These entries enrich the inventory list and the network
map (and name-resolution for hosts the profile doesn't know); detection
authorization stays profile-driven (a newly added host is never auto-trusted).
"""

from __future__ import annotations

import json
import os
import threading

from . import config

_lock = threading.Lock()

_DOMAINS = ("IT", "OT", "external")
_CRITS = ("critical", "high", "medium", "low")


def _load() -> dict:
    try:
        with open(config.INVENTORY_PATH) as f:
            d = json.load(f)
    except (OSError, json.JSONDecodeError):
        d = {}
    d.setdefault("assets", [])
    d.setdefault("network", {"subnet": "", "monitored_ranges": [], "sensor_placement": "", "notes": ""})
    return d


def _save(d: dict) -> None:
    os.makedirs(os.path.dirname(config.INVENTORY_PATH), exist_ok=True)
    tmp = config.INVENTORY_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, config.INVENTORY_PATH)


# --- assets -----------------------------------------------------------------

def assets() -> list[dict]:
    return _load()["assets"]


def name_for_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    for a in assets():
        if ip in (a.get("ips") or []):
            return a["id"]
    return None


def domain_for_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    for a in assets():
        if ip in (a.get("ips") or []):
            return a.get("domain")
    return None


def _validate(a: dict) -> str | None:
    if not (a.get("id") or "").strip():
        return "id is required"
    if a.get("domain") not in _DOMAINS:
        return f"domain must be one of {_DOMAINS}"
    if a.get("criticality") not in _CRITS:
        return f"criticality must be one of {_CRITS}"
    if not isinstance(a.get("ips", []), list):
        return "ips must be a list"
    return None


def add_asset(a: dict) -> dict:
    """Upsert a managed asset by id (validated). Raises ValueError on bad input."""
    err = _validate(a)
    if err:
        raise ValueError(err)
    rec = {
        "id": a["id"].strip(), "domain": a["domain"], "criticality": a["criticality"],
        "ips": [str(x).strip() for x in (a.get("ips") or []) if str(x).strip()],
        "role": (a.get("role") or "").strip(), "notes": (a.get("notes") or "").strip(),
    }
    with _lock:
        d = _load()
        d["assets"] = [x for x in d["assets"] if x.get("id") != rec["id"]] + [rec]
        _save(d)
    return rec


def delete_asset(asset_id: str) -> bool:
    with _lock:
        d = _load()
        before = len(d["assets"])
        d["assets"] = [x for x in d["assets"] if x.get("id") != asset_id]
        _save(d)
        return len(d["assets"]) < before


# --- network config ---------------------------------------------------------

def network() -> dict:
    return _load()["network"]


def set_network(patch: dict) -> dict:
    with _lock:
        d = _load()
        net = d["network"]
        for k in ("subnet", "sensor_placement", "notes"):
            if k in patch and patch[k] is not None:
                net[k] = str(patch[k])
        if "monitored_ranges" in patch and isinstance(patch["monitored_ranges"], list):
            net["monitored_ranges"] = [str(x).strip() for x in patch["monitored_ranges"] if str(x).strip()]
        d["network"] = net
        _save(d)
        return net
