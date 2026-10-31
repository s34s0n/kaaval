# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Asset inventory — sourced from the deployment profile (single source of truth).

The profile (profiles/*.yaml) declares the assets and the per-protocol
authorization. This module exposes that inventory in the shape the SOC Assets
view and the analyst-chat `get_asset` tool consume, deriving `authorized_ot` and
`speaks` from the authorization policy. No hardcoded asset list lives here.
"""

from __future__ import annotations

from . import inventory, profile

_OT_PROTOCOLS = ("s7comm", "opcua")
_ALL_PROTOCOLS = ("s7comm", "opcua", "ssh")


def _authorized_for(asset_id: str, proto: str) -> bool:
    rule = profile.authz(proto) or {}
    return asset_id in (rule.get("allowed_clients") or [])


def _shape(a: dict) -> dict:
    aid = a["id"]
    speaks = [p for p in _ALL_PROTOCOLS if _authorized_for(aid, p)]
    return {
        "name": aid,
        "role": a.get("role"),
        "domain": a.get("domain"),
        "criticality": a.get("criticality"),
        "ips": a.get("ips", []),
        "speaks": speaks,
        "authorized_ot": any(_authorized_for(aid, p) for p in _OT_PROTOCOLS),
        "notes": (a.get("process_context") or "").strip(),
    }


def _shape_managed(a: dict) -> dict:
    return {
        "name": a["id"], "role": a.get("role"), "domain": a.get("domain"),
        "criticality": a.get("criticality"), "ips": a.get("ips", []),
        "speaks": [], "authorized_ot": False, "notes": (a.get("notes") or "").strip(),
        "managed": True,
    }


def list_assets() -> list[dict]:
    """Profile inventory (authoritative) + any user-managed assets (overlay)."""
    out = [{**_shape(a), "managed": False} for a in profile.assets()]
    known = {a["name"] for a in out}
    out += [_shape_managed(a) for a in inventory.assets() if a.get("id") not in known]
    return out


def get_asset(query: str) -> dict | None:
    q = (query or "").lower()
    for a in list_assets():
        if q and (q in a["name"].lower() or q in (a.get("role") or "").lower()):
            return a
    return None
