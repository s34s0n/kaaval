# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Behavior-derived adversary labels — correlation / narrative layer ONLY (F-fix).

Passive discovery stays honest: an undeclared host is an UNMANAGED IP, nothing more.
Only here — once correlation has seen the full pattern (an UNMANAGED host that is the
SOURCE of remote access / scanning / unauthorized OT, or the DESTINATION of a C2
beacon) — do we draw the CONCLUSION and name it. These labels are NEVER written to the
asset inventory or to discovery; they decorate the incident narrative / CEF / kill-
chain only. Discovery and the inventory never call this module.
"""

from __future__ import annotations

import ipaddress

from . import inventory, profile

ADVERSARY = "external adversary host"
C2 = "C2 endpoint"

# rule-id fragments that put a host in an adversarial ROLE
_SOURCE_RULES = ("remote_access", "remote_services", "scan", "unauthorized", "rogue")
_BEACON_RULES = ("beacon", "c2")


def _get(e, k, default=None):
    return e.get(k, default) if isinstance(e, dict) else getattr(e, k, default)


def _host(v):
    return str(v).split(":")[0] if v else None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _managed(host: str | None) -> bool:
    """A host is MANAGED if it's a declared asset. Event src/dst is name_for_ip():
    a non-IP value is already a declared name; an IP is managed only if the profile
    or inventory knows it."""
    if not host:
        return True
    if not _is_ip(host):
        return True
    return bool(profile.asset_for_ip(host) or inventory.domain_for_ip(host))


def label_hosts(events) -> dict:
    """Return {host -> behavioral label} for the UNMANAGED hosts this incident's
    events implicate as adversarial. Empty when nothing qualifies (honest default)."""
    labels: dict[str, str] = {}
    for e in events:
        rule = (_get(e, "rule") or "").lower()
        src, dst = _host(_get(e, "src")), _host(_get(e, "dst"))
        if any(k in rule for k in _SOURCE_RULES) and src and not _managed(src):
            labels[src] = ADVERSARY
        if any(k in rule for k in _BEACON_RULES) and dst and not _managed(dst):
            labels.setdefault(dst, C2)
    return labels


def rogue_devices(events) -> list[str]:
    """UNMANAGED host IPs implicated as src/dst in these events — the rogue devices
    involved in the incident. Derived/read-only; deduped + sorted. Callers ACCUMULATE
    this onto the case so the rogue device persists after the transient F1 rogue_asset
    alert has aged out of the live event list."""
    out = set()
    for e in events:
        for k in ("src", "dst"):
            host = _host(_get(e, k))
            if host and _is_ip(host) and not _managed(host):
                out.add(host)
    return sorted(out)


def relabel(text: str, labels: dict) -> str:
    """Substitute raw host tokens with their behavioral label in a narrative string.
    Longest token first so an IP isn't partially replaced."""
    if not text or not labels:
        return text
    for raw, lab in sorted(labels.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(raw, lab)
    return text
