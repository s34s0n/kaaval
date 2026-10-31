# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""First-seen / rogue-device detection — discovery wired INTO detection.

On a static OT segment, "a device or a conversation we have never seen before" is
the single highest-signal anomaly. This is the thin, temporal complement to the
profile-authorization rules (NO ML baselining): a persisted seen-set of hosts and
(src,dst,proto) pairs. The FIRST observation establishes the baseline silently;
after that, a novel host or pair raises a real Event that flows through correlation
into an incident — instead of being merely visualized in the Assets view.

A novel host that is also UNDECLARED (not in the profile/inventory) is a rogue
device (high/critical); a novel conversation touching an OT protocol is high.
"""

from __future__ import annotations

from . import config, inventory, profile, store
from .model import Event

_PORT_PROTO = {22: "ssh", 53: "dns", 443: "tls", 80: "http", 102: "s7comm",
               4840: "opcua", 502: "modbus", 3389: "rdp"}
_OT_PROTOS = {"s7comm", "opcua", "modbus"}


def _managed(ip: str) -> bool:
    return profile.asset_for_ip(ip) is not None or inventory.name_for_ip(ip) is not None


def _name(ip: str) -> str:
    return profile.name_for_ip(ip) or inventory.name_for_ip(ip) or ip


def _domain(ip: str, ot: bool) -> str:
    a = profile.asset_for_ip(ip)
    if a:
        return a.get("domain") or ("OT" if ot else "IT")
    if inventory.domain_for_ip(ip):
        return inventory.domain_for_ip(ip)
    return "OT" if ot else "IT"


def detect(logs: dict) -> list[Event]:
    conn_rows = logs.get("conn", [])
    if not conn_rows:
        return []

    # current hosts + (src,dst,proto) pairs from this window.
    host_ts: dict[str, float] = {}
    pair_ts: dict[str, tuple] = {}   # pairkey -> (ts, src, dst, proto)
    for r in conn_rows:
        o, d, p, ts = r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p"), r.get("ts") or 0.0
        if not o or not d:
            continue
        proto = _PORT_PROTO.get(p, str(p))
        host_ts.setdefault(o, ts); host_ts.setdefault(d, ts)
        key = f"{o}|{d}|{proto}"
        pair_ts.setdefault(key, (ts, o, d, proto))

    db = store.connect(); store.init(db)
    try:
        baselined = store.meta_get(db, "baselined")
        seen_hosts = store.get_seen_hosts(db)
        seen_pairs = store.get_seen_pairs(db)
        events: list[Event] = []

        new_hosts = [(ip, ts) for ip, ts in host_ts.items() if ip not in seen_hosts]
        new_pairs = [(k, v) for k, v in pair_ts.items() if k not in seen_pairs]

        for ip, ts in new_hosts:
            ot = any(v[3] in _OT_PROTOS and (v[1] == ip or v[2] == ip) for v in pair_ts.values())
            if not _managed(ip):
                # ROGUE: an undeclared host is inherently novel — alert on FIRST sight,
                # independent of any learning window (deduped via seen_hosts so it fires
                # once). This is the highest-signal, timing-robust OT detection.
                events.append(Event(
                    id=f"rogue_asset#{ip}", ts=ts, domain=_domain(ip, ot), rule="rogue_asset",
                    techniques=[{"id": "T0848", "name": "Rogue Master / Undeclared Device"}],
                    severity="critical" if ot else "high", src=ip, dst="monitored-segment",
                    summary=f"Undeclared device {ip} observed on the monitored segment "
                            f"(not in the asset inventory){' · speaks OT protocols' if ot else ''}.",
                    evidence_count=1, evidence={"ip": ip, "ot_speaker": ot, "managed": False}))
            elif baselined:
                # A KNOWN asset newly appearing — low-signal, and only after the baseline
                # is established (avoids start-up noise from declared assets coming online).
                events.append(Event(
                    id=f"new_device#{ip}", ts=ts, domain=_domain(ip, ot), rule="new_device",
                    techniques=[], severity="low", src=ip, dst="monitored-segment",
                    summary=f"Known asset {_name(ip)} ({ip}) appeared on the segment for the first time.",
                    evidence_count=1, evidence={"ip": ip, "managed": True}))

        # New conversation pairs are baseline-gated (the first populated cycle seeds the
        # steady-state so we don't flood on start-up); after that, a novel pair alerts.
        if baselined:
            for key, (ts, o, d, proto) in new_pairs:
                ot = proto in _OT_PROTOS
                events.append(Event(
                    id=f"new_conversation#{key}", ts=ts, domain="OT" if ot else "IT", rule="new_conversation",
                    techniques=[{"id": "T0840", "name": "Network Connection Enumeration"}] if ot else [],
                    severity="high" if ot else "low", src=_name(o), dst=f"{_name(d)}:{proto}",
                    summary=f"New conversation {_name(o)} -> {_name(d)} over {proto}, not previously "
                            f"observed on this segment{' (OT protocol)' if ot else ''}.",
                    evidence_count=1, evidence={"src": o, "dst": d, "proto": proto}))

        # Promote observations into the baseline so each alerts only once; mark baseline
        # established after the first cycle that actually saw traffic.
        store.add_seen_hosts(db, [(ip, ts, _managed(ip)) for ip, ts in new_hosts])
        store.add_seen_pairs(db, [(k, pair_ts[k][0]) for k, _ in new_pairs])
        if not baselined and host_ts:
            store.meta_set(db, "baselined", "1")
        return events
    finally:
        db.close()
