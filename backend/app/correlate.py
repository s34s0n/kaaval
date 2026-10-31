# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Cross-domain correlation — fuse IT and OT events into single incidents.

The product differentiator: most OT tools see only OT and most IT SOCs see only
IT. Here the linkage is the shared ENTITY (a host the activity transits), not mere
co-occurrence in time — so an IT foothold that pivots into OT is one intrusion even
when the stages are far apart.

Multi-scale (P5): clustering is entity-linked across two timescales. Events that
share a host link when they are either (a) contemporaneous — within the BURST
window — or (b) a campaign PROGRESSION: within the wider, rolling CAMPAIGN window
and introducing a stage (rule) the cluster does not yet have. A later REPEAT of an
existing stage beyond the burst window is NOT linked — it forms its own incident.
This keeps a fast attack and a low-and-slow one both correct: the slow IT->OT
campaign fuses, while a re-run of the same action stays a separate case.
"""

from __future__ import annotations

import hashlib
from collections import Counter

from . import adversary, config
from .model import Event, Incident


def _incident_id(cluster: list[Event]) -> str:
    """A STABLE id derived from the cluster's anchor — its earliest event — not from
    its position in the result list. As later stages of the same campaign flush into
    the cluster, the anchor is unchanged, so the incident keeps its id across
    detection cycles; its triage and approvals are never orphaned by re-clustering.
    (Anchoring on the pivot would be fragile — the most-common source can shift as
    the cluster grows.)"""
    anchor = min(cluster, key=lambda e: e.ts)
    sig = hashlib.sha1(anchor.id.encode()).hexdigest()[:8]
    return f"INC-{sig}"

def _narrative(events: list[dict], pivot: str) -> str:
    # Build the kill-chain narrative from the fired rules' own metadata (each
    # event's summary), in the order the activity actually happened (by ts). No
    # hardcoded scenario phrases — the story is whatever the data says.
    ordered = sorted(events, key=lambda e: e.get("ts", 0))
    steps = [e.get("summary") or e.get("rule") for e in ordered]
    domains = {e["domain"] for e in events}
    # Describe only what was actually detected, naming the pivot the data implicates.
    if "IT" in domains and "OT" in domains:
        lead = f"IT activity pivoted into OT through {pivot}: "
    elif domains == {"OT"}:
        lead = f"Unauthorized OT activity from {pivot}: "
    else:
        lead = f"Suspicious IT activity from {pivot}: "
    # Narrative-layer ONLY: name the unmanaged adversary/C2 hosts as a behavioral
    # CONCLUSION (discovery still knows them only as unmanaged IPs).
    return adversary.relabel(lead + " → ".join(steps) + ".", adversary.label_hosts(events))


def _hosts(e: Event) -> set:
    """The host entities an event touches (source + destination host, no port)."""
    hosts = set()
    if e.src:
        hosts.add(e.src)
    if e.dst:
        hosts.add(str(e.dst).split(":")[0])
    return hosts


def _crosses_boundary(c_last: float, ts: float, boundaries) -> bool:
    """True if an explicit campaign boundary falls between a cluster's last event and
    this one — i.e. a NEW attack was launched in that gap, so this is a new incident."""
    return any(c_last < b <= ts for b in boundaries)


def _link_clusters(evs: list[Event], boundaries=()) -> list[list[Event]]:
    """Single entity-linked, multi-scale pass over time-ordered events. Each event
    attaches to an existing cluster it shares a host with when the link is either
    contemporaneous (within the burst window) or a campaign progression (within the
    rolling campaign window and a NEW rule for that cluster); otherwise it opens a
    new cluster. An event that is eligible for several clusters bridges them.

    A campaign boundary (recorded when an operator launches a fresh attack) always
    splits: events on opposite sides never link, even on the same host — so several
    distinct campaigns through the same pivot form several distinct incidents."""
    burst = config.CORRELATION_WINDOW_S
    campaign = config.CAMPAIGN_WINDOW_S
    clusters: list[dict] = []   # {hosts:set, rules:set, events:[Event], last_ts:float}
    for e in evs:
        eh = _hosts(e)
        eligible = []
        for c in clusters:
            if not (c["hosts"] & eh):
                continue
            if _crosses_boundary(c["last_ts"], e.ts, boundaries):
                continue                                        # new campaign — do not link
            gap = e.ts - c["last_ts"]
            if gap <= burst:
                eligible.append(c)                              # same contemporaneous activity
            elif gap <= campaign and e.rule not in c["rules"]:
                eligible.append(c)                              # campaign progressing (new stage)
            # same rule beyond the burst window => a repeat: not linked here.
        if not eligible:
            clusters.append({"hosts": set(eh), "rules": {e.rule}, "events": [e], "last_ts": e.ts})
            continue
        head = eligible[0]
        for other in eligible[1:]:                              # bridge clusters this event joins
            head["hosts"] |= other["hosts"]
            head["rules"] |= other["rules"]
            head["events"].extend(other["events"])
            head["last_ts"] = max(head["last_ts"], other["last_ts"])
            clusters.remove(other)
        head["hosts"] |= eh
        head["rules"].add(e.rule)
        head["events"].append(e)
        head["last_ts"] = max(head["last_ts"], e.ts)
    return [c["events"] for c in clusters]


def correlate(events: list[Event], boundaries=()) -> list[Incident]:
    if not events:
        return []
    evs = sorted(events, key=lambda e: e.ts)
    clusters = _link_clusters(evs, boundaries)
    clusters.sort(key=lambda c: min(e.ts for e in c))

    incidents: list[Incident] = []
    for cluster in clusters:
        cd = [e.to_dict() for e in cluster]
        domains = sorted({e.domain for e in cluster})
        # union techniques, de-duped by id, preserving first-seen order
        techs, seen = [], set()
        for e in cluster:
            for t in e.techniques:
                if t["id"] not in seen:
                    seen.add(t["id"]); techs.append(t)
        first_seen = min(e.ts for e in cluster)
        last_seen = max(e.ts for e in cluster)
        # Pivot = the source asset implicated in the most events (derived from the
        # data, not a guessed IP).
        pivot = Counter(e.src for e in cluster).most_common(1)[0][0]
        incidents.append(Incident(
            id=_incident_id(cluster),
            created=last_seen,
            first_seen=first_seen,
            last_seen=last_seen,
            severity=config.max_severity(e.severity for e in cluster),
            pivot=pivot,
            cross_domain=("IT" in domains and "OT" in domains),
            domains=domains,
            techniques=techs,
            event_ids=[e.id for e in cluster],
            summary=_narrative(cd, pivot),
        ))
    return incidents
