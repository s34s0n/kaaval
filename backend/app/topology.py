# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Automatic Purdue-model topology inference (F4).

Built ENTIRELY from real data and the system's EXISTING source of truth — no
synthetic topology, no fresh heuristic invented for the diagram:
  - Nodes  = discovered assets (asset_discovery.discover()).
  - Edges  = observed Zeek flows (zeek_stats.overview()['edges']).
  - Zone   = each asset's canonical domain (OT / IT / external) — the SAME zone
             detection/authz already use. The Purdue level is a deterministic
             refinement BY ROLE that never overrides the zone.
  - Findings = boundary violations judged by the SAME authorization function the
             rest of the system uses (profile.is_authorized_client, surfaced via
             the edge 'anomalous' flag). A red line on this map IS a real finding.

Local only. Read-only. No egress, no LLM, no action path. Invariant 1 holds by
construction (this module imports neither gating nor actions).
"""

from __future__ import annotations

from . import asset_discovery, profile, zeek_stats

# Purdue bands, top (enterprise/untrusted) -> bottom (process). `order` drives the
# vertical layout; smaller = higher in the stack, so an IT/external -> OT flow
# reads as a downward pivot toward the physical process.
_BAND_ORDER = {
    "External": 0, "IT · Enterprise": 1, "IT · Operations": 2, "IT/OT DMZ": 3,
    "OT · Supervisory": 4, "OT · Control": 5, "OT · Process": 6,
}


def _purdue(zone: str, device_type: str | None, role: str | None) -> dict:
    """Refine the CANONICAL zone (OT/IT/external) into a Purdue level by device
    role. The zone is authoritative; this only sub-classifies within it."""
    t = f"{device_type or ''} {role or ''}".lower()
    if zone == "external":
        band, level, label = "External", "ext", "External / Untrusted"
    elif zone == "OT":
        if any(k in t for k in ("gateway", "conduit", "dmz", "boundary")):
            band, level, label = "IT/OT DMZ", 3.5, "L3.5 · IT/OT DMZ (conduit)"
        elif any(k in t for k in ("rtu", "sensor", "field", "actuator", "transmitter", "process")):
            band, level, label = "OT · Process", 0, "L0 · Process"
        elif any(k in t for k in ("plc", "controller", "s7", "control client")):
            band, level, label = "OT · Control", 1, "L1 · Basic Control"
        else:  # opcua/scada/hmi/historian/supervisory and the OT default
            band, level, label = "OT · Supervisory", 2, "L2 · Supervisory"
    else:  # IT
        if any(k in t for k in ("engineering", "workstation", "ews", "operator",
                                "historian", "server", "soc", "hmi", "scada", "authorized hmi")):
            band, level, label = "IT · Operations", 3, "L3 · Operations"
        else:
            band, level, label = "IT · Enterprise", 4, "L4 · Enterprise IT"
    return {"band": band, "level": level, "label": label, "order": _BAND_ORDER[band]}


def graph(log_dir: str | None = None) -> dict:
    disc = asset_discovery.discover(log_dir) if log_dir else asset_discovery.discover()
    ov = zeek_stats.overview(log_dir)

    nodes = []
    for a in disc.get("assets", []):
        zone = a.get("domain") or "external"
        dt, role = a.get("device_type"), a.get("role")
        nodes.append({
            "id": a.get("id"), "ip": a.get("ip"), "zone": zone,
            "device_type": dt, "role": role, "criticality": a.get("criticality"),
            "unmanaged": bool(a.get("unmanaged")),
            # a device the fingerprint could not place from its observed protocols
            "unzoneable": bool(dt and dt.lower().startswith("unclassified")),
            "protocols": a.get("protocols", []),
            "purdue": _purdue(zone, dt, role),
        })
    # ONE zone source: edge endpoints take their zone from the same node map, so the
    # map can never show a device in two different zones.
    zmap = {n["id"]: n["zone"] for n in nodes}

    edges, findings = [], []
    for e in ov.get("edges", []):
        src, dst = e.get("src"), e.get("dst")
        sd = zmap.get(src, e.get("src_domain") or "external")
        dd = zmap.get(dst, e.get("dst_domain") or "external")
        violation = bool(e.get("anomalous"))     # == not profile.is_authorized_client(...)
        edges.append({
            "src": src, "dst": dst, "src_zone": sd, "dst_zone": dd,
            "services": e.get("services", []), "conns": e.get("conns"), "bytes": e.get("bytes"),
            "boundary_crossing": sd != dd, "violation": violation,
        })
        if violation:
            pivot = sd in ("IT", "external") and dd == "OT"
            findings.append({
                "type": "ot_pivot" if pivot else "unauthorized_ot_flow",
                "severity": "critical" if sd == "external" and dd == "OT" else "high",
                "src": src, "dst": dst, "services": e.get("services", []),
                "detail": (f"{src} ({sd}) → {dst} ({dd}) over {'/'.join(e.get('services') or []) or 'OT'}: "
                           "unauthorized client for an OT control protocol crossing the IT/OT boundary."),
            })

    for n in nodes:
        if n["unmanaged"]:
            findings.append({"type": "unmanaged_asset",
                             "severity": "high" if n["zone"] == "OT" else "medium",
                             "src": n["id"],
                             "detail": f"{n['id']} ({n['zone']}) is unmanaged — observed on the wire but not in the declared inventory."})
        if n["unzoneable"]:
            findings.append({"type": "unzoneable", "severity": "medium", "src": n["id"],
                             "detail": f"{n['id']} cannot be cleanly zoned from its observed protocols — review placement."})

    bands = sorted({n["purdue"]["band"] for n in nodes}, key=lambda b: _BAND_ORDER[b])
    sev_rank = {"critical": 3, "high": 2, "medium": 1}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 0), reverse=True)
    return {
        "nodes": nodes,
        "edges": edges,
        "findings": findings,
        "bands": [{"band": b, "order": _BAND_ORDER[b]} for b in bands],
        "summary": {
            "nodes": len(nodes), "edges": len(edges),
            "violations": sum(1 for f in findings if f["type"] in ("ot_pivot", "unauthorized_ot_flow")),
            "boundary_crossings": sum(1 for e in edges if e["boundary_crossing"]),
            "unmanaged": sum(1 for n in nodes if n["unmanaged"]),
            "findings": len(findings),
        },
    }
