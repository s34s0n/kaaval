# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Passive asset discovery — derive the OT/IT inventory from the wire (Dragos-style).

Instead of a hand-entered list, this builds the asset inventory from what the Zeek
sensor actually observed: every host that appears in conn/ssh/ssl/dns and the OT
logs (s7comm/opcua/cotp), fingerprinted to a device type, classified into a zone
(OT/IT/external), and enriched with the protocols it speaks, who it talks to, how
much, and when it was first/last seen. The declared profile inventory becomes the
KNOWN baseline — anything seen on the wire but not declared is flagged UNMANAGED
(a potential rogue device), which is the high-value signal an OT-SOC wants.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from . import assets as assets_mod, config, inventory, profile
from .model import load_logs

# resp-port → app protocol (server side).
_PORT_PROTO = {22: "ssh", 53: "dns", 443: "tls", 80: "http", 102: "s7comm", 4840: "opcua", 502: "modbus", 3389: "rdp"}


def _internal_ranges():
    """The plant's OWN address space — the single source of truth for internal vs
    external. The declared `monitored_ranges` (plus the sensor `subnet`) are the
    plant's ranges; anything inside is INTERNAL (a plant asset, declared or not),
    anything outside is EXTERNAL. This replaces per-host `domain: external`
    declarations — discovery decides scope from the address, not a hand label."""
    net = inventory.network()
    cidrs = [str(c).strip() for c in (net.get("monitored_ranges") or [])]
    if net.get("subnet"):
        cidrs.append(str(net["subnet"]).strip())
    out = []
    for c in cidrs:
        try:
            out.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    if not out:
        out.append(ipaddress.ip_network("172.30.0.0/24"))
    return out


def _is_external(ip, ranges):
    """External = NOT inside any of the plant's own ranges. Loopback and unparsable
    are treated as internal (never spuriously external)."""
    if ip in ("127.0.0.1", "::1"):
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not ranges:
        return False
    return not any(addr in n for n in ranges)


def _new(ip):
    return {"ip": ip, "protocols": set(), "server_protos": set(), "client_protos": set(),
            "peers": set(), "conns": 0, "bytes": 0, "first_seen": None, "last_seen": None}


def _seen(h, ts):
    if ts is None:
        return
    h["first_seen"] = ts if h["first_seen"] is None else min(h["first_seen"], ts)
    h["last_seen"] = ts if h["last_seen"] is None else max(h["last_seen"], ts)


def _fingerprint(h, external):
    sp, cp = h["server_protos"], h["client_protos"]
    if external:
        return "External host", "external", "low"
    if "s7comm" in sp:
        return "Siemens S7 PLC", "OT", "critical"
    if "opcua" in sp:
        return "OPC UA server / gateway", "OT", "high"
    if "modbus" in sp:
        return "Modbus device", "OT", "high"
    if "s7comm" in cp or "opcua" in cp:
        return "OT control client", "OT", "high"     # speaks OT but isn't the server
    if "ssh" in sp or "rdp" in sp:
        return "Host / server (SSH/RDP)", "IT", "medium"
    if cp & {"tls", "dns", "http", "ssh"}:
        return "Workstation / IT endpoint", "IT", "medium"
    return "Unclassified host", "IT", "low"


def discover(log_dir: str | None = None) -> dict:
    logs = load_logs(log_dir or config.LOG_DIR)
    nets = _internal_ranges()
    hosts: dict[str, dict] = {}

    def H(ip):
        if ip not in hosts:
            hosts[ip] = _new(ip)
        return hosts[ip]

    # conn.log — the host universe + volume + peers.
    for r in logs.get("conn", []):
        o, d, p = r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p")
        if not o or not d:
            continue
        b = (r.get("orig_ip_bytes") or 0) + (r.get("resp_ip_bytes") or 0)
        proto = _PORT_PROTO.get(p)
        for ip, other, role in ((o, d, "client"), (d, o, "server")):
            h = H(ip)
            h["conns"] += 1 if role == "client" else 0
            h["bytes"] += b
            h["peers"].add(other)
            _seen(h, r.get("ts"))
            if proto:
                h["protocols"].add(proto)
                h[("server_protos" if role == "server" else "client_protos")].add(proto)

    # app logs — confirm protocol + server/client roles by analyzer (more reliable).
    def app(rows, proto, src="id.orig_h", dst="id.resp_h"):
        for r in rows:
            o, d = r.get(src), r.get(dst)
            if o:
                H(o)["protocols"].add(proto); H(o)["client_protos"].add(proto); _seen(H(o), r.get("ts"))
            if d:
                H(d)["protocols"].add(proto); H(d)["server_protos"].add(proto); _seen(H(d), r.get("ts"))
    app(logs.get("ssh", []), "ssh")
    app(logs.get("ssl", []), "tls")
    app(logs.get("dns", []), "dns")
    app(logs.get("opcua_binary", []), "opcua")
    # ICSNPP s7comm uses source_h/destination_h when present.
    for r in logs.get("s7comm", []):
        o = r.get("id.orig_h") or r.get("source_h"); d = r.get("id.resp_h") or r.get("destination_h")
        if o:
            H(o)["protocols"].add("s7comm"); H(o)["client_protos"].add("s7comm"); _seen(H(o), r.get("ts"))
        if d:
            H(d)["protocols"].add("s7comm"); H(d)["server_protos"].add("s7comm"); _seen(H(d), r.get("ts"))

    # classify + enrich against the declared inventory.
    declared = {a["name"]: a for a in assets_mod.list_assets()}
    decl_by_ip = {ip: a for a in declared.values() for ip in (a.get("ips") or [])}

    out = []
    for ip, h in hosts.items():
        external = _is_external(ip, nets)
        dev, domain, crit = _fingerprint(h, external)
        known = decl_by_ip.get(ip)
        if known:
            # A declared asset: trust the inventory's role/zone over the inference.
            name = known["name"]; managed = True
            domain = known.get("domain") or domain
            crit = known.get("criticality") or crit
            authorized_ot = bool(known.get("authorized_ot"))
            dev = known.get("role") or dev
        else:
            name = None; managed = False; authorized_ot = False
        out.append({
            "id": name or ip, "ip": ip, "name": name, "managed": managed, "unmanaged": not managed,
            # scope is decided from the ADDRESS (monitored_ranges), not a host label:
            #   internal + unmanaged = a not-yet-declared plant device (enroll it)
            #   external             = outside the plant's ranges
            "scope": "external" if external else "internal",
            "enrollment_candidate": (not managed) and (not external),
            "domain": domain, "device_type": dev, "criticality": crit, "authorized_ot": authorized_ot,
            "protocols": sorted(h["protocols"]),
            "role": ("server" if h["server_protos"] and not h["client_protos"]
                     else "client" if h["client_protos"] and not h["server_protos"]
                     else "both" if h["server_protos"] else "—"),
            "peers": len(h["peers"]), "conns": h["conns"], "bytes": h["bytes"],
            "first_seen": h["first_seen"], "last_seen": h["last_seen"],
        })

    # Include declared assets with no current traffic (known but quiet), so the
    # inventory is complete, not just whatever happened to talk this window.
    seen_ips = set(hosts)
    for a in declared.values():
        if not any(ip in seen_ips for ip in (a.get("ips") or [])):
            out.append({
                "id": a["name"], "ip": (a.get("ips") or [None])[0], "name": a["name"],
                "managed": True, "unmanaged": False,
                "scope": "external" if a.get("domain") == "external" else "internal",
                "enrollment_candidate": False, "domain": a.get("domain"),
                "device_type": a.get("role") or "Declared asset", "criticality": a.get("criticality"),
                "authorized_ot": bool(a.get("authorized_ot")), "protocols": [], "role": "—",
                "peers": 0, "conns": 0, "bytes": 0, "first_seen": None, "last_seen": None, "quiet": True,
            })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.sort(key=lambda a: (order.get(a["criticality"], 9), -a["bytes"]))
    summary = {
        "total": len(out),
        "ot": sum(1 for a in out if a["domain"] == "OT"),
        "it": sum(1 for a in out if a["domain"] == "IT"),
        "external": sum(1 for a in out if a["scope"] == "external"),
        "internal_unmanaged": sum(1 for a in out if a.get("enrollment_candidate")),
        "unmanaged": sum(1 for a in out if a["unmanaged"]),
        "active": sum(1 for a in out if a.get("last_seen")),
    }
    return {"assets": out, "summary": summary,
            "subnet": inventory.network().get("subnet"),
            "ranges": [str(n) for n in nets]}
