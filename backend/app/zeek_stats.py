# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Zeek log analytics — protocol-aware aggregations over the sensor's logs.

Turns the raw Zeek logs (conn / dns / ssl / ssh + the ICSNPP OT logs opcua_binary /
s7comm / cotp) into the structured views an OT-SOC actually wants: who talks to
whom, by which protocol, how much, and whether that peer is AUTHORIZED for the OT
protocols (decided from the deployment profile's inventory — not guessed). Read-only
and stateless: it re-derives everything from the current logs on each call.
"""

from __future__ import annotations

from collections import defaultdict

from . import config, inventory, profile
from .model import load_logs

# Well-known ports → service label (display only).
_SVC = {22: "ssh", 53: "dns", 443: "https", 102: "s7comm", 4840: "opcua",
        3389: "rdp", 445: "smb", 80: "http", 502: "modbus"}

# Protocols we surface, with their layer. OT protocols are the ICSNPP analyzers.
_PROTOCOLS = [
    ("ssh", "SSH", "IT"), ("ssl", "TLS / SSL", "IT"), ("dns", "DNS", "IT"),
    ("conn", "Connections", "IT"),
    ("s7comm", "S7comm", "OT"), ("opcua_binary", "OPC UA", "OT"), ("cotp", "COTP", "OT"),
]

# Authorization is keyed by protocol name in the profile.
_OT_AUTHZ = {"s7comm": "s7comm", "opcua_binary": "opcua"}


def _svc(port) -> str:
    try:
        return _SVC.get(int(port), str(port))
    except (TypeError, ValueError):
        return str(port or "?")


def _name(ip):
    n = profile.name_for_ip(ip)
    if n == ip:                         # unknown to the profile — try the managed overlay
        return inventory.name_for_ip(ip) or n
    return n


def _domain(ip):
    a = profile.asset_for_ip(ip)
    if a:
        return a.get("domain", "external")
    return inventory.domain_for_ip(ip) or "external"


def overview(log_dir: str | None = None) -> dict:
    logs = load_logs(log_dir or config.LOG_DIR)
    conn = logs.get("conn", [])
    return {
        "protocols": _protocols(logs),
        "conversations": _conversations(conn),
        "edges": _edges(conn),
        "dns": _dns(logs.get("dns", [])),
        "tls": _tls(logs.get("ssl", [])),
        "ssh": _ssh(logs.get("ssh", [])),
        "ot": _ot(logs),
        "totals": _totals(logs),
    }


def _protocols(logs) -> list[dict]:
    out = []
    for key, label, layer in _PROTOCOLS:
        out.append({"key": key, "label": label, "layer": layer, "count": len(logs.get(key, []))})
    return out


def _totals(logs) -> dict:
    conn = logs.get("conn", [])
    nbytes = sum((r.get("orig_ip_bytes") or 0) + (r.get("resp_ip_bytes") or 0) for r in conn)
    ot_ops = len(logs.get("s7comm", [])) + len(logs.get("opcua_binary", []))
    return {
        "connections": len(conn), "bytes": nbytes,
        "dns_queries": len(logs.get("dns", [])), "tls_sessions": len(logs.get("ssl", [])),
        "ssh_sessions": len(logs.get("ssh", [])), "ot_ops": ot_ops,
        "hosts": len({r.get("id.orig_h") for r in conn} | {r.get("id.resp_h") for r in conn}),
    }


def _conversations(conn) -> list[dict]:
    """Top src→dst:port conversations by volume, with OT authorization flagged."""
    agg = defaultdict(lambda: {"conns": 0, "bytes": 0, "states": set()})
    for r in conn:
        src, dst, port, proto = r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p"), r.get("proto")
        k = (src, dst, port, proto)
        a = agg[k]
        a["conns"] += 1
        a["bytes"] += (r.get("orig_ip_bytes") or 0) + (r.get("resp_ip_bytes") or 0)
        if r.get("conn_state"):
            a["states"].add(r["conn_state"])
    rows = []
    for (src, dst, port, proto), a in agg.items():
        svc = _svc(port)
        authz = _OT_AUTHZ.get("s7comm" if svc == "s7comm" else "opcua_binary" if svc == "opcua" else "")
        anomalous = bool(authz) and not profile.is_authorized_client(authz, src)
        rows.append({
            "src": _name(src), "src_ip": src, "dst": _name(dst), "dst_ip": dst,
            "port": port, "service": svc, "proto": proto,
            "conns": a["conns"], "bytes": a["bytes"], "states": sorted(a["states"]),
            "anomalous": anomalous,
        })
    rows.sort(key=lambda x: x["bytes"], reverse=True)
    return rows[:40]


def _edges(conn) -> list[dict]:
    """Host→host edges for a communication graph (deduped, with anomaly flags)."""
    agg = defaultdict(lambda: {"conns": 0, "bytes": 0, "svcs": set()})
    for r in conn:
        src, dst, port = r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p")
        a = agg[(src, dst)]
        a["conns"] += 1
        a["bytes"] += (r.get("orig_ip_bytes") or 0) + (r.get("resp_ip_bytes") or 0)
        a["svcs"].add(_svc(port))
    out = []
    for (src, dst), a in agg.items():
        ot_svc = "s7comm" in a["svcs"] or "opcua" in a["svcs"]
        authz = profile.is_authorized_client("s7comm", src) or profile.is_authorized_client("opcua", src)
        out.append({
            "src": _name(src), "dst": _name(dst), "src_domain": _domain(src), "dst_domain": _domain(dst),
            "conns": a["conns"], "bytes": a["bytes"], "services": sorted(a["svcs"]),
            "anomalous": ot_svc and not authz,
        })
    out.sort(key=lambda x: x["bytes"], reverse=True)
    return out


def _dns(dns) -> list[dict]:
    agg = defaultdict(lambda: {"count": 0, "answers": set(), "qtype": ""})
    for r in dns:
        q = r.get("query") or "(none)"
        a = agg[q]
        a["count"] += 1
        a["qtype"] = r.get("qtype_name") or a["qtype"]
        for ans in (r.get("answers") or []):
            a["answers"].add(str(ans))
    rows = [{"query": q, "count": v["count"], "qtype": v["qtype"],
             "answers": sorted(v["answers"])[:4],
             "external": not (q.endswith(".local") or q == "(none)")}
            for q, v in agg.items()]
    rows.sort(key=lambda x: x["count"], reverse=True)
    return rows


def _tls(ssl) -> list[dict]:
    out = []
    for r in ssl:
        out.append({
            "src": _name(r.get("id.orig_h")), "dst": _name(r.get("id.resp_h")),
            "server_name": r.get("server_name") or "—", "version": r.get("version") or "—",
            "cipher": r.get("cipher") or "—", "established": bool(r.get("established")),
        })
    return out


def _ssh(ssh) -> list[dict]:
    out = []
    for r in ssh:
        dst_ip = r.get("id.resp_h")
        out.append({
            "src": _name(r.get("id.orig_h")), "src_ip": r.get("id.orig_h"),
            "dst": _name(dst_ip), "auth_attempts": r.get("auth_attempts"),
            "client": r.get("client") or "—", "server": r.get("server") or "—",
            "kex": r.get("kex_alg") or "—",
            # Inbound SSH to the ews from a non-authorized source is the foothold.
            "inbound_to_ews": _name(dst_ip) == "ews",
        })
    return out


def _ot(logs) -> dict:
    # S7comm function-code breakdown, with unauthorized writes flagged.
    s7_funcs = defaultdict(lambda: {"count": 0, "unauthorized": 0})
    for r in logs.get("s7comm", []):
        fn = r.get("function_name") or r.get("rosctr_name") or "?"
        src = r.get("id.orig_h") or r.get("source_h")
        f = s7_funcs[fn]
        f["count"] += 1
        if not profile.is_authorized_client("s7comm", src):
            f["unauthorized"] += 1
    s7 = [{"function": k, "count": v["count"], "unauthorized": v["unauthorized"]}
          for k, v in sorted(s7_funcs.items(), key=lambda kv: -kv[1]["count"])]
    # OPC UA message-type breakdown.
    opc = defaultdict(int)
    endpoints = set()
    for r in logs.get("opcua_binary", []):
        opc[r.get("msg_type") or "?"] += 1
        if r.get("endpoint_url"):
            endpoints.add(r["endpoint_url"])
    opcua = [{"msg_type": k, "count": v} for k, v in sorted(opc.items(), key=lambda kv: -kv[1])]
    return {"s7comm": s7, "opcua": opcua, "endpoints": sorted(endpoints)[:5],
            "cotp": len(logs.get("cotp", []))}
