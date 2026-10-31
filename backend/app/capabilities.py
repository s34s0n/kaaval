# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Sensor capabilities — which Zeek analyzers / ICSNPP parsers are active, the
logs they produce, and their key fields. Filtered to the logs actually present
in ./logs. Doubles as the field palette for building rules (Detections view).
"""

from __future__ import annotations

import glob
import os

from . import config

# Curated analyzer catalog. key fields are the useful ones for rules/telemetry.
CATALOG = [
    {"analyzer": "Conn", "kind": "native", "logs": ["conn"],
     "fields": ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
                "conn_state", "history", "duration", "orig_bytes", "resp_bytes"]},
    {"analyzer": "DNS", "kind": "native", "logs": ["dns"],
     "fields": ["ts", "id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name", "answers"]},
    {"analyzer": "SSL/TLS", "kind": "native", "logs": ["ssl"],
     "fields": ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "version", "cipher",
                "server_name", "established"]},
    {"analyzer": "SSH", "kind": "native", "logs": ["ssh"],
     "fields": ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "auth_success",
                "auth_attempts", "client", "server"]},
    {"analyzer": "ICSNPP::OPCUA_Binary", "kind": "icsnpp", "logs": ["opcua_binary"],
     "fields": ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "msg_type", "endpoint_url"]},
    {"analyzer": "ICSNPP::S7COMM", "kind": "icsnpp", "logs": ["s7comm", "cotp"],
     "fields": ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "rosctr_name",
                "function_code", "function_name", "source_h", "destination_h"]},
]


def present_logs() -> set[str]:
    found = set()
    for path in glob.glob(os.path.join(config.LOG_DIR, "*.log")):
        name = os.path.basename(path)[:-4]            # strip .log
        # opcua produces many sub-logs; collapse to the base "opcua_binary"
        if name.startswith("opcua_binary"):
            found.add("opcua_binary")
        else:
            found.add(name)
    return found


def capabilities() -> dict:
    have = present_logs()
    analyzers = []
    for a in CATALOG:
        active = any(l in have for l in a["logs"])
        analyzers.append({**a, "active": active})
    return {
        "log_dir": config.LOG_DIR,
        "logs_present": sorted(have),
        "analyzers": analyzers,
        # flat palette for the rule builder: log -> fields
        "field_palette": {a["logs"][0]: a["fields"] for a in CATALOG},
    }
