# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Event/Incident data model and Zeek-log helpers for the Kaaval backend."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict


@dataclass
class Event:
    id: str                       # stable rule-based id (one per rule per detection run)
    ts: float                     # earliest Zeek timestamp contributing to this event
    domain: str                   # "IT" or "OT"
    rule: str                     # detection rule name
    techniques: list              # [{"id","name"}]
    severity: str                 # info|low|medium|high|critical
    src: str                      # originating host (IP)
    dst: str                      # target "host:port"
    summary: str                  # plain-language one-liner
    evidence_count: int           # number of Zeek rows behind this event
    evidence: dict = field(default_factory=dict)  # representative sample

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Incident:
    id: str
    created: float
    first_seen: float
    last_seen: float
    severity: str
    pivot: str                    # the workstation IP the chain transits
    cross_domain: bool            # spans both IT and OT
    domains: list                 # ["IT","OT"]
    techniques: list              # union of [{"id","name"}]
    event_ids: list
    summary: str

    def to_dict(self) -> dict:
        return asdict(self)


def read_json_log(log_dir: str, name: str) -> list[dict]:
    """Read a newline-delimited-JSON Zeek log; tolerate a partial final line."""
    path = os.path.join(log_dir, name)
    rows: list[dict] = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # partial line being written, or non-JSON banner
    return rows


def load_logs(log_dir: str, since: float | None = None) -> dict[str, list[dict]]:
    """Load every log the detection rules use. When `since` is set, keep only rows
    newer than that timestamp — a FRESH window of telemetry gathered after a given
    moment (used to verify a threat actually stopped without re-scanning the
    historical logs that still contain the past attack)."""
    names = ["ssh.log", "ssl.log", "dns.log", "conn.log",
             "opcua_binary.log", "s7comm.log", "cotp.log"]
    out: dict[str, list[dict]] = {}
    for n in names:
        rows = read_json_log(log_dir, n)
        if since is not None:
            rows = [r for r in rows if (r.get("ts") or 0) > since]
        out[n.replace(".log", "")] = rows
    return out


# derive_ews_ip removed in D2 — authorization/pivot now come from the deployment
# profile (asset inventory), not from guessing the pivot IP out of the logs.
