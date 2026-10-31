# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Live Zeek log tailer — streams new JSON log lines for the Telemetry view.

Polls the interesting logs in ./logs for appended lines and yields normalized
records {log_type, ts, src, dst, parsed_fields, raw, flagged}. `flagged` marks
lines that contributed to (or would trip) a detection, so the UI can color them.
Backend-side: a bounded poll loop; UI handles virtualization (R3).
"""

from __future__ import annotations

import asyncio
import json
import os

from . import config, profile, rules_engine, rules_store

# Logs surfaced in the telemetry tail (the ones the SOC cares about).
TAILED = ["conn", "ssh", "ssl", "dns", "opcua_binary", "s7comm", "cotp"]

# Compact per-log field subset for the table columns; raw JSON on expand.
_COLS = {
    "conn": ["proto", "id.resp_p", "conn_state", "history", "duration"],
    "ssh": ["id.resp_p", "auth_attempts", "client"],
    "ssl": ["id.resp_p", "version", "server_name"],
    "dns": ["query", "qtype_name", "rcode_name"],
    "opcua_binary": ["id.resp_p", "msg_type", "endpoint_url"],
    "s7comm": ["rosctr_name", "function_name", "function_code"],
    "cotp": ["pdu_name"],
}


def _is_external(ip: str | None) -> bool:
    a = profile.asset_for_ip(ip)
    return a is None or a.get("domain") == "external"


def _flag_line(log_type: str, row: dict) -> bool:
    """Would this line contribute to a detection? Inventory-driven (no pivot IP)."""
    src = row.get("id.orig_h")
    # OT protocols from a source that isn't an authorized client.
    if log_type == "opcua_binary":
        return not profile.is_authorized_client("opcua", src)
    if log_type in ("s7comm", "cotp"):
        return not profile.is_authorized_client("s7comm", src)
    # Inbound SSH from a non-authorized client.
    if log_type == "ssh" and row.get("id.resp_p") == 22 \
            and not profile.is_authorized_client("ssh", src):
        return True
    # TLS/DNS to an external (non-inventory) host = possible C2.
    if log_type in ("ssl", "dns") and _is_external(row.get("id.resp_h")):
        return True
    # Any enabled single-row user rule on this log.
    for r in rules_store.active_user_rules():
        if r.get("log") == log_type and rules_engine._match(
                rules_engine._get(row, r["field"]), r["op"], r.get("value")):
            return True
    return False


def _normalize(log_type: str, row: dict) -> dict:
    src = row.get("id.orig_h")
    dst = (f"{row.get('id.resp_h')}:{row.get('id.resp_p')}"
           if row.get("id.resp_h") is not None else None)
    fields = {k: row.get(k) for k in _COLS.get(log_type, []) if row.get(k) is not None}
    return {
        "log_type": log_type,
        "ts": row.get("ts"),
        "uid": row.get("uid"),
        "src": src,
        "dst": dst,
        "parsed_fields": fields,
        "raw": row,
        "flagged": _flag_line(log_type, row),
    }


def recent(max_backlog: int = 200, per_log: int = 30) -> list[dict]:
    """Snapshot of the most recent records across the tailed logs (for the REST
    seed so the Telemetry view renders immediately, before the first WS frame)."""
    seeded: list[dict] = []
    for lt in TAILED:
        path = os.path.join(config.LOG_DIR, f"{lt}.log")
        if not os.path.exists(path):
            continue
        with open(path) as f:
            lines = f.readlines()
        for line in lines[-per_log:]:
            rec = _safe(lt, line)
            if rec:
                seeded.append(rec)
    seeded.sort(key=lambda r: r.get("ts") or 0)
    return seeded[-max_backlog:]


async def tail(stop: asyncio.Event, max_backlog: int = 200):
    """Async generator of new log records. On connect, emits a small recent
    backlog from each tailed log, then streams appended lines."""
    paths = {lt: os.path.join(config.LOG_DIR, f"{lt}.log") for lt in TAILED}
    offsets: dict[str, int] = {}
    for lt, path in paths.items():
        offsets[lt] = os.path.getsize(path) if os.path.exists(path) else 0

    for rec in recent(max_backlog):           # seed from existing logs
        yield rec

    while not stop.is_set():
        for lt, path in paths.items():
            if not os.path.exists(path):
                continue
            size = os.path.getsize(path)
            if size < offsets.get(lt, 0):       # file rotated/truncated
                offsets[lt] = 0
            if size > offsets.get(lt, 0):
                with open(path) as f:
                    f.seek(offsets[lt])
                    new = f.readlines()
                    offsets[lt] = f.tell()
                for line in new:
                    rec = _safe(lt, line)
                    if rec:
                        yield rec
        await asyncio.sleep(0.5)


def _safe(log_type: str, line: str):
    line = line.strip()
    if not line:
        return None
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        return None
    return _normalize(log_type, row)
