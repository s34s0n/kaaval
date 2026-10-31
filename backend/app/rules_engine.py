# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Generic evaluator for user-defined detection rules.

Each active user rule (from rules_store) matches rows in one Zeek log by a
{field, op, value} condition; if at least `min_count` rows match (default 1) it
emits one aggregated Event that flows into the same correlation as the built-in
detections. Field lookup is dotted-key aware (e.g. "id.orig_h") and the Zeek
JSON already uses flat dotted keys, so a direct dict lookup works.
"""

from __future__ import annotations

from collections import defaultdict

from . import config, profile, rules_store
from .model import Event

_TECH_NAMES = {
    "T0822": "External Remote Services", "T0869": "Standard Application Layer Protocol",
    "T0846": "Remote System Discovery", "T0888": "Remote System Information Discovery",
    "T0855": "Unauthorized Command Message", "T0836": "Modify Parameter",
    "T0831": "Manipulation of Control",
}


def _get(row: dict, field: str):
    if field in row:
        return row[field]
    # fall back to nested lookup for dotted paths not stored flat
    cur = row
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match(value, op: str, target) -> bool:
    if op == "exists":
        return value is not None
    if value is None:
        return False
    try:
        if op == "eq":
            return str(value) == str(target)
        if op == "ne":
            return str(value) != str(target)
        if op == "contains":
            return str(target).lower() in str(value).lower()
        if op in ("gt", "ge", "lt", "le"):
            v, t = float(value), float(target)
            return {"gt": v > t, "ge": v >= t, "lt": v < t, "le": v <= t}[op]
    except (ValueError, TypeError):
        return False
    return False


def _is_external(ip) -> bool:
    a = profile.asset_for_ip(ip)
    return a is None or a.get("domain") == "external"


def _where(rule: dict) -> list:
    """Generic predicates; `field/op/value` is shorthand for one predicate."""
    w = list(rule.get("where") or [])
    if rule.get("field"):
        w.append({"field": rule["field"], "op": rule.get("op", "exists"), "value": rule.get("value")})
    return w


def _rows(logs: dict, rule: dict) -> list:
    names = rule.get("logs") or ([rule["log"]] if rule.get("log") else [])
    out = []
    for n in names:
        out += logs.get(n, [])
    return out


def _where_ok(row: dict, where: list) -> bool:
    return all(_match(_get(row, c["field"]), c["op"], c.get("value")) for c in where)


def _metric(rs, agg, distinct_on):
    if agg == "distinct":
        return len({tuple(_get(r, f) for f in distinct_on) for r in rs})
    return len(rs)


def _bursts(rows: list) -> list[list]:
    """Split a source's matching rows into time-separated BURSTS (a gap larger than
    the correlation window starts a new burst). Each burst is a distinct occurrence,
    so a repeat of the same activity later becomes its OWN event/incident rather than
    folding into the first occurrence forever."""
    rs = sorted(rows, key=lambda r: r.get("ts", 0))
    if not rs:
        return []
    out = [[rs[0]]]
    for r in rs[1:]:
        if r.get("ts", 0) - out[-1][-1].get("ts", 0) <= config.CORRELATION_WINDOW_S:
            out[-1].append(r)
        else:
            out.append([r])
    return out


def _build_event(rule: dict, g, rs: list) -> Event:
    """Build one Event from a single burst `rs` of a source `g`."""
    agg = rule.get("aggregate", "count")
    distinct_on = rule.get("distinct_on", ["id.resp_h", "id.resp_p"])
    n = _metric(rs, agg, distinct_on)
    first = min(rs, key=lambda r: r.get("ts", 0))

    severity = rule["severity"]
    techs = list(rule.get("attack", []))
    esc = rule.get("escalate")
    if esc:
        hit = any(_where_ok(r, esc.get("where") or []) for r in rs)
        wp = esc.get("write_proto")
        if hit and (not wp or not profile.allow_write(wp)):
            severity = esc.get("severity", severity)
            techs += [t for t in esc.get("add_attack", []) if t not in techs]

    src_name = profile.name_for_ip(g)
    dst_name = profile.name_for_ip(first.get("id.resp_h"))
    dst = f"{dst_name}:{first.get('id.resp_p')}" if first.get("id.resp_p") is not None else dst_name

    evidence = {"rule_id": rule["id"], "count": n, "src_ip": g, "builtin": bool(rule.get("logs"))}
    funcs = sorted({r.get("function_name") for r in rs if r.get("function_name")})
    if funcs:
        evidence["functions"] = funcs
        evidence["write"] = any("write" in (f or "").lower() for f in funcs)
    if agg == "distinct":
        evidence["targets"] = sorted({f"{profile.name_for_ip(r.get('id.resp_h'))}:{r.get('id.resp_p')}" for r in rs})[:20]
    queries = sorted({r.get("query") for r in rs if r.get("query")})
    if queries:
        evidence["queries"] = queries[:3]

    summary = (rule.get("summary") or rule.get("description") or rule.get("condition") or rule["id"])
    summary = summary.replace("{src}", src_name).replace("{dst}", dst_name).replace("{n}", str(n))

    # Burst-unique, stable id: a later burst of the same rule is a distinct event.
    ts = first.get("ts", 0)
    return Event(
        id=f"{rule['id']}#{int(ts)}", ts=ts, domain=rule.get("domain", "IT"),
        rule=rule.get("rule") or rule.get("name") or rule["id"],
        techniques=[{"id": t, "name": _TECH_NAMES.get(t, t)} for t in techs],
        severity=severity, src=src_name, dst=dst,
        summary=summary, evidence_count=n, evidence=evidence,
    )


def _eval_rule(logs: dict, rule: dict) -> list[Event]:
    where = _where(rule)
    proto = rule.get("unauthorized")
    ext = rule.get("external_dst")

    def keep(r):
        if where and not _where_ok(r, where):
            return False
        if proto and profile.is_authorized_client(proto, r.get("id.orig_h")):
            return False  # source IS an allowed client -> authorized, not flagged
        if ext and not _is_external(r.get("id.resp_h")):
            return False
        return True

    matched = [r for r in _rows(logs, rule) if keep(r)]
    if not matched:
        return []

    group_by = rule.get("group_by", "id.orig_h")
    groups: dict = defaultdict(list)
    for r in matched:
        groups[_get(r, group_by)].append(r)

    agg = rule.get("aggregate", "count")
    distinct_on = rule.get("distinct_on", ["id.resp_h", "id.resp_p"])
    min_count = int(rule.get("min_count", 1))

    # Pick the top source overall, then emit one event PER BURST it meets the
    # threshold in (so repeated activity over time -> multiple incidents).
    qualifying = [(g, rs) for g, rs in groups.items()
                  if _metric(rs, agg, distinct_on) >= min_count]
    if not qualifying:
        return []
    g, rs = max(qualifying, key=lambda kv: _metric(kv[1], agg, distinct_on))
    return [_build_event(rule, g, burst) for burst in _bursts(rs)
            if _metric(burst, agg, distinct_on) >= min_count]


def evaluate(logs: dict) -> list[Event]:
    """Run every enabled rule (built-in + user) through one generic engine."""
    events: list[Event] = []
    for rule in rules_store.active_rules():
        try:
            evs = _eval_rule(logs, rule)
        except Exception:
            evs = []        # a malformed rule must never break detection
        events.extend(evs)
    return events
