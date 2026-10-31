# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""SQLite persistence for Kaaval events and incidents (stdlib only)."""

from __future__ import annotations

import json
import sqlite3

from . import config


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    # WAL: readers see a consistent committed snapshot and never block the writer,
    # so a concurrent reader can no longer observe a half-rebuilt detection store.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, ts REAL, domain TEXT, rule TEXT,
            techniques TEXT, severity TEXT, src TEXT, dst TEXT,
            summary TEXT, evidence_count INTEGER, evidence TEXT
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY, created REAL, first_seen REAL, last_seen REAL,
            severity TEXT, pivot TEXT, cross_domain INTEGER, domains TEXT,
            techniques TEXT, event_ids TEXT, summary TEXT
        );
        -- Persisted SOC case state (agent triage, action/gate status, timestamps),
        -- so a backend restart does not erase the analyst's work-in-progress.
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, detect_ts REAL, contain_ts REAL, remediated_ts REAL,
            agents_done INTEGER, agents_event_count INTEGER,
            agents TEXT, actions TEXT, last_response TEXT, resolution TEXT,
            rogue_devices TEXT
        );
        -- Immutable approval/decision audit log: who approved which control action,
        -- when, and why it was gated. Append-only; never cleared by detection.
        CREATE TABLE IF NOT EXISTS approvals (
            ts REAL, approver TEXT, action TEXT, incident_id TEXT, decision TEXT,
            gated INTEGER, rationale TEXT, gating_reason TEXT, result_ok INTEGER
        );
        -- Immutable cloud-egress audit: every outbound LLM call (no payload), so
        -- "what left the box" is provable. Same durability as approvals.
        CREATE TABLE IF NOT EXISTS egress_log (
            ts REAL, provider TEXT, model TEXT, bytes INTEGER, incident_id TEXT,
            principal TEXT, purpose TEXT, ok INTEGER
        );
        -- Separate audit channel for the autonomy auto-containment POLICY: reversible
        -- IT actions executed without per-action approval. Distinct from approvals so
        -- the human-approved record is never conflated with automated policy actions.
        CREATE TABLE IF NOT EXISTS auto_actions (
            ts REAL, action TEXT, incident_id TEXT, policy TEXT, enabled_by TEXT, result_ok INTEGER
        );
        -- Discovery baseline: hosts and (src,dst,proto) pairs ever observed, with the
        -- first-seen timestamp. Drives first-seen / rogue alerting.
        CREATE TABLE IF NOT EXISTS seen_hosts (ip TEXT PRIMARY KEY, first_seen REAL, managed INTEGER);
        CREATE TABLE IF NOT EXISTS seen_pairs (pair TEXT PRIMARY KEY, first_seen REAL);
        CREATE TABLE IF NOT EXISTS discovery_meta (k TEXT PRIMARY KEY, v TEXT);
        -- CVE enrichment cache, keyed on CPE only (no asset identity). Avoids
        -- re-querying NVD for the same CPE and lets the demo run without live NVD.
        CREATE TABLE IF NOT EXISTS cve_cache (
            cpe TEXT PRIMARY KEY, fetched_ts REAL, source TEXT, data TEXT
        );
        -- SIEM forwarding audit: what we emitted to the customer's SIEM (internal,
        -- on-prem destination), the transport used, and whether it was delivered.
        CREATE TABLE IF NOT EXISTS siem_log (
            ts REAL, kind TEXT, signature TEXT, incident_id TEXT,
            transport TEXT, ok INTEGER, detail TEXT
        );
        -- Case-management WORKFLOW state, parallel to the detection-derived status.
        -- Workflow only — never touches the gate or any action.
        CREATE TABLE IF NOT EXISTS case_meta (
            incident_id TEXT PRIMARY KEY, assignee TEXT, state TEXT, state_reason TEXT,
            disposition TEXT, closed_by TEXT, closed_ts REAL,
            report_md TEXT, report_status TEXT, report_by TEXT, report_ts REAL, updated_ts REAL
        );
        -- Case history = chain-of-custody audit trail. Append-only: every case
        -- mutation (assign/comment/transition/close/reopen/report) by the VERIFIED
        -- principal, timestamped. A government reviewer reads who did what, when, why.
        CREATE TABLE IF NOT EXISTS case_history (
            ts REAL, incident_id TEXT, actor TEXT, role TEXT, kind TEXT, detail TEXT
        );
        """
    )
    # Lightweight migration for DBs created before a column was added.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(cases)").fetchall()}
    if "rogue_devices" not in cols:
        conn.execute("ALTER TABLE cases ADD COLUMN rogue_devices TEXT")
    conn.commit()


def replace_all(conn: sqlite3.Connection, events, incidents) -> None:
    """Atomically swap the detection snapshot in ONE transaction: a concurrent
    reader sees either the entire previous snapshot or the entire new one, never an
    empty/half-rebuilt store. Replaces the old DELETE-then-INSERT-with-many-commits
    path that raced readers every 2s."""
    with conn:                                   # single transaction, single commit
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM incidents")
        conn.executemany(
            "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [(e.id, e.ts, e.domain, e.rule, json.dumps(e.techniques), e.severity,
              e.src, e.dst, e.summary, e.evidence_count, json.dumps(e.evidence))
             for e in events],
        )
        conn.executemany(
            "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [(inc.id, inc.created, inc.first_seen, inc.last_seen, inc.severity,
              inc.pivot, int(inc.cross_domain), json.dumps(inc.domains),
              json.dumps(inc.techniques), json.dumps(inc.event_ids), inc.summary)
             for inc in incidents],
        )


def get_events(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM events ORDER BY ts").fetchall()
    return [_event_row(r) for r in rows]


def get_incidents(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM incidents ORDER BY created").fetchall()
    return [_incident_row(r) for r in rows]


def _event_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["techniques"] = json.loads(d["techniques"])
    d["evidence"] = json.loads(d["evidence"])
    return d


def _incident_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["cross_domain"] = bool(d["cross_domain"])
    for k in ("domains", "techniques", "event_ids"):
        d[k] = json.loads(d[k])
    return d


# --- persisted SOC case state (survives restart) ----------------------------

def save_case(conn: sqlite3.Connection, c: dict) -> None:
    """Upsert one case's analyst-facing state. `c` is the Case.persist_dict()."""
    conn.execute(
        "INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (c["id"], c.get("detect_ts"), c.get("contain_ts"), c.get("remediated_ts"),
         int(bool(c.get("agents_done"))), c.get("agents_event_count") or 0,
         json.dumps(c.get("agents")), json.dumps(c.get("actions") or []),
         json.dumps(c.get("last_response")), json.dumps(c.get("resolution")),
         json.dumps(c.get("rogue_devices") or [])),
    )
    conn.commit()


def clear_cases(conn: sqlite3.Connection) -> None:
    """Drop persisted case state (e.g. on demo reset). The approvals audit log is
    intentionally left intact — it is an immutable record, not work-in-progress."""
    conn.execute("DELETE FROM cases")
    conn.commit()


def load_cases(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM cases").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["agents_done"] = bool(d["agents_done"])
        for k in ("agents", "actions", "last_response", "resolution", "rogue_devices"):
            d[k] = json.loads(d[k]) if d.get(k) is not None else None
        d["actions"] = d["actions"] or []
        d["rogue_devices"] = d["rogue_devices"] or []
        out.append(d)
    return out


# --- immutable approval/decision audit log ----------------------------------

def add_approval(conn: sqlite3.Connection, *, ts: float, approver: str, action: str,
                 incident_id: str, decision: str, gated: bool, rationale: str,
                 gating_reason: str, result_ok: bool) -> None:
    conn.execute(
        "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?)",
        (ts, approver, action, incident_id, decision, int(bool(gated)),
         rationale, gating_reason, int(bool(result_ok))),
    )
    conn.commit()


def get_approvals(conn: sqlite3.Connection, incident_id: str | None = None) -> list[dict]:
    if incident_id:
        rows = conn.execute(
            "SELECT * FROM approvals WHERE incident_id=? ORDER BY ts DESC", (incident_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM approvals ORDER BY ts DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["gated"] = bool(d["gated"])
        d["result_ok"] = bool(d["result_ok"])
        out.append(d)
    return out


# --- cloud egress audit -----------------------------------------------------

def add_egress(conn, *, ts, provider, model, bytes, incident_id, principal, purpose, ok):
    conn.execute("INSERT INTO egress_log VALUES (?,?,?,?,?,?,?,?)",
                 (ts, provider, model, int(bytes or 0), incident_id, principal, purpose, int(bool(ok))))
    conn.commit()


def get_egress(conn, limit: int = 200) -> list[dict]:
    rows = conn.execute("SELECT * FROM egress_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) | {"ok": bool(dict(r)["ok"])} for r in rows]


# --- autonomy auto-action audit (separate channel) --------------------------

def add_auto_action(conn, *, ts, action, incident_id, policy, enabled_by, result_ok):
    conn.execute("INSERT INTO auto_actions VALUES (?,?,?,?,?,?)",
                 (ts, action, incident_id, policy, enabled_by, int(bool(result_ok))))
    conn.commit()


def get_auto_actions(conn, limit: int = 200) -> list[dict]:
    rows = conn.execute("SELECT * FROM auto_actions ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) | {"result_ok": bool(dict(r)["result_ok"])} for r in rows]


# --- CVE enrichment cache (keyed on CPE only) -------------------------------

def get_cve_cache(conn, cpe: str) -> dict | None:
    r = conn.execute("SELECT * FROM cve_cache WHERE cpe=?", (cpe,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["data"] = json.loads(d["data"])
    return d


def set_cve_cache(conn, *, cpe: str, source: str, data, ts: float) -> None:
    conn.execute("INSERT OR REPLACE INTO cve_cache VALUES (?,?,?,?)",
                 (cpe, ts, source, json.dumps(data)))
    conn.commit()


def clear_cve_cache(conn) -> None:
    conn.execute("DELETE FROM cve_cache")
    conn.commit()


# --- SIEM forwarding audit ---------------------------------------------------

def add_siem_log(conn, *, ts, kind, signature, incident_id, transport, ok, detail) -> None:
    conn.execute("INSERT INTO siem_log VALUES (?,?,?,?,?,?,?)",
                 (ts, kind, signature, incident_id or "", transport, int(bool(ok)), detail))
    conn.commit()


def get_siem_log(conn, limit: int = 200) -> list[dict]:
    rows = conn.execute("SELECT * FROM siem_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) | {"ok": bool(dict(r)["ok"])} for r in rows]


# --- case management: workflow state + chain-of-custody history --------------

_CASE_META_COLS = ("incident_id", "assignee", "state", "state_reason", "disposition",
                   "closed_by", "closed_ts", "report_md", "report_status", "report_by",
                   "report_ts", "updated_ts")


def get_case_meta(conn, incident_id: str) -> dict | None:
    r = conn.execute("SELECT * FROM case_meta WHERE incident_id=?", (incident_id,)).fetchone()
    return dict(r) if r else None


def upsert_case_meta(conn, incident_id: str, patch: dict, *, ts: float) -> dict:
    cur = get_case_meta(conn, incident_id) or {c: None for c in _CASE_META_COLS}
    cur["incident_id"] = incident_id
    for k, v in patch.items():
        if k in _CASE_META_COLS:
            cur[k] = v
    cur["updated_ts"] = ts
    conn.execute(
        "INSERT OR REPLACE INTO case_meta VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        tuple(cur.get(c) for c in _CASE_META_COLS))
    conn.commit()
    return cur


def add_case_history(conn, *, ts, incident_id, actor, role, kind, detail) -> None:
    conn.execute("INSERT INTO case_history VALUES (?,?,?,?,?,?)",
                 (ts, incident_id, actor, role, kind, detail))
    conn.commit()


def get_case_history(conn, incident_id: str) -> list[dict]:
    rows = conn.execute("SELECT * FROM case_history WHERE incident_id=? ORDER BY ts", (incident_id,)).fetchall()
    return [dict(r) for r in rows]


# --- discovery baseline (seen-set) ------------------------------------------

def get_seen_hosts(conn) -> dict:
    return {r["ip"]: {"first_seen": r["first_seen"], "managed": bool(r["managed"])}
            for r in conn.execute("SELECT * FROM seen_hosts").fetchall()}


def get_seen_pairs(conn) -> set:
    return {r["pair"] for r in conn.execute("SELECT pair FROM seen_pairs").fetchall()}


def add_seen_hosts(conn, items: list[tuple]) -> None:  # (ip, first_seen, managed)
    conn.executemany("INSERT OR IGNORE INTO seen_hosts VALUES (?,?,?)",
                     [(ip, ts, int(bool(m))) for ip, ts, m in items])
    conn.commit()


def add_seen_pairs(conn, items: list[tuple]) -> None:  # (pair, first_seen)
    conn.executemany("INSERT OR IGNORE INTO seen_pairs VALUES (?,?)", items)
    conn.commit()


def meta_get(conn, k: str):
    r = conn.execute("SELECT v FROM discovery_meta WHERE k=?", (k,)).fetchone()
    return r["v"] if r else None


def meta_set(conn, k: str, v: str) -> None:
    conn.execute("INSERT OR REPLACE INTO discovery_meta VALUES (?,?)", (k, v))
    conn.commit()


def clear_discovery_baseline(conn) -> None:
    conn.executescript("DELETE FROM seen_hosts; DELETE FROM seen_pairs; DELETE FROM discovery_meta;")
    conn.commit()
