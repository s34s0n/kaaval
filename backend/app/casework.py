# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Case management — WORKFLOW STATE over existing incidents (F7).

This is a parallel layer next to the detection-derived `Case.status()`: assignment,
threaded comments, manual state transitions (with a logged reason), close/reopen, and
a per-case report draft/sign-off. EVERY mutation is recorded to `case_history` against
the VERIFIED principal (same identity discipline as approvals) — the history IS a
chain-of-custody audit trail.

It is workflow only. This module imports neither `actions` nor `gating`; there is no
route from any case operation to execution. Closing a case changes a state row, never
the plant. (Invariant 1.)
"""

from __future__ import annotations

import time

from . import store

# Operator-facing workflow states. `closed` is reached only via close().
WORKFLOW_STATES = ("open", "investigating", "contained", "resolved", "closed")
_DERIVED_TO_WORKFLOW = {"open": "open", "triaged": "investigating", "contained": "contained",
                        "remediating": "contained", "resolved": "resolved"}
DISPOSITIONS = ("true_positive_remediated", "true_positive_unresolved",
                "false_positive", "benign", "duplicate")


def _who(principal: dict) -> tuple[str, str]:
    return (principal or {}).get("name") or "unknown", (principal or {}).get("role") or "viewer"


def _conn():
    conn = store.connect(); store.init(conn); return conn


def default_state(derived_status: str | None) -> str:
    return _DERIVED_TO_WORKFLOW.get(derived_status or "", "open")


def get(incident_id: str, derived_status: str | None = None) -> dict:
    conn = _conn()
    meta = store.get_case_meta(conn, incident_id) or {}
    history = store.get_case_history(conn, incident_id)
    conn.close()
    return {
        "incident_id": incident_id,
        "assignee": meta.get("assignee"),
        "state": meta.get("state") or default_state(derived_status),
        "state_overridden": bool(meta.get("state")),
        "state_reason": meta.get("state_reason"),
        "disposition": meta.get("disposition"),
        "closed_by": meta.get("closed_by"), "closed_ts": meta.get("closed_ts"),
        "report_status": meta.get("report_status"), "report_by": meta.get("report_by"),
        "report_ts": meta.get("report_ts"),
        "history": history,
    }


def _log(conn, incident_id, principal, kind, detail, ts):
    actor, role = _who(principal)
    store.add_case_history(conn, ts=ts, incident_id=incident_id, actor=actor, role=role,
                           kind=kind, detail=detail)


def assign(incident_id: str, principal: dict, assignee: str) -> dict:
    conn = _conn(); ts = time.time()
    store.upsert_case_meta(conn, incident_id, {"assignee": assignee}, ts=ts)
    _log(conn, incident_id, principal, "assign", f"assigned to {assignee}", ts)
    conn.close()
    return get(incident_id)


def comment(incident_id: str, principal: dict, text: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("empty comment")
    conn = _conn(); ts = time.time()
    store.upsert_case_meta(conn, incident_id, {}, ts=ts)            # touch updated_ts
    _log(conn, incident_id, principal, "comment", text, ts)
    conn.close()
    return get(incident_id)


def transition(incident_id: str, principal: dict, state: str, reason: str | None) -> dict:
    if state not in WORKFLOW_STATES or state == "closed":
        raise ValueError("invalid transition state (use close() to close)")
    conn = _conn(); ts = time.time()
    store.upsert_case_meta(conn, incident_id, {"state": state, "state_reason": reason or ""}, ts=ts)
    _log(conn, incident_id, principal, "transition",
         f"state → {state}" + (f" · {reason}" if reason else ""), ts)
    conn.close()
    return get(incident_id)


def close(incident_id: str, principal: dict, disposition: str, reason: str | None) -> dict:
    actor, _ = _who(principal)
    conn = _conn(); ts = time.time()
    store.upsert_case_meta(conn, incident_id, {"state": "closed", "disposition": disposition,
                           "state_reason": reason or "", "closed_by": actor, "closed_ts": ts}, ts=ts)
    _log(conn, incident_id, principal, "close",
         f"closed [{disposition}]" + (f" · {reason}" if reason else ""), ts)
    conn.close()
    return get(incident_id)


def reopen(incident_id: str, principal: dict, reason: str | None) -> dict:
    conn = _conn(); ts = time.time()
    store.upsert_case_meta(conn, incident_id, {"state": "investigating", "disposition": None,
                           "closed_by": None, "closed_ts": None, "state_reason": reason or ""}, ts=ts)
    _log(conn, incident_id, principal, "reopen", f"reopened" + (f" · {reason}" if reason else ""), ts)
    conn.close()
    return get(incident_id)


# --- per-case report draft / sign-off (state only; prose lives in case_report) ---

def save_report(incident_id: str, principal: dict, markdown: str, *, ai_drafted: bool) -> dict:
    conn = _conn(); ts = time.time()
    store.upsert_case_meta(conn, incident_id, {"report_md": markdown, "report_status": "draft"}, ts=ts)
    _log(conn, incident_id, principal, "report",
         "AI-drafted incident report" if ai_drafted else "edited incident report draft", ts)
    conn.close()
    return get(incident_id)


def signoff_report(incident_id: str, principal: dict) -> dict:
    actor, _ = _who(principal)
    conn = _conn()
    meta = store.get_case_meta(conn, incident_id) or {}
    if not meta.get("report_md"):
        conn.close()
        raise ValueError("no report draft to sign off")
    ts = time.time()
    store.upsert_case_meta(conn, incident_id, {"report_status": "final", "report_by": actor, "report_ts": ts}, ts=ts)
    _log(conn, incident_id, principal, "report", "signed off incident report (final)", ts)
    conn.close()
    return get(incident_id)


def get_report(incident_id: str) -> dict:
    conn = _conn()
    meta = store.get_case_meta(conn, incident_id) or {}
    conn.close()
    return {"markdown": meta.get("report_md"), "status": meta.get("report_status"),
            "by": meta.get("report_by"), "ts": meta.get("report_ts")}
