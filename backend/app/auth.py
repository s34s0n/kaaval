# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Authentication + RBAC — mandatory, fail-closed, verified identity.

Bearer tokens map to a principal {name, role}. Roles ascend:
    viewer < operator < approver < admin
  - viewer   : read-only (all GETs).
  - operator : investigate, apply reversible IT actions, author rules, manage assets.
  - approver : + APPROVE gated OT control actions. Separation of duties — an
               operator-only principal cannot approve; a distinct approver/admin must.
  - admin    : + provider/key switch, autonomy policy, reset, range/attack, net config.

Fail-closed: outside DEV_MODE a mutating request with no valid token is rejected
(401). The resolved principal is threaded into the audit log, so approvals record a
VERIFIED identity, never a client-supplied string.
"""

from __future__ import annotations

import json

from . import config

ROLES = {"viewer": 0, "operator": 1, "approver": 2, "admin": 3}


def rank(role: str) -> int:
    return ROLES.get(role, -1)


def _load_tokens() -> dict:
    """token -> {name, role}. From inline env JSON, a file, and the legacy token."""
    toks: dict = {}
    if config.AUTH_TOKENS_ENV:
        try:
            toks.update(json.loads(config.AUTH_TOKENS_ENV))
        except (json.JSONDecodeError, TypeError):
            pass
    try:
        with open(config.AUTH_TOKENS_PATH) as f:
            toks.update(json.load(f))
    except (OSError, json.JSONDecodeError):
        pass
    if config.AUTH_TOKEN:
        toks.setdefault(config.AUTH_TOKEN, {"name": "admin", "role": "admin"})
    # Demo users are seeded ONLY when nothing else was provisioned, so a real
    # deployment that sets its own tokens is never polluted with demo credentials.
    if config.SEED_DEMO_USERS and not toks:
        toks.update(config.DEMO_TOKENS)
    return toks


def principal_for_token(token: str | None) -> dict | None:
    if not token:
        return None
    rec = _load_tokens().get(token)
    if not isinstance(rec, dict):
        return None
    role = rec.get("role", "viewer")
    if role not in ROLES:
        role = "viewer"
    return {"name": str(rec.get("name", "user")), "role": role}


def authenticate(request) -> dict | None:
    """Resolve the principal from the Authorization header, or None.
    In DEV_MODE with NO tokens provisioned, an un-tokened caller is a local admin."""
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    p = principal_for_token(token)
    if p:
        return p
    if config.DEV_MODE and not _load_tokens():
        return {"name": "dev", "role": "admin", "dev": True}
    return None


def authorized(principal: dict | None, need_role: str) -> bool:
    return principal is not None and rank(principal["role"]) >= rank(need_role)


def required_role(method: str, path: str) -> str:
    """Minimum role for a request. GETs are viewer; mutations escalate by path."""
    if method in ("GET", "HEAD", "OPTIONS"):
        return "viewer"
    # Admin-only: anything that changes the model/egress posture, the plant, or runs
    # the lab attack affordance.
    if (path.startswith("/api/llm") or path == "/api/autonomy" or path == "/api/reset"
            or path.startswith("/api/attack") or path.startswith("/api/range")
            or path.startswith("/api/siem")           # SIEM egress posture (configure/test/forward)
            or path == "/api/inventory/network"):
        return "admin"
    # Approving a gated OT control action requires the approver role (SoD).
    if path.startswith("/api/actions/") and path.endswith("/approve"):
        return "approver"
    # Case management: closing/reopening a case and signing off its report are
    # accountable decisions -> approver. Working a case (assign/comment/transition/
    # draft+edit report) is operator. (Workflow only; never touches the gate.)
    if path.startswith("/api/cases/") and (path.endswith("/close") or path.endswith("/reopen")
                                           or path.endswith("/report/signoff")):
        return "approver"
    # All other mutations (apply IT action, author rules, manage inventory, chat,
    # verify) require at least operator.
    return "operator"
