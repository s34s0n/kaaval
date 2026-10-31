# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Response playbooks (SOAR-lite) — PROPOSALS, never automation.

A playbook is profile-bound, versioned YAML keyed on detection technique/rule. It
orders investigation steps and proposed actions. It does NOT execute and it does
NOT pre-authorize: this module imports neither `actions` nor any executor, so there
is no code path from a playbook to execution. Every action step is resolved against
the CODE-derived action catalog (gating.spec / gating.relevant_actions) and stamped
with the authoritative gate decision (gating.apply) at runtime — the YAML cannot set
`requires_human_approval`, cannot expand the catalog, and an unknown action id fails
CLOSED (available=False, gated). The frontend executes a resolved step only through
the EXISTING /api/actions/{name}/apply|approve endpoints, where the gate + RBAC +
audit already live.
"""

from __future__ import annotations

import os

import yaml

from . import config, gating, profile


def _slug() -> str:
    return os.path.splitext(os.path.basename(config.PROFILE_PATH))[0]


def _load_all() -> list[dict]:
    out = []
    d = config.PLAYBOOKS_DIR
    if not os.path.isdir(d):
        return out
    for fn in sorted(os.listdir(d)):
        if fn.endswith((".yaml", ".yml")):
            try:
                with open(os.path.join(d, fn)) as f:
                    doc = yaml.safe_load(f) or {}
                if doc.get("playbook"):
                    out.append(doc)
            except (OSError, yaml.YAMLError):
                pass
    return out


def _for_profile(doc: dict) -> bool:
    return (doc.get("playbook") or {}).get("profile") in (_slug(), "any", None)


def _meta(pb: dict) -> dict:
    return {"id": pb.get("id"), "name": pb.get("name"), "version": pb.get("version"),
            "profile": pb.get("profile"), "authority": pb.get("authority"),
            "description": pb.get("description"), "match": pb.get("match") or {}}


def list_playbooks() -> list[dict]:
    return [_meta(d["playbook"]) for d in _load_all() if _for_profile(d)]


def _find(pb_id: str) -> dict | None:
    for d in _load_all():
        if (d.get("playbook") or {}).get("id") == pb_id:
            return d
    return None


def _short(rule: str | None) -> str:
    """Normalize a rule id for matching: 'ot.unauthorized_s7_command' -> 'unauthorized_s7_command'."""
    return (rule or "").split(".")[-1]


def _bundle_keys(bundle: dict):
    incident = (bundle or {}).get("incident") or {}
    events = (bundle or {}).get("events") or []
    techs = set()
    for t in incident.get("techniques") or []:
        techs.add(t.get("id") if isinstance(t, dict) else t)
    for e in events:
        for t in (e.get("techniques") or []):
            techs.add(t.get("id") if isinstance(t, dict) else t)
    rules = {_short(e.get("rule")) for e in events}
    domains = set(incident.get("domains") or []) | {e.get("domain") for e in events}
    cross = bool(incident.get("cross_domain")) or len(domains & {"IT", "OT"}) > 1
    return techs, rules, domains, cross


def match(bundle: dict) -> list[str]:
    """Code-derived: which playbooks are RELEVANT to this incident (a suggestion set).
    Pure data over the incident's techniques/rules/domains — no LLM, no execution."""
    techs, rules, domains, cross = _bundle_keys(bundle)
    out = []
    for d in _load_all():
        if not _for_profile(d):
            continue
        m = d["playbook"].get("match") or {}
        hit = (m.get("always")
               or bool(set(m.get("techniques") or []) & techs)
               or bool({_short(r) for r in (m.get("rules") or [])} & rules)
               or (m.get("cross_domain") and cross)
               or (m.get("any_ot") and "OT" in domains))
        if hit:
            out.append(d["playbook"]["id"])
    return out


def resolve(pb_id: str, bundle: dict | None = None) -> dict | None:
    """Expand a playbook into ordered steps. Action steps are resolved against the
    code catalog and gate — the gate decision comes from gating.apply, never the YAML.
    Unknown / un-catalogued actions fail CLOSED."""
    d = _find(pb_id)
    if d is None:
        return None
    pb = d["playbook"]
    relevant = set(gating.relevant_actions(bundle or {}))
    steps = []
    for i, s in enumerate(d.get("steps", []), 1):
        if s.get("step") == "action":
            name = s.get("action")
            spec = gating.spec(name)
            if spec is None:
                # Fail CLOSED: a playbook cannot introduce an action the catalog lacks.
                steps.append({"order": i, "kind": "action", "action": name, "available": False,
                              "requires_human_approval": True, "endpoint": None,
                              "reason": f"'{name}' is not in this profile's action catalog — unavailable (fail-closed)."})
                continue
            applied = gating.apply([{"name": name, "rationale": s.get("why") or spec.get("rationale", "")}])[0]
            gated = applied["requires_human_approval"]
            steps.append({
                "order": i, "kind": "action", "action": name, "available": True,
                "title": applied.get("title"), "domain": applied.get("domain"),
                "requires_human_approval": gated, "gating_reason": applied.get("gating_reason", ""),
                "rationale": applied.get("rationale", ""),
                "relevant": name in relevant,
                # which EXISTING endpoint the human uses — not a new execution route
                "endpoint": "approve" if gated else "apply",
            })
        else:
            steps.append({"order": i, "kind": "investigate",
                          "title": s.get("title"), "detail": s.get("detail")})
    return {
        **_meta(pb), "steps": steps,
        "summary": {
            "investigate": sum(1 for s in steps if s["kind"] == "investigate"),
            "actions": sum(1 for s in steps if s["kind"] == "action"),
            "gated": sum(1 for s in steps if s["kind"] == "action" and s.get("requires_human_approval")),
            "unavailable": sum(1 for s in steps if s["kind"] == "action" and not s.get("available")),
        },
    }
