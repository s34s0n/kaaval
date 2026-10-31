# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""OT-safety gating — the core product safety logic, enforced in code.

The Response agent *proposes* actions and explains why each is risky, but this
module is the authority that decides whether an action may auto-execute. The
decision is made from each action's ATTRIBUTES, never its name: an action that
changes OT control state, could affect the physical process, or is not reversible
must be held for human approval; only low-risk reversible IT-side actions auto-run.
The action catalog (with attributes + device targets) lives in the deployment
profile — this module reads it but the device targets are used only by the
executor. We never trust the model's own gating claim, and any unknown or
unattributed action defaults to GATED (fail-safe).
"""

from __future__ import annotations

from . import profile


# --- catalog access (sourced from the deployment profile) -------------------

def catalog() -> list[dict]:
    return profile.actions()


def spec(name: str) -> dict | None:
    return profile.action(name)


def names() -> list[str]:
    """Canonical, ordered action ids (the playbook the agents may choose from)."""
    return [a["id"] for a in catalog() if a.get("id")]


def ot_action_names() -> list[str]:
    return [a["id"] for a in catalog() if a.get("kind") == "ot"]


# --- the gate (attribute-based, fail-safe) ----------------------------------

def is_gated(attrs: dict | None) -> bool:
    """Gated if the action touches the control plane, could affect the physical
    process, or is not reversible. Missing/empty attributes ⇒ gated (fail-safe)."""
    if not attrs:
        return True
    return bool(attrs.get("control_plane") or attrs.get("affects_process")
                or not attrs.get("reversible", False))


def is_gated_name(name: str) -> bool:
    """Gate decision for a named action — unknown or unattributed ⇒ gated."""
    s = spec(name)
    if s is None:
        return True
    return is_gated(s.get("attributes"))


def _gating_reason(name: str, attrs: dict) -> str:
    if attrs.get("control_plane"):
        return (f"'{name}' changes OT control state and could affect the physical "
                "process; held for human approval per the OT-safety policy.")
    if attrs.get("affects_process"):
        return (f"'{name}' could affect the physical process; held for human "
                "approval per the OT-safety policy.")
    if not attrs.get("reversible", False):
        return f"'{name}' is not readily reversible; held for human approval."
    return f"'{name}' is held for human approval per the OT-safety policy."


def apply(actions: list[dict]) -> list[dict]:
    """Stamp each recommended action with the authoritative gate decision.

    Keeps the model's `rationale`/`gating_reason` text but overrides the boolean
    decision from the action's attributes. Unknown/unattributed actions are gated.
    """
    out: list[dict] = []
    for a in actions or []:
        name = a.get("name", "")
        s = spec(name)
        if s is None:                          # unrecognized -> fail safe
            a = {**a, "known": False, "domain": a.get("domain", "OT")}
            a["requires_human_approval"] = True
            a["auto_executable"] = False
            a.setdefault("gating_reason",
                         f"'{name}' is not a recognized response action; gated for safety.")
            a["title"] = a.get("title") or name
            out.append(a)
            continue
        attrs = s.get("attributes") or {}
        gated = is_gated(attrs)
        kind = s.get("kind", "ot")
        a = {**a, "known": True, "kind": kind, "domain": kind.upper(),
             "title": s.get("title") or name,
             "reversible": bool(attrs.get("reversible", False)),
             "control_plane": bool(attrs.get("control_plane", False)),
             "affects_process": bool(attrs.get("affects_process", False))}
        a["requires_human_approval"] = gated
        a["auto_executable"] = not gated
        # Keep the agent's explanation if present; otherwise supply the policy one.
        if gated:
            a["gating_reason"] = a.get("gating_reason") or _gating_reason(name, attrs)
        else:
            a["gating_reason"] = ""
        out.append(a)
    return out


def summarize(actions: list[dict]) -> dict:
    auto = [a["name"] for a in actions if a.get("auto_executable")]
    gated = [a["name"] for a in actions if a.get("requires_human_approval")]
    return {"auto": auto, "gated": gated, "n_auto": len(auto), "n_gated": len(gated)}


# --- relevance (which catalog actions fit this incident) --------------------

def relevant_actions(bundle: dict) -> list[str]:
    """Pick the catalog actions whose `relevant_when` matches the detected events,
    so a single OT write doesn't recommend blocking a C2 channel that was never
    seen, etc. Returns ids in canonical (catalog) order. Pure / no LLM."""
    events = bundle.get("events", []) if bundle else []
    rules = {e.get("rule") for e in events}
    ot_write = any(e.get("domain") == "OT" and (e.get("evidence") or {}).get("write")
                   for e in events)
    out: list[str] = []
    for a in catalog():
        when = a.get("relevant_when") or {}
        hit = (when.get("always")
               or (when.get("rule") in rules)
               or (when.get("ot_write") and ot_write))
        if hit:
            out.append(a["id"])
    return out
