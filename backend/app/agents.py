# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The three Kaaval agents — Triage, Investigation, Response — on local Ollama.

Each agent gets the correlated incident (with its events) and returns strict,
schema-constrained JSON. Outputs are normalized so every key is always present
(a degraded model response yields a safe default, never a crash). The Response
agent selects from the fixed playbook; gating.py then makes the authoritative
auto-vs-gated decision.
"""

from __future__ import annotations

import json

from . import egress, gating, llm

# --- schemas (Ollama structured output) -------------------------------------

_TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "headline": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "priority": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]},
        "confidence": {"type": "number"},
        "process_at_risk": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["headline", "severity", "priority", "confidence", "process_at_risk", "rationale"],
}

_INVEST_SCHEMA = {
    "type": "object",
    "properties": {
        "narrative": {"type": "string"},
        "pivot": {"type": "string"},
        "it_ot_link": {"type": "string"},
        "attack_chain": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "order": {"type": "integer"},
                    "domain": {"type": "string", "enum": ["IT", "OT"]},
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "tactic": {"type": "string"},
                    "what_happened": {"type": "string"},
                },
                "required": ["order", "domain", "technique_id", "technique_name", "tactic", "what_happened"],
            },
        },
        "iocs": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["narrative", "pivot", "it_ot_link", "attack_chain"],
}

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "enum": gating.names()},
                    "rationale": {"type": "string"},
                    "gating_reason": {"type": "string"},
                },
                "required": ["name", "rationale"],
            },
        },
    },
    "required": ["summary", "actions"],
}


def _incident_text(bundle: dict) -> str:
    """The incident as the model's user message: sensitive fields stripped (denylist)
    and the whole blob structurally FENCED as untrusted telemetry, so attacker-
    controllable values (DNS query, SNI, S7 function_name) can't act as instructions."""
    return egress.fenced(json.dumps(egress.scrub(bundle), indent=2, default=str))


def _iid(bundle: dict) -> str | None:
    return (bundle.get("incident") or {}).get("id")


def _sys(text: str) -> str:
    """Prepend the untrusted-data injection notice to every agent system prompt."""
    return egress.INJECTION_NOTICE + "\n\n" + text


# --- agents -----------------------------------------------------------------

def triage(bundle: dict) -> dict:
    system = (
        "You are the Triage agent in an IT/OT security operations center. Assess the "
        "incident's severity and priority by reasoning from the data given: the detection "
        "events and the affected assets in `asset_context` (each with its criticality and "
        "process_context from the deployment inventory). Judge impact by the criticality "
        "and process role of the assets involved — activity touching the OT/control path "
        "of a high-criticality asset is more severe than IT-only activity. Set "
        "process_at_risk from the affected assets' process_context, not from any assumed "
        "scenario. Reply ONLY with JSON matching the schema."
    )
    obj, meta = llm.ollama_json(_sys(system), _incident_text(bundle), _TRIAGE_SCHEMA,
                                num_predict=600, incident_id=_iid(bundle), purpose="triage")
    return _norm_triage(obj, meta)


def investigate(bundle: dict) -> dict:
    system = (
        "You are the Investigation agent. Correlate the IT and OT detection events into "
        "ONE cross-boundary story. Identify the pivot asset — the source host implicated "
        "across the events that crossed the IT/OT boundary (the incident's `pivot` and the "
        "assets in `asset_context` tell you which host and its role). Map every stage to "
        "MITRE ATT&CK for ICS (technique id, name, and tactic). Explain in it_ot_link how "
        "the IT foothold led to the OT impact. Reply ONLY with JSON matching the schema."
    )
    obj, meta = llm.ollama_json(_sys(system), _incident_text(bundle), _INVEST_SCHEMA,
                                num_predict=1800, incident_id=_iid(bundle), purpose="investigation")
    return _norm_investigation(obj, meta)


def respond(bundle: dict) -> dict:
    playbook = "\n".join(
        f"- {a['id']}: {a.get('title', a['id'])} "
        f"(kind={a.get('kind')}, control_plane={(a.get('attributes') or {}).get('control_plane', False)})"
        for a in gating.catalog()
    )
    system = (
        "You are the Response agent. Recommend graded response actions for this incident, "
        "choosing ONLY from this playbook:\n" + playbook + "\n\n"
        "OT-safety rule: any action that changes OT control state or could affect the "
        "physical process must be held for human approval; only low-risk reversible IT "
        "actions run automatically. For each action give a rationale, and for control-plane "
        "actions a plain-language gating_reason explaining why a human must approve it. "
        "Order actions so IT containment comes before OT recovery. Reply ONLY with JSON "
        "matching the schema."
    )
    obj, meta = llm.ollama_json(_sys(system), _incident_text(bundle), _RESPONSE_SCHEMA,
                                num_predict=1200, incident_id=_iid(bundle), purpose="response")
    out = _norm_response(obj, meta)
    # Recommend only actions RELEVANT to what was actually detected (not a fixed
    # playbook every time). Keep the model's rationale where it chose an action,
    # else fall back to the catalog's declared rationale.
    relevant = gating.relevant_actions(bundle)
    chosen = {a["name"]: a for a in out["actions"] if a.get("name") in relevant}
    merged = [chosen.get(n, {"name": n, "rationale": (gating.spec(n) or {}).get("rationale", "")})
              for n in relevant]
    out["actions"] = gating.apply(merged)              # authoritative gate decision
    out["gating_summary"] = gating.summarize(out["actions"])
    return out


def run_pipeline(bundle: dict) -> dict:
    return {
        "triage": triage(bundle),
        "investigation": investigate(bundle),
        "response": respond(bundle),
    }


# --- normalization (guarantee keys; degrade safely) -------------------------

def _meta(meta: dict) -> dict:
    return {"degraded": not meta.get("ok", False), "latency_s": meta.get("latency_s"),
            "error": meta.get("error")}


def _norm_triage(obj, meta) -> dict:
    o = obj or {}
    return {
        "headline": str(o.get("headline") or "Security incident requires review"),
        "severity": o.get("severity") if o.get("severity") in ("critical", "high", "medium", "low") else "high",
        "priority": o.get("priority") if o.get("priority") in ("P1", "P2", "P3", "P4") else "P1",
        "confidence": float(o["confidence"]) if isinstance(o.get("confidence"), (int, float)) else 0.5,
        "process_at_risk": str(o.get("process_at_risk") or "The affected process and assets"),
        "rationale": str(o.get("rationale") or "Model output unavailable; review the raw events."),
        "_meta": _meta(meta),
    }


def _norm_investigation(obj, meta) -> dict:
    o = obj or {}
    chain = o.get("attack_chain") if isinstance(o.get("attack_chain"), list) else []
    return {
        "narrative": str(o.get("narrative") or "Cross-domain analysis unavailable; see correlated events."),
        "pivot": str(o.get("pivot") or "the implicated source asset"),
        "it_ot_link": str(o.get("it_ot_link") or ""),
        "attack_chain": [c for c in chain if isinstance(c, dict)],
        "iocs": [str(x) for x in o.get("iocs", []) if isinstance(o.get("iocs"), list)],
        "_meta": _meta(meta),
    }


def _norm_response(obj, meta) -> dict:
    o = obj or {}
    actions = o.get("actions") if isinstance(o.get("actions"), list) else []
    return {
        "summary": str(o.get("summary") or "Recommended response actions for the incident."),
        "actions": [a for a in actions if isinstance(a, dict) and a.get("name")],
        "_meta": _meta(meta),
    }
