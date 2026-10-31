# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""LLM-assisted detection-rule authoring (detection-as-code with an AI co-pilot).

An analyst describes intent in plain language ("flag inbound RDP to a plant host",
"DNS to a newly-seen domain") and the local LLM proposes ONE field-based rule in
the same generic schema the engine already evaluates. The proposal is GROUNDED:
the model may only use the real Zeek/ICSNPP logs + fields it is shown, the valid
operators, and valid severities; the output is validated against the rules store's
own validator. Nothing is saved or activated here — the proposal is returned for
the human to review, edit, and explicitly save (POST /api/rules). Human-in-command,
exactly like the response gate.
"""

from __future__ import annotations

from . import llm, rules_store

# The Zeek/ICSNPP logs the engine reads, with the fields most useful for rules.
# The model is constrained to these so it can't invent non-existent fields.
FIELD_PALETTE: dict[str, list[str]] = {
    "ssh":  ["id.orig_h", "id.resp_h", "id.resp_p", "auth_success", "auth_attempts", "client", "server"],
    "ssl":  ["id.orig_h", "id.resp_h", "id.resp_p", "server_name", "version", "validation_status"],
    "dns":  ["id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name"],
    "conn": ["id.orig_h", "id.resp_h", "id.resp_p", "proto", "conn_state", "history", "duration", "orig_bytes"],
    "opcua_binary": ["id.orig_h", "id.resp_h", "id.resp_p", "msg_type", "endpoint_url"],
    "s7comm": ["id.orig_h", "id.resp_h", "rosctr_name", "function_name", "function_code"],
    "cotp": ["id.orig_h", "id.resp_h", "pdu_name"],
}

_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "log": {"type": "string", "enum": list(FIELD_PALETTE)},
        "field": {"type": "string"},
        "op": {"type": "string", "enum": sorted(rules_store._VALID_OPS)},
        "value": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "domain": {"type": "string", "enum": ["IT", "OT"]},
        "attack": {"type": "array", "items": {"type": "string"}},
        "description": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["name", "log", "field", "op", "value", "severity", "domain", "description"],
}


def _palette_text() -> str:
    return "\n".join(f"  {log}: {', '.join(fields)}" for log, fields in FIELD_PALETTE.items())


def propose(intent: str, sample: str | None = None) -> dict:
    """Return {proposed_rule, valid, warning, rationale, meta}. Never raises, never
    saves. The proposed rule is shaped to drop straight into POST /api/rules."""
    system = (
        "You are a detection engineer for an IT/OT SOC that evaluates Zeek + ICSNPP "
        "logs. Given the analyst's intent, propose exactly ONE field-based detection "
        "rule as strict JSON for the schema. Hard rules:\n"
        "- Use ONLY these logs and their fields (never invent a field):\n" + _palette_text() + "\n"
        "- op is one of: " + ", ".join(sorted(rules_store._VALID_OPS)) + " "
        "(use 'exists' when presence alone matters; numeric compares for ports/counts).\n"
        "- severity: critical|high|medium|low|info. domain: IT or OT (OT = s7comm/opcua/cotp).\n"
        "- attack: MITRE ATT&CK for ICS technique ids (e.g. T0886) when applicable, else [].\n"
        "- Pick the single most precise field+op+value that captures the intent.\n"
        "- description: one line an analyst can read. rationale: why this catches it.\n"
        "Reply ONLY with JSON matching the schema."
    )
    user = f"Analyst intent:\n{intent}\n"
    if sample:
        user += f"\nA sample log line to match (JSON):\n{sample}\n"

    obj, meta = llm.ollama_json(system, user, _SCHEMA, num_predict=500)
    if not obj:
        return {"proposed": None, "valid": False,
                "warning": "the model did not return a usable rule; try rephrasing",
                "meta": {"degraded": True, **(meta or {})}}

    proposed = {
        "name": str(obj.get("name") or "").strip() or f"{obj.get('log')} {obj.get('field')} {obj.get('op')}",
        "log": obj.get("log"),
        "field": str(obj.get("field") or "").strip(),
        "op": obj.get("op"),
        "value": "" if obj.get("op") == "exists" else str(obj.get("value", "")),
        "severity": obj.get("severity"),
        "domain": obj.get("domain", "IT"),
        "attack": [str(a).strip() for a in (obj.get("attack") or []) if str(a).strip()],
        "description": str(obj.get("description") or "").strip(),
    }
    # Validate against the SAME validator the create endpoint uses; surface (not
    # raise) any problem so the analyst can fix it in the form before saving.
    err = rules_store._validate_user_rule(proposed)
    warning = None
    if proposed["log"] not in FIELD_PALETTE:
        warning = f"unknown log {proposed['log']!r}"
    elif proposed["field"] not in FIELD_PALETTE.get(proposed["log"], []):
        warning = f"field {proposed['field']!r} is not a known {proposed['log']} field — double-check it"
    elif err:
        warning = err
    return {
        "proposed": proposed,
        "valid": err is None and warning is None,
        "warning": warning,
        "rationale": str(obj.get("rationale") or ""),
        "meta": {"degraded": not meta.get("ok", False), "latency_s": meta.get("latency_s")},
    }
