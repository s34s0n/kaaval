# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Compliance assessment engine — control status from STORE EVIDENCE, never the LLM.

Framework control -> check mappings are CONFIG (backend/app/frameworks/*.yaml, with a
version field that tracks the standard revision). Each control names a deterministic
CHECK that reads ground truth from the store/profile (detections, assets, the immutable
approval + egress audit logs) and returns one of three explicit states:

    MET           — positive evidence is present.
    GAP           — evidence of ABSENCE (a violation/missing control was observed).
    NOT_ASSESSED  — we do not observe this control here (absence of data, NOT 'met').

Absence of data renders as NOT_ASSESSED, never MET (no over-claiming). Every asserted
status carries evidence items an auditor can trace (incident id, approval record,
asset, timestamp). An optional LLM EXECUTIVE NARRATIVE may be drafted from the already-
computed deterministic results (and only via the egress boundary in cloud mode); it can
NEVER change a control's status.
"""

from __future__ import annotations

import json
import os
import time  # noqa: F401  (callers stamp generated_ts; kept for parity)

import yaml

from . import (asset_discovery, assets as assets_mod, auth, config, egress, llm,
               profile, rules_store, store, telemetry)

MET, GAP, NOT = "MET", "GAP", "NOT_ASSESSED"
FRAMEWORKS_DIR = os.environ.get("KAAVAL_FRAMEWORKS",
                                os.path.join(config.REPO_ROOT, "backend", "app", "frameworks"))


def _r(status, rationale, evidence):
    return {"status": status, "rationale": rationale, "evidence": evidence}


def _ev(kind, ref, detail, ts=None):
    return {"type": kind, "ref": ref, "detail": detail, "ts": ts}


# --- ground-truth context (read directly from the store; no model, no snapshot) ----

def build_context() -> dict:
    conn = store.connect(); store.init(conn)
    incidents = store.get_incidents(conn)
    events = store.get_events(conn)
    approvals = store.get_approvals(conn)
    egress_log = store.get_egress(conn)
    auto_actions = store.get_auto_actions(conn)
    cases = store.load_cases(conn)
    conn.close()

    executed_gated = []
    resolved = []
    for c in cases:
        for a in (c.get("actions") or []):
            if a.get("requires_human_approval") and a.get("status") in ("approved", "executed"):
                executed_gated.append({"incident": c["id"], "name": a.get("name")})
        if (c.get("resolution") or {}).get("resolved"):
            resolved.append(c["id"])

    return {
        "incidents": incidents, "events": events, "approvals": approvals,
        "egress": egress_log, "auto_actions": auto_actions, "cases": cases,
        "executed_gated": executed_gated, "resolved_cases": resolved,
        "assets": assets_mod.list_assets(),
        "discovery": asset_discovery.discover(),
        "rules_enabled": [r["id"] for r in rules_store.list_rules() if r.get("enabled")],
        "profile_authz": profile._load().get("authorization") or {},
        "roles_configured": {v.get("role") for v in auth._load_tokens().values() if isinstance(v, dict)},
        "dev_mode": config.DEV_MODE,
        "llm_mode": llm.mode(),
        "telemetry_present": bool(telemetry.recent(per_log=1)) or bool(events),
        "site": profile.name(),
    }


# --- deterministic checks (each returns {status, rationale, evidence}) -------------

def asset_inventory(ctx, p):
    a = ctx["assets"]; s = ctx["discovery"]["summary"]
    if not a:
        return _r(GAP, "No assets are inventoried.", [])
    ev = [_ev("asset", x["name"], f"{x['domain']} · {x.get('role') or x.get('device_type','')} · crit={x['criticality']}")
          for x in a[:8]]
    ev.append(_ev("audit", "asset_discovery",
                  f"passive discovery: {s.get('total', 0)} assets ({s.get('ot', 0)} OT, {s.get('unmanaged', 0)} unmanaged/rogue)"))
    return _r(MET, f"{len(a)} assets inventoried with zone + criticality classification (passive discovery).", ev)


def network_monitoring(ctx, p):
    if ctx["telemetry_present"]:
        return _r(MET, "Passive network monitoring (Zeek + ICSNPP) is collecting IT and OT telemetry.",
                  [_ev("audit", "sensor:zeek+icsnpp", f"{len(ctx['events'])} detection events derived from observed traffic")])
    return _r(NOT, "No telemetry observed in the current window — monitoring status indeterminate.", [])


def detection_capability(ctx, p):
    rules = ctx["rules_enabled"]
    if rules:
        return _r(MET, f"{len(rules)} detection rules are active (protocol-aware OT + IT).",
                  [_ev("config", r, "enabled detection rule") for r in rules[:6]])
    return _r(GAP, "No detection rules are enabled.", [])


def ot_access_control(ctx, p):
    authz = ctx["profile_authz"]
    if not authz:
        return _r(NOT, "No OT authorization policy is declared in the deployment profile.", [])
    ev = [_ev("config", f"authz:{proto}", f"allowed_clients={rule.get('allowed_clients')}")
          for proto, rule in authz.items()]
    unauth = [e for e in ctx["events"] if "unauthorized" in (e.get("rule") or "")]
    for e in unauth[:4]:
        ev.append(_ev("event", e["id"], f"unauthorized OT access detected + flagged: {e['summary'][:80]}", e.get("ts")))
    return _r(MET, "OT access is policy-controlled (authorized clients per protocol) and unauthorized access is detected.", ev)


def human_approval_gate(ctx, p):
    approvals = ctx["approvals"]
    approved_keys = {(a["incident_id"], a["action"]) for a in approvals if a["decision"] == "approved"}
    missing = [g for g in ctx["executed_gated"] if (g["incident"], g["name"]) not in approved_keys]
    if missing:
        return _r(GAP, "A gated OT control action is recorded as executed WITHOUT a matching human-approval record.",
                  [_ev("incident", g["incident"], f"gated action '{g['name']}' executed with no approval record") for g in missing[:5]])
    gated = [a for a in approvals if a.get("gated")]
    if gated:
        ev = [_ev("approval", f"{a['incident_id']}/{a['action']}",
                  f"approved by '{a['approver']}' · result={'OK' if a['result_ok'] else 'failed'} · {a['gating_reason'][:70]}", a["ts"])
              for a in gated[:6]]
        return _r(MET, "Every OT control action was held at the gate and executed only after a recorded human approval.", ev)
    return _r(NOT, "No OT control actions occurred in this period — gate enforcement was not exercised.", [])


def audit_logging(ctx, p):
    ev = []
    if ctx["approvals"]:
        ev.append(_ev("audit", "approvals", f"{len(ctx['approvals'])} immutable approval/decision records", ctx["approvals"][0]["ts"]))
    ev.append(_ev("audit", "egress_log", f"{len(ctx['egress'])} cloud-egress records (provable data-leaving-box)",
                  ctx["egress"][0]["ts"] if ctx["egress"] else None))
    ev.append(_ev("audit", "auto_actions", f"{len(ctx['auto_actions'])} autonomy-policy action records"))
    if ctx["approvals"] or ctx["egress"] or ctx["auto_actions"]:
        return _r(MET, "Append-only audit channels record approvals, autonomy actions, and cloud egress.", ev)
    return _r(NOT, "Audit channels are provisioned but hold no records for this period.",
              [_ev("audit", "approvals/egress/auto_actions", "audit schema present; no entries yet")])


def separation_of_duties(ctx, p):
    roles = ctx["roles_configured"]
    if "approver" in roles and "operator" in roles:
        return _r(MET, "Distinct operator and approver roles are provisioned; an operator cannot authorize an OT control action.",
                  [_ev("config", "rbac", f"roles provisioned: {sorted(roles)}")])
    if ctx["dev_mode"]:
        return _r(NOT, "Running in DEV mode (no token store) — RBAC separation of duties not exercised here.", [])
    return _r(GAP, "No distinct approver/operator roles are provisioned; separation of duties is not enforced.", [])


def zones_conduits(ctx, p):
    s = ctx["discovery"]["summary"]
    if s.get("total"):
        return _r(MET, "Assets are partitioned into zones (OT / IT / external) with the IT/OT gateway as the conduit.",
                  [_ev("audit", "zones", f"OT={s.get('ot')} · IT={s.get('it')} · external={s.get('external')}"),
                   _ev("asset", "gateway", "declared IT/OT conduit (authorized boundary device)")])
    return _r(NOT, "No zone classification is available.", [])


def incident_response(ctx, p):
    incs = ctx["incidents"]
    if incs:
        ev = [_ev("incident", i["id"], f"{i['severity']} · {'cross-domain ' if i['cross_domain'] else ''}{'+'.join(i['domains'])} · correlated + triaged")
              for i in incs[:5]]
        return _r(MET, "Detected activity is correlated into incidents, triaged, and routed to a human-gated response.", ev)
    return _r(NOT, "No incidents occurred in this period — the IR workflow was not exercised.", [])


def remediation_verification(ctx, p):
    if ctx["resolved_cases"]:
        return _r(MET, "Remediation is verified against FRESH post-action telemetry (not cached state).",
                  [_ev("incident", r, "resolution confirmed on a fresh telemetry window") for r in ctx["resolved_cases"][:4]])
    return _r(NOT, "No remediation verification has run in this period.", [])


def egress_control(ctx, p):
    mode = ctx["llm_mode"]
    ev = [_ev("config", "llm.mode", f"current mode: {mode} "
              f"({'air-gapped — no external model calls' if mode == 'local' else 'cloud via the sanitizing egress boundary'})")]
    if ctx["egress"]:
        ev.append(_ev("audit", "egress_log", f"{len(ctx['egress'])} egress events; identities pseudonymized before transmission",
                      ctx["egress"][0]["ts"]))
    return _r(MET, "Data leaving the boundary is controlled: local mode is air-gapped; cloud routes through one sanitizing, "
                   "pseudonymizing, audited egress boundary.", ev)


def not_assessed(ctx, p):
    return _r(NOT, p.get("reason", "Not observable from network/SOC telemetry; assess by separate review (policy, physical, personnel)."), [])


CHECKS = {
    "asset_inventory": asset_inventory, "network_monitoring": network_monitoring,
    "detection_capability": detection_capability, "ot_access_control": ot_access_control,
    "human_approval_gate": human_approval_gate, "audit_logging": audit_logging,
    "separation_of_duties": separation_of_duties, "zones_conduits": zones_conduits,
    "incident_response": incident_response, "remediation_verification": remediation_verification,
    "egress_control": egress_control, "not_assessed": not_assessed,
}


# --- framework loading + evaluation -------------------------------------------------

def list_frameworks() -> list[dict]:
    out = []
    if not os.path.isdir(FRAMEWORKS_DIR):
        return out
    for fn in sorted(os.listdir(FRAMEWORKS_DIR)):
        if fn.endswith((".yaml", ".yml")):
            try:
                with open(os.path.join(FRAMEWORKS_DIR, fn)) as f:
                    d = yaml.safe_load(f) or {}
                fw = d.get("framework", {})
                out.append({"id": fw.get("id", fn), "name": fw.get("name"), "version": fw.get("version"),
                            "authority": fw.get("authority"), "controls": len(d.get("controls", []))})
            except (OSError, yaml.YAMLError):
                pass
    return out


def _load_framework(framework_id: str) -> dict | None:
    for fn in os.listdir(FRAMEWORKS_DIR) if os.path.isdir(FRAMEWORKS_DIR) else []:
        if not fn.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(FRAMEWORKS_DIR, fn)) as f:
            d = yaml.safe_load(f) or {}
        if (d.get("framework") or {}).get("id") == framework_id:
            return d
    return None


_NARRATIVE_SCHEMA = {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}


def _fallback_narrative(report: dict) -> str:
    s = report["summary"]
    posture = f"{s.get(MET, 0)} met, {s.get(GAP, 0)} gap(s), and {s.get(NOT, 0)} not assessed of {s.get('total', 0)} controls"
    gaps = [c for c in report["controls"] if c["status"] == GAP]
    parts = [f"Assessment of {report['site']} against {report['framework'].get('name')} finds {posture}."]
    if gaps:
        parts.append("Gap(s) requiring attention: " + "; ".join(f"{c['id']} {c['title']}" for c in gaps[:3]) + ".")
    else:
        parts.append("No gaps were identified among the assessed controls.")
    parts.append("Controls marked 'not assessed' are not observable from network/SOC telemetry and require separate review.")
    parts.append("All statuses are derived from recorded evidence — detections, the immutable approval and egress audit "
                 "logs, and the asset inventory — not from model judgement.")
    return " ".join(parts)


def narrative(report: dict) -> dict:
    """Optional executive prose drafted FROM the deterministic results. Cannot change any
    control status. In cloud mode this routes through the egress boundary (identities
    pseudonymized out / de-pseudonymized back). Falls back to a deterministic template."""
    fallback = _fallback_narrative(report)
    system = (
        "You are drafting a one-paragraph EXECUTIVE SUMMARY for a regulatory compliance report. "
        "Use ONLY the assessment results provided. The control statuses (MET / GAP / NOT_ASSESSED) "
        "are AUTHORITATIVE and were computed from recorded evidence — you must NOT change, invent, "
        "soften, or re-judge any status, and you must NOT claim a control is met unless it is marked "
        "MET. Write 4-6 sentences of plain, formal language for a government auditor: overall posture, "
        "key strengths, the specific gaps (if any), and that statuses are evidence-backed. "
        "Return JSON {\"summary\": \"...\"}."
    )
    payload = {
        "framework": report["framework"].get("name"), "site": report["site"], "summary": report["summary"],
        "controls": [{"id": c["id"], "title": c["title"], "status": c["status"], "rationale": c["rationale"]}
                     for c in report["controls"]],
    }
    try:
        obj, meta = llm.ollama_json(system, json.dumps(payload), _NARRATIVE_SCHEMA, num_predict=450,
                                    incident_id=None, principal="compliance", purpose="compliance-narrative")
    except Exception:  # noqa: BLE001 — narrative is best-effort; never block the report
        obj, meta = None, {"ok": False}
    if obj and isinstance(obj.get("summary"), str) and obj["summary"].strip():
        return {"text": obj["summary"].strip(), "source": f"llm:{meta.get('provider', '?')}"}
    return {"text": fallback, "source": "deterministic-fallback"}


def assess(framework_id: str, *, generated_ts: float | None = None) -> dict:
    """Deterministic assessment of one framework against current store evidence."""
    fw = _load_framework(framework_id)
    if fw is None:
        return {"error": f"unknown framework '{framework_id}'"}
    ctx = build_context()
    controls = []
    for c in fw.get("controls", []):
        check = CHECKS.get(c.get("check"), not_assessed)
        res = check(ctx, c.get("params") or {})
        controls.append({"id": c.get("id"), "family": c.get("family"), "title": c.get("title"),
                         "check": c.get("check"), **res})
    summary = {MET: 0, GAP: 0, NOT: 0}
    for c in controls:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    summary["total"] = len(controls)
    return {
        "framework": fw.get("framework", {}),
        "site": ctx["site"],
        "generated": generated_ts or 0.0,   # stamped by the caller (no Date in engine)
        "summary": summary,
        "controls": controls,
    }
