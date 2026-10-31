# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Glue: load the latest correlated incident from SQLite into the bundle the
agents consume, and run the full agent pipeline over it."""

from __future__ import annotations

from . import agents, assets, store


def _bundle_for(inc: dict, all_events: list[dict]) -> dict:
    """Shape one incident + its member events + the affected assets' profile context."""
    events = [e for e in all_events if e["id"] in inc["event_ids"]]
    refs = {inc.get("pivot")}
    for e in events:
        refs.add(e.get("src"))
        dst = e.get("dst") or ""
        refs.add(dst.split(":")[0] if dst else None)
    asset_context = [a for a in assets.list_assets() if a["name"] in refs]
    return {"incident": inc, "events": events, "asset_context": asset_context}


def all_incident_bundles() -> list[dict]:
    """One bundle per correlated incident (for the multi-incident SOC queue)."""
    conn = store.connect()
    store.init(conn)
    incidents = store.get_incidents(conn)
    all_events = store.get_events(conn)
    conn.close()
    return [_bundle_for(inc, all_events) for inc in incidents]


def latest_incident_bundle() -> dict | None:
    """Newest incident bundle (back-compat: the analyst chat grounds on this)."""
    bundles = all_incident_bundles()
    return bundles[-1] if bundles else None


def run() -> dict | None:
    bundle = latest_incident_bundle()
    if bundle is None:
        return None
    result = agents.run_pipeline(bundle)
    result["incident"] = bundle["incident"]
    return result


# --- observable (the Phase 5 demo printout + assertions) --------------------

_C = {"crit": "\033[1;31m", "warn": "\033[1;33m", "ok": "\033[1;32m",
      "auto": "\033[1;32m", "gate": "\033[1;31m", "dim": "\033[2m", "r": "\033[0m"}


def main() -> int:
    from . import detect  # local import to avoid cycle

    bundle = latest_incident_bundle()
    if bundle is None:
        print("No incident in the store; running detection over current logs ...")
        detect.run_detection()
        bundle = latest_incident_bundle()
    if bundle is None:
        print("No incident found — run an attack first (scripts/phase3_run.sh).")
        return 2

    inc = bundle["incident"]
    print(f"Kaaval agent pipeline over incident {inc['id']} "
          f"(pivot={inc['pivot']}, severity={inc['severity']})\n")

    result = agents.run_pipeline(bundle)
    tri, inv, resp = result["triage"], result["investigation"], result["response"]

    print(f"{_C['warn']}== TRIAGE =={_C['r']}  [{tri['_meta']['latency_s']}s]")
    print(f"  {tri['severity'].upper()} / {tri['priority']}  (confidence {tri['confidence']:.2f})")
    print(f"  headline: {tri['headline']}")
    print(f"  at risk : {tri['process_at_risk']}")
    print(f"  {_C['dim']}{tri['rationale']}{_C['r']}\n")

    print(f"{_C['warn']}== INVESTIGATION =={_C['r']}  [{inv['_meta']['latency_s']}s]")
    print(f"  pivot: {inv['pivot']}")
    print(f"  {_C['dim']}{inv['narrative']}{_C['r']}")
    print(f"  IT/OT link: {inv['it_ot_link']}")
    print("  ATT&CK ICS chain:")
    for c in sorted(inv["attack_chain"], key=lambda x: x.get("order", 0)):
        print(f"    {c.get('order','?')}. [{c.get('domain','?')}] {c.get('technique_id','?')} "
              f"{c.get('technique_name','')} — {c.get('tactic','')}")
    print()

    print(f"{_C['warn']}== RESPONSE =={_C['r']}  [{resp['_meta']['latency_s']}s]")
    print(f"  {_C['dim']}{resp['summary']}{_C['r']}")
    for a in resp["actions"]:
        if a["requires_human_approval"]:
            tag = f"{_C['gate']}GATED (human approval){_C['r']}"
        else:
            tag = f"{_C['auto']}AUTO{_C['r']}"
        print(f"  [{tag}] {a['name']} — {a.get('title','')}")
        print(f"        why: {a.get('rationale','')}")
        if a["requires_human_approval"]:
            print(f"        gate: {a.get('gating_reason','')}")
    gs = resp["gating_summary"]
    print(f"\n  gating: {gs['n_auto']} auto {gs['auto']}, {gs['n_gated']} gated {gs['gated']}")

    # --- assertions -----------------------------------------------------------
    chain_domains = {c.get("domain") for c in inv["attack_chain"]}
    # The pivot is correctly identified if it names the workstation/ews OR refers
    # to the incident's pivot host (the model may use the IP), in either the
    # pivot field or the narrative.
    pivot_text = (inv["pivot"] + " " + inv["narrative"]).lower()
    pivot_ok = ("ews" in pivot_text or "workstation" in pivot_text
                or str(inc["pivot"]) in (inv["pivot"] + inv["narrative"]))
    checks = {
        "triage parsed": not tri["_meta"]["degraded"],
        "investigation parsed": not inv["_meta"]["degraded"],
        "response parsed": not resp["_meta"]["degraded"],
        "triage has severity": tri["severity"] in ("critical", "high", "medium", "low"),
        "investigation spans IT+OT": {"IT", "OT"} <= chain_domains,
        "investigation identifies pivot": pivot_ok,
        "OT actions gated": all(n in gs["gated"] for n in ("rearm_interlock", "restore_setpoint")),
        "IT containment auto": "isolate_ews_ot" in gs["auto"],
    }
    print()
    ok = True
    for label, passed in checks.items():
        ok &= passed
        print(f"  {_C['ok'] + 'PASS' + _C['r'] if passed else _C['crit'] + 'FAIL' + _C['r']} {label}")
    print()
    print(f"{_C['ok']}PHASE 5 PASS{_C['r']}" if ok else f"{_C['crit']}PHASE 5 INCOMPLETE{_C['r']}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
