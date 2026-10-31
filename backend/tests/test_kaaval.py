# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Kaaval unit tests — the safety-critical + scenario-agnostic logic, offline.

No containers/LLM required: these exercise the pure logic (attribute gating,
profile loaders for BOTH plants, the detection engine's authorization decision,
the fresh-window telemetry filter, profile-driven status, and rule-assist
validation). Run: ../.venv/bin/python -m pytest backend/tests -q
"""
import os

import asyncio
import json

from app import (actions, adversary, asset_discovery, assets as assets_mod, auth, case_report, casework,
                 cef, config, correlate, cpe as cpe_mod, discovery_detect, egress, enrichment, executors,
                 gating, inventory, llm, main as appmain, model, nvd, oui, playbooks, profile,
                 rule_assist, rules_engine, rules_store, siem, store, topology)
from app.model import Event

PUMP = os.path.join(config.REPO_ROOT, "profiles", "pumpstation.yaml")
REACTOR = os.path.join(config.REPO_ROOT, "profiles", "reactor.yaml")


def use(path):
    """Point the profile loader at a specific deployment profile (cache-busting)."""
    config.PROFILE_PATH = path
    profile._cache.update(mtime=None, data=None)


# --- attribute-based gating (the OT-safety core) ----------------------------

def test_is_gated_attribute_matrix():
    assert gating.is_gated({"control_plane": True, "reversible": True, "affects_process": False})
    assert gating.is_gated({"control_plane": False, "reversible": True, "affects_process": True})
    assert gating.is_gated({"control_plane": False, "reversible": False, "affects_process": False})
    assert not gating.is_gated({"control_plane": False, "reversible": True, "affects_process": False})


def test_gating_fail_safe():
    # Missing / empty / unknown -> gated. A real product must fail closed.
    assert gating.is_gated({}) is True
    assert gating.is_gated(None) is True
    use(PUMP)
    assert gating.is_gated_name("not_a_real_action") is True
    out = gating.apply([{"name": "not_a_real_action"}])
    assert out[0]["requires_human_approval"] is True and out[0]["known"] is False


def test_ot_gated_it_auto_both_profiles():
    for p in (PUMP, REACTOR):
        use(p)
        assert gating.names(), f"{p}: empty catalog"
        for n in gating.ot_action_names():
            assert gating.is_gated_name(n) is True, f"{p}: OT action {n} not gated"
        for a in gating.catalog():
            if a.get("kind") == "it":
                assert gating.is_gated_name(a["id"]) is False, f"{p}: IT action {a['id']} gated"


# --- profile loaders (both plants) ------------------------------------------

def test_pump_profile():
    use(PUMP)
    assert profile.is_authorized_client("s7comm", "172.30.0.11")        # gateway
    assert not profile.is_authorized_client("s7comm", "172.30.0.12")    # ews
    assert profile.safety()["variable"] == "discharge_pressure_bar"
    assert profile.safety()["danger"] == 12.0
    assert profile.opcua_nodes()["nodes"]["discharge_pressure_bar"]
    assert {"rearm_interlock", "restore_setpoint"} <= {a["id"] for a in profile.actions()}


def test_reactor_profile():
    use(REACTOR)
    assert profile.safety()["variable"] == "reactor_temp_c"
    assert profile.safety()["danger"] == 280.0
    assert profile.opcua_nodes()["nodes"]["reactor_temp_c"] == "Reactor.ReactorTemp"
    assert profile.opcua_nodes()["namespace_uri"].endswith("/reactor")
    ids = {a["id"] for a in profile.actions()}
    assert {"rearm_hightemp_interlock", "restore_coolant_setpoint"} <= ids
    # Same protocol policy as profile #1 (topology unchanged).
    assert profile.is_authorized_client("s7comm", "172.30.0.11")
    assert not profile.is_authorized_client("s7comm", "172.30.0.12")


# --- detection engine: authorization is data, not a hardcoded pivot ----------

def _builtin(rid):
    return next(b for b in rules_store.BUILTINS if b["id"] == rid)


def test_unauthorized_s7_write_fires_critical():
    use(PUMP)
    rule = _builtin("ot.unauthorized_s7_command")
    logs = {"s7comm": [{"id.orig_h": "172.30.0.12", "id.resp_h": "172.30.0.10",
                        "function_name": "Write Variable", "ts": 1.0}]}
    evs = rules_engine._eval_rule(logs, rule)
    assert len(evs) == 1 and evs[0].rule == "unauthorized_s7_command"
    assert evs[0].severity == "critical"        # write escalation
    assert any(t["id"] == "T0836" for t in evs[0].techniques)


def test_authorized_s7_does_not_fire():
    use(PUMP)
    rule = _builtin("ot.unauthorized_s7_command")
    logs = {"s7comm": [{"id.orig_h": "172.30.0.11", "id.resp_h": "172.30.0.10",  # gateway = allowed
                        "function_name": "Read Variable", "ts": 1.0}]}
    assert rules_engine._eval_rule(logs, rule) == []


def test_repeat_activity_forms_separate_bursts():
    # Two S7 writes far apart in time -> two distinct burst events (-> two incidents),
    # not one event pinned to the first occurrence.
    use(PUMP)
    rule = _builtin("ot.unauthorized_s7_command")
    logs = {"s7comm": [{"id.orig_h": "172.30.0.12", "id.resp_h": "172.30.0.10",
                        "function_name": "Write Variable", "ts": 10.0},
                       {"id.orig_h": "172.30.0.12", "id.resp_h": "172.30.0.10",
                        "function_name": "Write Variable", "ts": 10.0 + config.CORRELATION_WINDOW_S + 50}]}
    evs = rules_engine._eval_rule(logs, rule)
    assert len(evs) == 2 and evs[0].id != evs[1].id


def test_malformed_rule_never_raises():
    # The engine must swallow a bad rule, not crash detection.
    assert rules_engine.evaluate({"s7comm": [{"ts": 1.0}]}) is not None  # returns a list


# --- fresh-window telemetry filter (D6 verification) ------------------------

def test_load_logs_since_filter(tmp_path):
    (tmp_path / "s7comm.log").write_text('{"ts":10.0,"x":1}\n{"ts":20.0,"x":2}\n')
    fresh = model.load_logs(str(tmp_path), since=15.0)
    assert [r["ts"] for r in fresh["s7comm"]] == [20.0]
    allrows = model.load_logs(str(tmp_path))
    assert len(allrows["s7comm"]) == 2


# --- profile-driven status (scenario-agnostic) ------------------------------

def test_status_pump():
    use(PUMP)
    assert appmain._status({"discharge_pressure_bar": 5.0, "interlock_enabled": True}) == "ok"
    assert appmain._status({"discharge_pressure_bar": 12.5, "interlock_enabled": True}) == "burst"
    assert appmain._status({"discharge_pressure_bar": 5.0, "interlock_enabled": False}) == "danger"


def test_status_reactor():
    use(REACTOR)
    assert appmain._status({"reactor_temp_c": 80.0, "hightemp_interlock_enabled": True}) == "ok"
    assert appmain._status({"reactor_temp_c": 300.0, "hightemp_interlock_enabled": True}) == "burst"
    assert appmain._status({"reactor_temp_c": 80.0, "hightemp_interlock_enabled": False}) == "danger"


# --- correlation: entity-scoped, not merge-everything-in-a-window -----------

def _ev(rid, ts, domain, src, dst):
    return Event(id=rid, ts=ts, domain=domain, rule=rid, techniques=[], severity="high",
                 src=src, dst=dst, summary=rid, evidence_count=1, evidence={})


def test_chain_merges_via_pivot():
    # Inbound SSH (attacker->ews) + ews-originated OT write share the ews pivot ->
    # ONE cross-domain incident, even though the two events have different sources.
    evs = [_ev("external_remote_access", 1.0, "IT", "attacker", "ews:22"),
           _ev("unauthorized_s7_command", 3.0, "OT", "ews", "plc:102")]
    incs = correlate.correlate(evs)
    assert len(incs) == 1 and incs[0].cross_domain is True


def test_unrelated_sources_do_not_merge():
    # Two unrelated sources touching unrelated hosts within the SAME time window
    # must NOT be merged into one incident (the old time-only clustering bug).
    evs = [_ev("c2_beaconing", 1.0, "IT", "ews", "c2:443"),
           _ev("ot_network_scan", 2.0, "IT", "workstation7", "fileserver:445")]
    incs = correlate.correlate(evs)
    assert len(incs) == 2


def test_low_and_slow_campaign_correlates():
    # The headline P5 case: an IT foothold and the OT manipulation are FAR apart in
    # time (a low-and-slow campaign), but share the ews pivot and are different
    # stages. They must still fuse into ONE cross-domain incident — the old fixed
    # 30s window would have split them and missed the correlation entirely.
    slow = config.CORRELATION_WINDOW_S * 100        # way beyond the burst window
    evs = [_ev("external_remote_access", 0.0, "IT", "attacker", "ews:22"),
           _ev("unauthorized_s7_command", slow, "OT", "ews", "plc:102")]
    incs = correlate.correlate(evs)
    assert len(incs) == 1 and incs[0].cross_domain is True


def test_repeated_same_stage_stays_separate():
    # Two runs of the SAME action, far apart: same rule + same host but beyond the
    # burst window => NOT a progression, so they remain two distinct incidents
    # (preserves "repeated activity forms its own incident").
    slow = config.CORRELATION_WINDOW_S * 100
    evs = [_ev("unauthorized_s7_command", 0.0, "OT", "ews", "plc:102"),
           _ev("unauthorized_s7_command", slow, "OT", "ews", "plc:102")]
    assert len(correlate.correlate(evs)) == 2


def test_beyond_campaign_window_does_not_merge():
    # Even a new stage on the same host does NOT join once the gap exceeds the
    # campaign window — linkage is bounded, not unlimited.
    far = config.CAMPAIGN_WINDOW_S + 100
    evs = [_ev("external_remote_access", 0.0, "IT", "attacker", "ews:22"),
           _ev("unauthorized_s7_command", far, "OT", "ews", "plc:102")]
    assert len(correlate.correlate(evs)) == 2


def test_campaign_boundary_splits_same_pivot():
    # Two campaigns through the SAME ews pivot. Entity-scoping alone fuses them
    # (new rule within the campaign window = progression), but an explicit campaign
    # boundary (a fresh attack launch) splits them into two distinct incidents.
    evs = [_ev("external_remote_access", 0.0, "IT", "attacker", "ews:22"),
           _ev("unauthorized_s7_command", 5.0, "OT", "ews", "plc:102"),
           _ev("c2_beaconing", 100.0, "IT", "ews", "c2:443")]   # second campaign
    assert len(correlate.correlate(evs)) == 1                    # no boundary -> fused
    assert len(correlate.correlate(evs, boundaries=[50.0])) == 2  # boundary -> two incidents


def test_boundary_before_a_campaign_does_not_split_it():
    # A boundary that precedes ALL of a campaign's events must not split that
    # campaign — only boundaries that fall BETWEEN events segment them.
    evs = [_ev("external_remote_access", 60.0, "IT", "attacker", "ews:22"),
           _ev("unauthorized_s7_command", 63.0, "OT", "ews", "plc:102")]
    assert len(correlate.correlate(evs, boundaries=[50.0])) == 1


def test_incident_id_is_stable_as_cluster_grows():
    # The id is content-derived (anchor = earliest event), not positional. A later
    # stage joining the same campaign must NOT change the incident's id — otherwise
    # its triage/approvals would be orphaned on the next 2s detection cycle.
    e1 = _ev("external_remote_access", 1.0, "IT", "attacker", "ews:22")
    id1 = correlate.correlate([e1])[0].id
    e2 = _ev("unauthorized_s7_command", 3.0, "OT", "ews", "plc:102")
    incs2 = correlate.correlate([e1, e2])
    assert len(incs2) == 1 and incs2[0].id == id1
    assert id1.startswith("INC-") and len(id1) == 12      # INC- + 8 hex

    # Two genuinely separate incidents get DIFFERENT stable ids.
    other = correlate.correlate([_ev("c2_beaconing", 99.0, "IT", "ews", "c2:443")])[0].id
    assert other != id1


# --- P2 data layer: atomic snapshot + persisted state + audit trail ----------

def _tmpdb(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.sqlite"))
    conn = store.connect()
    store.init(conn)
    return conn


def test_replace_all_atomic_roundtrip(tmp_path, monkeypatch):
    conn = _tmpdb(tmp_path, monkeypatch)
    evs = [_ev("external_remote_access", 1.0, "IT", "attacker", "ews:22"),
           _ev("unauthorized_s7_command", 3.0, "OT", "ews", "plc:102")]
    incs = correlate.correlate(evs)
    store.replace_all(conn, evs, incs)
    assert len(store.get_events(conn)) == 2
    assert len(store.get_incidents(conn)) == 1
    # A second swap fully replaces the prior snapshot (no accumulation, no leftovers).
    store.replace_all(conn, [evs[0]], correlate.correlate([evs[0]]))
    assert len(store.get_events(conn)) == 1
    conn.close()


def test_case_state_survives_restart(tmp_path, monkeypatch):
    conn = _tmpdb(tmp_path, monkeypatch)
    c = appmain.Case("INC-deadbeef", 100.0)
    c.agents = {"triage": {"severity": "critical"}}
    c.actions = [{"name": "rearm_interlock", "status": "approved",
                  "requires_human_approval": True}]
    c.agents_done = True
    c.remediated_ts = 150.0
    store.save_case(conn, c.persist_dict())
    conn.close()

    # Simulate a fresh process: load persisted cases and rebuild the Case.
    conn2 = store.connect(); store.init(conn2)
    rows = store.load_cases(conn2); conn2.close()
    assert len(rows) == 1
    restored = appmain.Case.from_persist(rows[0])
    assert restored.id == "INC-deadbeef"
    assert restored.agents_done is True
    assert restored.actions[0]["status"] == "approved"
    assert restored.status() == "remediating"


def test_approvals_audit_is_appended_and_survives_case_clear(tmp_path, monkeypatch):
    conn = _tmpdb(tmp_path, monkeypatch)
    store.add_approval(conn, ts=1.0, approver="analyst-1", action="rearm_interlock",
                       incident_id="INC-1", decision="approved", gated=True,
                       rationale="re-arm safety interlock", gating_reason="affects process",
                       result_ok=True)
    rows = store.get_approvals(conn, "INC-1")
    assert len(rows) == 1 and rows[0]["approver"] == "analyst-1"
    assert rows[0]["gated"] is True and rows[0]["result_ok"] is True
    # Clearing cases (demo reset) must NOT erase the immutable audit trail.
    store.save_case(conn, {"id": "INC-1", "actions": []})
    store.clear_cases(conn)
    assert store.load_cases(conn) == []
    assert len(store.get_approvals(conn)) == 1
    conn.close()


# --- secrets handling: the API key must never touch disk --------------------

def test_api_key_never_persisted_to_disk(tmp_path, monkeypatch):
    cfg_path = tmp_path / "llm.json"
    monkeypatch.setattr(config, "LLM_CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "")   # no env seed
    monkeypatch.setattr(llm, "_cfg_cache", None)

    # cloud mode required for a cloud provider to be active (mode is the single switch).
    cfg = llm.set_config({"mode": "cloud", "provider": "anthropic", "anthropic_api_key": "sk-ant-SECRET-xyz"})
    # In-memory config keeps the key (so the session works)...
    assert cfg["anthropic_api_key"] == "sk-ant-SECRET-xyz"
    # ...but the persisted file must NOT contain it.
    on_disk = json.loads(cfg_path.read_text())
    assert "anthropic_api_key" not in on_disk
    assert on_disk["provider"] == "anthropic"
    # status() never leaks the key either, only whether one is present.
    assert "anthropic_api_key" not in llm.status()
    assert llm.status()["has_key"] is True


def test_env_key_takes_precedence_and_is_not_written(tmp_path, monkeypatch):
    cfg_path = tmp_path / "llm.json"
    cfg_path.write_text(json.dumps({"provider": "local"}))   # legacy file, no key
    monkeypatch.setattr(config, "LLM_CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-ant-FROM-ENV")
    monkeypatch.setattr(llm, "_cfg_cache", None)

    assert llm.get_config()["anthropic_api_key"] == "sk-ant-FROM-ENV"
    llm.set_config({"anthropic_model": "claude-opus-4-8"})
    assert "anthropic_api_key" not in json.loads(cfg_path.read_text())


def test_legacy_key_on_disk_is_ignored(tmp_path, monkeypatch):
    # A hand-edited / legacy file that still carries a key must not load it.
    cfg_path = tmp_path / "llm.json"
    cfg_path.write_text(json.dumps({"provider": "anthropic", "anthropic_api_key": "sk-ant-LEAKED"}))
    monkeypatch.setattr(config, "LLM_CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(llm, "_cfg_cache", None)
    assert llm.get_config()["anthropic_api_key"] == ""


def test_secret_never_in_status_disk_error_or_audit(tmp_path, monkeypatch):
    """The key lives in process memory only. It must not surface in status(), on
    disk, in a transport error trace, or in the egress audit row."""
    import io
    import urllib.error
    SENTINEL = "sk-or-v1-SENTINEL-must-never-leak-cafebabe"
    monkeypatch.setattr(config, "LLM_CONFIG_PATH", str(tmp_path / "llm.json"))
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "e.sqlite"))
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(llm, "_cfg_cache", None)

    llm.set_config({"mode": "cloud", "provider": "openrouter",
                    "openrouter_model": "m", "openrouter_api_key": SENTINEL})
    # (a) status() carries only has_key, never the value
    assert SENTINEL not in json.dumps(llm.status()) and llm.status()["has_key"] is True
    # (b) disk never carries the key
    assert SENTINEL not in (tmp_path / "llm.json").read_text()
    # (c) a transport failure echoes the provider RESPONSE, never the request key
    def boom(*a, **k):
        raise urllib.error.HTTPError("https://api/x", 401, "Unauthorized", {}, io.BytesIO(b"invalid key supplied"))
    monkeypatch.setattr(egress, "_http", boom)
    obj, meta = egress.cloud_json("openrouter", "m", SENTINEL, "sys", "user",
                                  {"type": "object", "properties": {}}, retries=0)
    assert obj is None and SENTINEL not in json.dumps(meta)
    # (d) the egress audit row records provider/model/bytes only — no key
    conn = store.connect(); store.init(conn)
    rows = store.get_egress(conn); conn.close()
    assert rows and all(SENTINEL not in json.dumps(r) for r in rows)
    monkeypatch.setattr(llm, "_cfg_cache", None)


def test_openrouter_egress_is_always_pseudonymized(tmp_path, monkeypatch):
    """The default provider is OpenRouter (off-prem). Real asset identity (IPs,
    names) must be pseudonymized at the egress boundary BEFORE anything leaves the
    box — and a missing/failed provider must degrade safely, never crash."""
    import urllib.error
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "e.sqlite"))
    captured = {}

    def fake_http(provider, model, key, system, user_msgs, *, stream=False, max_tokens=None):
        # Capture exactly what cloud_json is about to put on the wire, then stop
        # before any socket is opened.
        captured["system"] = system
        captured["users"] = json.dumps(user_msgs)
        raise urllib.error.URLError("stop-before-network")

    monkeypatch.setattr(egress, "_http", fake_http)
    real_ip = "172.30.0.12"      # the ews — a real on-prem identifier
    obj, meta = egress.cloud_json(
        "openrouter", "any-model:free", "sk-or-test",
        f"system prompt referencing {real_ip}",
        f"the engineering workstation {real_ip} issued an S7 write",
        {"type": "object", "required": ["verdict"]}, incident_id="INC-PSEUDO", retries=1)
    wire = captured["system"] + captured["users"]
    assert real_ip not in wire, "real IP must never cross the cloud egress boundary"
    assert "HOST_" in wire, "the real IP must be replaced by a per-incident pseudonym token"
    # Provider failure degrades to (None, not-ok) — the pipeline never crashes.
    assert obj is None and meta["ok"] is False


def test_chat_cloud_mode_needs_no_local_ollama(tmp_path, monkeypatch):
    """In cloud mode the analyst chat must stream an answer with NO local Ollama:
    the Ollama tool loop is skipped and the final answer streams through the
    pseudonymizing egress boundary. If any code path touches Ollama, fail loudly."""
    import app.chat as chatmod
    monkeypatch.setattr(config, "LLM_CONFIG_PATH", str(tmp_path / "llm.json"))
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "c.sqlite"))
    monkeypatch.setattr(llm, "_cfg_cache", None)
    llm.set_config({"mode": "cloud", "provider": "openrouter",
                    "openrouter_model": "m:free", "openrouter_api_key": "k"})

    def no_ollama(*a, **k):
        raise AssertionError("cloud mode must not call local Ollama")
    monkeypatch.setattr(chatmod, "_post", no_ollama)

    async def fake_stream(provider, model, key, system, messages, **k):
        yield "plant "
        yield "is recovering"
    monkeypatch.setattr(egress, "cloud_stream", fake_stream)
    # propose_action runs through llm.ollama_json -> cloud path; stub to "no action".
    monkeypatch.setattr(llm, "ollama_json", lambda *a, **k: (None, {}))

    async def _run():
        out = []
        async for ev in chatmod.chat_sse("what happened?", incident_id=None,
                                         history=[], latest_state=None, plain=True):
            out.append(ev)
        return "".join(out)

    text = asyncio.new_event_loop().run_until_complete(_run())
    assert "plant" in text and "recovering" in text
    monkeypatch.setattr(llm, "_cfg_cache", None)


# --- managed-inventory overlay (add asset / network settings) ----------------

def test_inventory_add_validate_merge_and_resolve(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INVENTORY_PATH", str(tmp_path / "inv.json"))
    use(PUMP)
    # validation: bad domain / criticality / missing id are rejected.
    assert inventory._validate({"id": "x", "domain": "bogus", "criticality": "high"}) is not None
    assert inventory._validate({"id": "", "domain": "IT", "criticality": "high"}) is not None
    rec = inventory.add_asset({"id": "historian01", "domain": "IT", "criticality": "high",
                               "ips": ["172.30.0.20"], "role": "Process historian"})
    assert rec["id"] == "historian01"
    # merged into the asset list, tagged managed (profile assets are not).
    by = {a["name"]: a for a in assets_mod.list_assets()}
    assert by["historian01"]["managed"] is True and by["plc"]["managed"] is False
    # the new IP now resolves to the managed name (used by the map / zeek stats).
    assert inventory.name_for_ip("172.30.0.20") == "historian01"
    assert inventory.domain_for_ip("172.30.0.20") == "IT"
    # a managed asset is NEVER auto-authorized for OT.
    assert by["historian01"]["authorized_ot"] is False
    assert inventory.delete_asset("historian01") is True
    assert "historian01" not in {a["name"] for a in assets_mod.list_assets()}


def test_passive_asset_discovery(tmp_path, monkeypatch):
    use(PUMP)
    monkeypatch.setattr(config, "INVENTORY_PATH", str(tmp_path / "inv.json"))
    logdir = tmp_path / "logs"; logdir.mkdir()
    (logdir / "conn.log").write_text(
        json.dumps({"id.orig_h": "172.30.0.12", "id.resp_h": "172.30.0.10", "id.resp_p": 102,
                    "proto": "tcp", "orig_ip_bytes": 100, "resp_ip_bytes": 50, "ts": 1.0}) + "\n"
        + json.dumps({"id.orig_h": "203.0.113.5", "id.resp_h": "172.30.0.12", "id.resp_p": 22,
                      "proto": "tcp", "orig_ip_bytes": 40, "resp_ip_bytes": 20, "ts": 2.0}) + "\n")
    (logdir / "s7comm.log").write_text(
        json.dumps({"id.orig_h": "172.30.0.12", "id.resp_h": "172.30.0.10",
                    "function_name": "Write Variable", "ts": 1.0}) + "\n")

    d = asset_discovery.discover(str(logdir))
    by = {a["ip"]: a for a in d["assets"]}
    # the PLC is discovered on the wire, classified OT, and matched to the profile.
    assert by["172.30.0.10"]["domain"] == "OT" and by["172.30.0.10"]["managed"] is True
    assert "s7comm" in by["172.30.0.10"]["protocols"]
    # an undeclared external host is discovered and flagged UNMANAGED (rogue signal).
    assert by["203.0.113.5"]["unmanaged"] is True
    assert by["203.0.113.5"]["domain"] == "external"
    assert d["summary"]["unmanaged"] >= 1


def test_inventory_network_settings_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INVENTORY_PATH", str(tmp_path / "inv.json"))
    n = inventory.set_network({"subnet": "172.30.0.0/24", "monitored_ranges": ["10.0.0.0/8", " "]})
    assert n["subnet"] == "172.30.0.0/24"
    assert n["monitored_ranges"] == ["10.0.0.0/8"]   # blanks dropped
    assert inventory.network()["subnet"] == "172.30.0.0/24"


# --- PHASE 1: RBAC / auth (the gate is only as good as who can reach it) ----

def test_rbac_required_roles():
    rr = auth.required_role
    assert rr("POST", "/api/actions/x/approve") == "approver"   # OT approve
    assert rr("POST", "/api/actions/x/apply") == "operator"     # reversible IT
    assert rr("POST", "/api/llm") == "admin"
    assert rr("POST", "/api/autonomy") == "admin"
    assert rr("POST", "/api/reset") == "admin"
    assert rr("POST", "/api/attack/run") == "admin"
    assert rr("POST", "/api/range/malicious") == "admin"
    assert rr("PUT", "/api/inventory/network") == "admin"
    assert rr("PUT", "/api/siem") == "admin"            # SIEM egress posture
    assert rr("POST", "/api/siem/forward") == "admin"
    assert rr("GET", "/api/siem") == "viewer"           # status is readable
    assert rr("POST", "/api/cases/INC-1/comment") == "operator"      # working a case
    assert rr("POST", "/api/cases/INC-1/transition") == "operator"
    assert rr("POST", "/api/cases/INC-1/close") == "approver"        # accountable decision
    assert rr("POST", "/api/cases/INC-1/reopen") == "approver"
    assert rr("POST", "/api/cases/INC-1/report/signoff") == "approver"
    assert rr("GET", "/api/cases/INC-1") == "viewer"
    assert rr("POST", "/api/rules") == "operator"
    assert rr("GET", "/api/incidents") == "viewer"


def test_rbac_separation_of_duties():
    operator = {"name": "o", "role": "operator"}
    approver = {"name": "a", "role": "approver"}
    admin = {"name": "ad", "role": "admin"}
    # An operator (the investigator) CANNOT approve an OT control action.
    assert not auth.authorized(operator, "approver")
    assert auth.authorized(approver, "approver")
    assert auth.authorized(admin, "approver")
    # Only admin reaches admin actions; no principal => denied (fail closed).
    assert not auth.authorized(approver, "admin")
    assert auth.authorized(admin, "admin")
    assert not auth.authorized(None, "viewer")


def test_rbac_token_store(tmp_path, monkeypatch):
    f = tmp_path / "auth.json"
    f.write_text(json.dumps({"tok-op": {"name": "alice", "role": "operator"},
                             "tok-ap": {"name": "bob", "role": "approver"}}))
    monkeypatch.setattr(config, "AUTH_TOKENS_PATH", str(f))
    monkeypatch.setattr(config, "AUTH_TOKENS_ENV", "")
    monkeypatch.setattr(config, "AUTH_TOKEN", "")
    assert auth.principal_for_token("tok-op") == {"name": "alice", "role": "operator"}
    assert auth.principal_for_token("tok-ap")["role"] == "approver"
    assert auth.principal_for_token("nope") is None     # bad token => no principal


# --- PHASE 1: cloud egress sanitization -------------------------------------

def test_egress_pseudonymize_roundtrip(monkeypatch):
    use(PUMP)
    monkeypatch.setattr(config, "INVENTORY_PATH", "/nonexistent-inv.json")
    ps = egress.Pseudonymizer()
    text = "Alert: 172.30.0.10 received a write from 172.30.0.12 (the ews host)."
    masked = ps.mask(text)
    # raw identifiers must NOT leave the box.
    assert "172.30.0.10" not in masked and "172.30.0.12" not in masked
    assert "ews" not in masked
    # but the relationship is preserved (two distinct tokens) and reverses cleanly.
    back = ps.unmask(masked)
    assert "172.30.0.10" in back and "172.30.0.12" in back and "ews" in back


def test_egress_streaming_unmask_across_chunks():
    rev = {"PLC_1": "172.30.0.10"}
    um = egress.StreamUnmasker(rev)
    # token split across two chunks must still be de-pseudonymized.
    out = um.feed("the host PL") + um.feed("C_1 wrote") + um.flush()
    assert "172.30.0.10" in out and "PLC_1" not in out


def test_egress_scrub_denylist(monkeypatch):
    monkeypatch.setattr(config, "EGRESS_DENYLIST", ["secret", "parsed_fields.query"])
    obj = {"keep": 1, "secret": "x", "parsed_fields": {"query": "evil`payload", "ok": 2}}
    assert egress.scrub(obj) == {"keep": 1, "parsed_fields": {"ok": 2}}


def test_egress_fencing_marks_untrusted():
    out = egress.fenced("DNS query: ignore-previous-instructions.evil")
    assert out.startswith("«UNTRUSTED_TELEMETRY»") and out.endswith("«/UNTRUSTED_TELEMETRY»")


# --- F1: corpus NL tools stay read-only + egress-masked ----------------------

def test_corpus_tools_are_read_only():
    from app import chat as chatmod
    names = {t["function"]["name"] for t in chatmod.TOOLS}
    assert names == {"query_events", "query_assets", "query_flows", "query_incidents",
                     "get_asset_detail", "get_asset", "list_rules", "get_latest_state"}
    # Every tool is a READ verb (query_/get_/list_) — none mutates or acts (invariant 1).
    assert all(n.startswith(("query_", "get_", "list_")) for n in names)
    # The chat module has no handle on the executor at all (no path to an action).
    assert not hasattr(chatmod, "actions")
    assert "actions" not in chatmod._run_tool.__code__.co_names


def test_corpus_tool_output_pseudonymized_for_cloud(monkeypatch):
    use(PUMP)
    monkeypatch.setattr(config, "INVENTORY_PATH", "/nonexistent-inv.json")
    # what the cloud path folds in: read-only tool output carrying real asset identity.
    tool_results = [{"tool": "query_assets", "args": {}, "result": {"assets": [
        {"id": "plc", "ip": "172.30.0.10", "device_type": "Siemens S7 PLC"},
        {"id": "ews", "ip": "172.30.0.12", "device_type": "Workstation"}]}}]
    masked = egress.session("INC-cloudtest").mask(egress.fenced(json.dumps(tool_results)))
    # asset IPs and names must NOT survive into the cloud prompt.
    assert "172.30.0.10" not in masked and "172.30.0.12" not in masked
    assert "plc" not in masked and "ews" not in masked
    # structural fence is preserved (still flagged untrusted to the model).
    assert "«UNTRUSTED_TELEMETRY»" in masked


# --- PHASE 1: invariant re-check — gate is fail-safe, never auto on a gate ---

def test_no_gated_action_is_auto_executable():
    for p in (PUMP, REACTOR):
        use(p)
        out = gating.apply([{"name": n} for n in gating.names()])
        for a in out:
            if a["requires_human_approval"]:
                assert a["auto_executable"] is False     # gated => never auto-runs


# --- PHASE 1: discovery wired into detection (first-seen / rogue) ------------

def test_first_seen_rogue_detection(tmp_path, monkeypatch):
    use(PUMP)
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "d.sqlite"))
    monkeypatch.setattr(config, "INVENTORY_PATH", str(tmp_path / "inv.json"))
    # 1) baseline cycle: only known hosts -> seed silently, NO alerts.
    base = {"conn": [{"id.orig_h": "172.30.0.12", "id.resp_h": "172.30.0.10",
                      "id.resp_p": 102, "proto": "tcp", "ts": 1.0}]}
    assert discovery_detect.detect(base) == []
    # 2) an UNDECLARED host appears -> a real rogue_asset Event (+ new OT conversation).
    nxt = {"conn": [{"id.orig_h": "203.0.113.9", "id.resp_h": "172.30.0.10",
                     "id.resp_p": 102, "proto": "tcp", "ts": 2.0}]}
    evs = discovery_detect.detect(nxt)
    rogue = [e for e in evs if e.rule == "rogue_asset"]
    assert rogue and rogue[0].src == "203.0.113.9" and rogue[0].severity == "critical"
    assert any(e.rule == "new_conversation" for e in evs)
    # 3) seen now -> no repeat alert for the same host/pair.
    assert discovery_detect.detect(nxt) == []


# --- LLM-assisted rule authoring: validation path (no model call) -----------

def test_rule_assist_validation():
    assert "s7comm" in rule_assist.FIELD_PALETTE and "conn" in rule_assist.FIELD_PALETTE
    good = {"name": "rdp", "log": "conn", "field": "id.resp_p", "op": "eq",
            "value": "3389", "severity": "high"}
    assert rules_store._validate_user_rule(good) is None
    bad_op = {**good, "op": "bogus"}
    assert rules_store._validate_user_rule(bad_op) is not None
    bad_sev = {**good, "severity": "urgent"}
    assert rules_store._validate_user_rule(bad_sev) is not None


# --- F2: compliance reporting (status from EVIDENCE, never the LLM) ----------

from app import compliance, compliance_render  # noqa: E402

_STATES = {compliance.MET, compliance.GAP, compliance.NOT}


def test_compliance_frameworks_are_versioned_config():
    fws = compliance.list_frameworks()
    ids = {f["id"] for f in fws}
    assert {"iec_62443_3_3", "nist_800_82_r3", "cea_nciipc_in"} <= ids
    # versioned so they track standard revisions; controls map to real checks
    for f in fws:
        assert f["version"] and f["controls"] > 0
    # every control names a check that EXISTS in the registry (no silent NOT_ASSESSED)
    for fid in ids:
        fw = compliance._load_framework(fid)
        for c in fw["controls"]:
            assert c["check"] in compliance.CHECKS, f"{fid}:{c['id']} -> unknown check {c['check']}"


def test_compliance_three_states_no_overclaim():
    # absence of data must render NOT_ASSESSED, never MET
    empty = {"approvals": [], "executed_gated": []}
    assert compliance.human_approval_gate(empty, {})["status"] == compliance.NOT
    # evidence of absence is a GAP (a gated action ran with no approval record)
    viol = {"approvals": [], "executed_gated": [{"incident": "INC-7", "name": "isolate_plc"}]}
    g = compliance.human_approval_gate(viol, {})
    assert g["status"] == compliance.GAP
    assert any(e["ref"] == "INC-7" for e in g["evidence"]), "GAP must cite the incident"
    # positive evidence is MET and cites the approver + timestamp
    ok = {"approvals": [{"incident_id": "INC-7", "action": "isolate_plc", "decision": "approved",
                         "gated": True, "approver": "andre", "result_ok": True,
                         "gating_reason": "OT control-plane action", "ts": 1700.0}],
          "executed_gated": [{"incident": "INC-7", "name": "isolate_plc"}]}
    m = compliance.human_approval_gate(ok, {})
    assert m["status"] == compliance.MET
    ev = m["evidence"][0]
    assert "andre" in ev["detail"] and ev["ts"] == 1700.0, "MET must trace to the approval record"
    # no-assets is a GAP, not a silent pass
    assert compliance.asset_inventory({"assets": [], "discovery": {"summary": {}}}, {})["status"] == compliance.GAP


def test_compliance_every_asserted_status_cites_evidence():
    rep = compliance.assess("iec_62443_3_3", generated_ts=0.0)
    assert set(rep["summary"]) >= _STATES
    for c in rep["controls"]:
        assert c["status"] in _STATES
        # MET/GAP are asserted claims -> must be traceable to a record
        if c["status"] in (compliance.MET, compliance.GAP):
            assert c["evidence"], f"{c['id']} asserts {c['status']} with no evidence"
        # NOT_ASSESSED must carry a rationale (why we don't observe it)
        assert c["rationale"]


def test_compliance_status_is_code_derived_not_llm(monkeypatch):
    # Even if the model tries to claim everything is met, statuses are unchanged:
    # the LLM only drafts prose; it never sets a control status.
    monkeypatch.setattr(llm, "ollama_json",
                        lambda *a, **k: ({"summary": "ALL CONTROLS ARE FULLY MET AND COMPLIANT."}, {"provider": "stub"}))
    rep = compliance.assess("nist_800_82_r3", generated_ts=0.0)
    before = {c["id"]: c["status"] for c in rep["controls"]}
    nar = compliance.narrative(rep)
    after = {c["id"]: c["status"] for c in rep["controls"]}
    assert before == after, "narrative generation must not mutate control status"
    assert nar["source"].startswith("llm:")  # prose came from the model, status did not


def test_compliance_render_produces_docx_and_pdf():
    rep = compliance.assess("cea_nciipc_in", generated_ts=0.0)
    nar = compliance._fallback_narrative(rep)
    docx = compliance_render.to_docx(rep, nar)
    pdf = compliance_render.to_pdf(rep, nar)
    assert docx[:2] == b"PK"          # DOCX is a zip container
    assert pdf[:5] == b"%PDF-"


def test_compliance_narrative_payload_is_egress_masked_in_cloud(tmp_path, monkeypatch):
    """The pseudonymizer was built for incident bundles; prove it ALSO covers the
    distinct compliance-narrative payload shape. Run narrative() in cloud mode and
    capture exactly what would leave the box — zero asset identity / IPs allowed."""
    import urllib.error
    use(PUMP)
    monkeypatch.setattr(config, "LLM_CONFIG_PATH", str(tmp_path / "llm.json"))
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "e.sqlite"))
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(llm, "_cfg_cache", None)
    llm.set_config({"mode": "cloud", "provider": "openrouter",
                    "openrouter_model": "m", "openrouter_api_key": "sk-dummy"})

    # A report whose site/title/rationale all carry real asset identity + an IP.
    report = {
        "framework": {"name": "IEC 62443-3-3"}, "site": "plc pumping station",
        "summary": {"MET": 1, "GAP": 0, "NOT_ASSESSED": 0, "total": 1},
        "controls": [{"id": "SR 1.2", "title": "ews and plc authentication",
                      "status": "MET",
                      "rationale": "asset plc (172.30.0.10) and gateway (172.30.0.11) are authorized OT clients"}],
    }
    captured = {}
    def cap(provider, model, key, system, user_msgs, **k):
        captured["blob"] = system + json.dumps(user_msgs)
        raise urllib.error.URLError("stop-before-network")
    monkeypatch.setattr(egress, "_http", cap)

    nar = compliance.narrative(report)               # routes via egress.cloud_json
    blob = captured["blob"]
    # ZERO real identity in the outbound payload...
    for ident in ("172.30.0.10", "172.30.0.11", "plc", "ews", "gateway"):
        assert ident not in blob, f"identity '{ident}' leaked into the cloud payload"
    # ...and masking actually ran (pseudonyms present), not just stripped.
    assert "PLC_" in blob or "HOST_" in blob or "GW_" in blob
    # transport was blocked, so the report still gets the deterministic fallback prose.
    assert nar["source"] == "deterministic-fallback"
    monkeypatch.setattr(llm, "_cfg_cache", None)


# --- F3: asset enrichment + CVE/NVD (CPE-only egress, honest no-match) --------

def test_oui_and_cpe_resolution_are_local():
    assert oui.vendor_for_mac("00:1B:1B:2A:4C:10") == "Siemens AG"
    assert oui.vendor_for_mac(None) is None and oui.vendor_for_mac("zz") is None
    # declared metadata -> CPE
    cpe = cpe_mod.resolve({"vendor": "Siemens", "product": "SIMATIC S7-1200", "version": "4.2", "banners": []})
    assert cpe == "cpe:2.3:o:siemens:s7-1200_firmware:4.2:*:*:*:*:*:*:*"
    # passive banner -> CPE (version captured from the Zeek SSH software string)
    cpe2 = cpe_mod.resolve({"vendor": None, "product": None, "version": None, "banners": ["SSH-2.0-OpenSSH_8.9p1"]})
    assert cpe2 == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
    # nothing to go on -> None (caller renders 'not assessed', never 'safe')
    assert cpe_mod.resolve({"vendor": None, "product": None, "version": None, "banners": []}) is None


def test_nvd_egress_transmits_only_the_cpe():
    """The single most important F3 property: only the CPE leaves the box."""
    cpe = "cpe:2.3:o:siemens:s7-1200_firmware:4.2:*:*:*:*:*:*:*"
    req = egress._nvd_request(cpe, api_key="rate-limit-key")
    wire = (req.full_url + json.dumps(dict(req.headers))).lower()
    # zero asset identity: no IP, no asset name, no MAC / OUI
    for ident in ("172.30.0.10", "172.30.0.11", "plc", "ews", "gateway", "00:1b:1b", "001b1b"):
        assert ident not in wire, f"asset identity '{ident}' would reach NVD"
    # the CPE product identifier IS present (that's all NVD needs)
    assert "s7-1200_firmware" in wire and "cpename" in wire


def test_nvd_egress_refuses_non_cpe_arguments():
    # an IP, an asset name, or a CPE with an IP appended must be refused outright,
    # so identity cannot be smuggled through the NVD socket.
    for bad in ("172.30.0.10", "plc", "siemens s7-1200",
                "cpe:2.3:o:siemens:s7-1200_firmware:4.2 at 172.30.0.10"):
        try:
            egress._nvd_request(bad, None)
            assert False, f"NVD egress accepted a non-CPE argument: {bad!r}"
        except ValueError:
            pass


def test_nvd_cloud_lookup_sends_only_cpe_end_to_end(tmp_path, monkeypatch):
    import urllib.request
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "c.sqlite"))
    monkeypatch.setattr(llm, "mode", lambda: "cloud")
    captured = {}
    class FakeResp:
        def read(self): return b'{"vulnerabilities":[]}'
        def __enter__(self): return self
        def __exit__(self, *a): return False
    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url; captured["headers"] = dict(req.headers); return FakeResp()
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    res = nvd.lookup("cpe:2.3:o:siemens:s7-1200_firmware:4.2:*:*:*:*:*:*:*")
    wire = (captured["url"] + json.dumps(captured["headers"])).lower()
    for ident in ("172.30.0.10", "plc", "gateway", "00:1b:1b", "001b1b"):
        assert ident not in wire
    assert "s7-1200_firmware" in wire and "cpename" in wire
    # empty NVD result = ASSESSED, none known — not 'not_assessed'
    assert res["status"] == "none_known"


def test_cve_unknown_is_not_assessed_never_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "c.sqlite"))
    monkeypatch.setattr(llm, "mode", lambda: "local")
    # no CPE -> not assessed
    assert nvd.lookup(None)["status"] == "not_assessed"
    # CPE absent from snapshot -> not assessed (NOT none_known / safe)
    assert nvd.lookup("cpe:2.3:o:acme:mystery_plc:1.0:*:*:*:*:*:*:*")["status"] == "not_assessed"
    # CPE present with CVEs -> vulnerable, with real severity
    r = nvd.lookup("cpe:2.3:o:siemens:s7-1200_firmware:4.2:*:*:*:*:*:*:*")
    assert r["status"] == "vulnerable" and r["max_cvss"] >= 9.0 and r["cves"]


def test_cve_cache_prevents_requery(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "c.sqlite"))
    monkeypatch.setattr(llm, "mode", lambda: "cloud")
    calls = {"n": 0}
    def fake_nvd(cpe, **k): calls["n"] += 1; return {"vulnerabilities": []}
    monkeypatch.setattr(egress, "nvd_cve", fake_nvd)
    cpe = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    nvd.lookup(cpe); nvd.lookup(cpe)
    assert calls["n"] == 1, "the second lookup must be served from the local CPE cache"


def test_enrichment_join_reassembled_locally(tmp_path, monkeypatch):
    use(PUMP)
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "c.sqlite"))
    monkeypatch.setattr(config, "INVENTORY_PATH", str(tmp_path / "inv.json"))
    monkeypatch.setattr(config, "LOG_DIR", str(tmp_path / "nologs"))
    monkeypatch.setattr(llm, "mode", lambda: "local")
    e = enrichment.enrich(ts=0.0)
    by = {a["name"]: a for a in e["assets"]}
    # Siemens PLC: OUI vendor + CPE + CVEs, joined back to THIS asset locally
    plc = by["plc"]
    assert plc["oui_vendor"] == "Siemens AG"
    assert plc["cpe"] == "cpe:2.3:o:siemens:s7-1200_firmware:4.2:*:*:*:*:*:*:*"
    assert plc["cve"]["status"] == "vulnerable" and plc["cve"]["max_cvss"] >= 9.0
    # gateway: Siemens by OUI but firmware unknown -> not assessed, NOT safe
    assert by["gateway"]["oui_vendor"] == "Siemens AG"
    assert by["gateway"]["cve"]["status"] == "not_assessed"


def test_enrichment_is_informational_only_no_action_path():
    # Invariant 1: an external feed/enrichment can never select or fire an action.
    assert not hasattr(enrichment, "gating") and not hasattr(enrichment, "actions")
    for mod in (enrichment, nvd, cpe_mod, oui):
        names = set(mod.__dict__)
        assert "gating" not in names and "actions" not in names
    # enrichment uses no LLM at all (pure data join)
    assert "agents" not in enrichment.__dict__


# --- F4: Purdue/topology inference (zone + authz from the one source of truth) -

def _topo_fixture(monkeypatch):
    """Synthetic discovery + flows: an IT host pivoting to OT over s7comm
    (unauthorized) alongside the authorized gateway->plc conduit, plus an
    unmanaged OT device. `anomalous` is exactly what zeek_stats derives from
    profile.is_authorized_client."""
    use(PUMP)
    monkeypatch.setattr(topology.asset_discovery, "discover", lambda *a, **k: {"assets": [
        {"id": "plc", "ip": "172.30.0.10", "domain": "OT", "device_type": "Siemens S7 PLC",
         "role": "Siemens PLC (pump controller)", "criticality": "critical", "unmanaged": False, "protocols": ["s7comm"]},
        {"id": "ews", "ip": "172.30.0.12", "domain": "IT", "device_type": "Workstation / IT endpoint",
         "role": "Engineering workstation", "criticality": "high", "unmanaged": False, "protocols": ["s7comm", "ssh"]},
        {"id": "gateway", "ip": "172.30.0.11", "domain": "OT", "device_type": "OPC UA server / gateway",
         "role": "IT/OT gateway", "criticality": "high", "unmanaged": False, "protocols": ["s7comm", "opcua"]},
        {"id": "10.0.0.99", "ip": "10.0.0.99", "domain": "OT", "device_type": "Siemens S7 PLC",
         "role": None, "criticality": "critical", "unmanaged": True, "protocols": ["s7comm"]},
    ], "summary": {}})
    monkeypatch.setattr(topology.zeek_stats, "overview", lambda *a, **k: {"edges": [
        {"src": "ews", "dst": "plc", "src_domain": "IT", "dst_domain": "OT",
         "services": ["s7comm"], "conns": 3, "bytes": 900, "anomalous": True},
        {"src": "gateway", "dst": "plc", "src_domain": "OT", "dst_domain": "OT",
         "services": ["s7comm"], "conns": 5, "bytes": 500, "anomalous": False},
    ]})


def test_topology_flags_unauthorized_it_to_ot_pivot(monkeypatch):
    _topo_fixture(monkeypatch)
    g = topology.graph()
    edges = {(e["src"], e["dst"]): e for e in g["edges"]}
    # the IT->OT s7comm flow from a non-authorized client is a flagged violation...
    assert edges[("ews", "plc")]["violation"] is True
    assert edges[("ews", "plc")]["boundary_crossing"] is True
    # ...the authorized gateway conduit (same boundary) is NOT flagged (not cosmetic)
    assert edges[("gateway", "plc")]["violation"] is False
    pivots = [f for f in g["findings"] if f["type"] == "ot_pivot"]
    assert pivots and pivots[0]["src"] == "ews" and pivots[0]["dst"] == "plc"
    # the unmanaged OT device is surfaced too
    assert any(f["type"] == "unmanaged_asset" and f["src"] == "10.0.0.99" for f in g["findings"])


def test_topology_violation_is_the_authz_functions_verdict():
    # The map's red line == the SAME authorization function detection uses. Prove it
    # for the canonical demo: ews is not an authorized s7comm client; the gateway is.
    use(PUMP)
    assert profile.is_authorized_client("s7comm", "172.30.0.12") is False   # ews -> flagged
    assert profile.is_authorized_client("s7comm", "172.30.0.11") is True    # gateway -> conduit


def test_topology_zone_matches_profile_domain(monkeypatch, tmp_path):
    # One source of truth: the zone shown for a managed device equals the domain
    # the profile declares (the same value detection/authz read).
    use(PUMP)
    monkeypatch.setattr(config, "LOG_DIR", str(tmp_path / "nologs"))
    monkeypatch.setattr(config, "INVENTORY_PATH", str(tmp_path / "inv.json"))
    declared = {a["id"]: a.get("domain") for a in profile.assets()}
    z = {n["id"]: n["zone"] for n in topology.graph()["nodes"]}
    for aid, dom in declared.items():
        assert z.get(aid) == dom, f"{aid}: map zone {z.get(aid)} != profile domain {dom}"


def test_purdue_level_never_contradicts_zone():
    for dt in ("Siemens S7 PLC", "OPC UA server / gateway", "Workstation / IT endpoint",
               "External host", "Unclassified host", "Modbus device"):
        assert topology._purdue("external", dt, None)["band"] == "External"
        ot_band = topology._purdue("OT", dt, None)["band"]
        assert ot_band.startswith("OT") or ot_band == "IT/OT DMZ"
        assert topology._purdue("IT", dt, None)["band"].startswith("IT")


def test_topology_is_read_only_local_no_action_or_egress():
    # Invariant 1 + local-only: no action path, no egress, no LLM in topology.
    for forbidden in ("gating", "actions", "egress", "llm", "agents"):
        assert forbidden not in topology.__dict__, f"topology must not reference {forbidden}"


# --- F5: response playbooks (PROPOSALS — never bypass the gate) --------------

_PIVOT_BUNDLE = {"incident": {"summary": "IT->OT pivot", "techniques": [{"id": "T0855"}, {"id": "T0822"}],
                             "cross_domain": True, "domains": ["IT", "OT"]},
                "events": [{"rule": "ot.unauthorized_s7_command", "domain": "OT",
                            "evidence": {"write": True}, "techniques": [{"id": "T0855"}]}]}


def test_playbook_match_is_code_derived():
    use(PUMP)
    matched = playbooks.match(_PIVOT_BUNDLE)
    assert "pump_it_ot_intrusion" in matched and "pump_unauthorized_ot_command" in matched
    # a bundle with nothing OT / no matching technique matches neither OT-keyed playbook
    assert playbooks.match({"incident": {}, "events": []}) == []


def test_playbook_gate_is_code_derived_not_yaml(monkeypatch):
    # A playbook YAML cannot set the gate. Even if it claims an OT action is auto,
    # resolve() stamps the decision from the code gate (gating), which wins.
    use(PUMP)
    fake = {"playbook": {"id": "f", "name": "f", "profile": "pumpstation"},
            "steps": [{"step": "action", "action": "rearm_interlock",
                       "requires_human_approval": False, "auto_executable": True},   # YAML lies
                      {"step": "action", "action": "isolate_ews_ot"}]}
    monkeypatch.setattr(playbooks, "_find", lambda pid: fake)
    steps = {s["action"]: s for s in playbooks.resolve("f", {})["steps"]}
    assert steps["rearm_interlock"]["requires_human_approval"] is True   # gate overrides the YAML
    assert steps["rearm_interlock"]["endpoint"] == "approve"
    assert steps["isolate_ews_ot"]["requires_human_approval"] is False   # IT, also from code
    # every available action's gate equals the authoritative code decision
    for s in steps.values():
        if s.get("available"):
            assert s["requires_human_approval"] == gating.is_gated_name(s["action"])


def test_playbook_unknown_action_fails_closed(monkeypatch):
    use(PUMP)
    fake = {"playbook": {"id": "f", "name": "f", "profile": "pumpstation"},
            "steps": [{"step": "action", "action": "nuke_plant"}]}
    monkeypatch.setattr(playbooks, "_find", lambda pid: fake)
    s = playbooks.resolve("f", {})["steps"][0]
    assert s["available"] is False and s["requires_human_approval"] is True and s["endpoint"] is None
    # the real endpoints would also reject it: unknown name is unspecced and gated
    assert gating.spec("nuke_plant") is None and gating.is_gated_name("nuke_plant") is True


def test_playbook_has_no_execution_path():
    # The single most important F5 property: a playbook cannot reach an executor.
    for forbidden in ("actions", "execute_it", "execute_ot", "OpcClient", "subprocess"):
        assert forbidden not in playbooks.__dict__, f"playbooks must not reference {forbidden}"
    use(PUMP)
    for s in playbooks.resolve("pump_it_ot_intrusion", _PIVOT_BUNDLE)["steps"]:
        if s["kind"] == "action" and s.get("available"):
            # the only thing a step offers is which EXISTING gated endpoint the human uses
            assert s["endpoint"] in ("approve", "apply")


def test_playbook_ot_step_cannot_execute_without_the_gate():
    # An OT playbook step is gated AND routes to the approver-only endpoint — there is
    # no path to execution that skips the human approval that exists today.
    use(PUMP)
    ot = [s for s in playbooks.resolve("pump_it_ot_intrusion", _PIVOT_BUNDLE)["steps"]
          if s["kind"] == "action" and s["domain"] == "OT"]
    assert ot, "the recover playbook must contain gated OT steps"
    for s in ot:
        assert s["requires_human_approval"] is True
        assert s["endpoint"] == "approve"
        assert gating.is_gated_name(s["action"]) is True
        assert auth.required_role("POST", f"/api/actions/{s['action']}/approve") == "approver"
    # separation of duties is intact: an operator still cannot approve an OT step
    assert not auth.authorized({"name": "o", "role": "operator"}, "approver")


def test_playbook_cannot_expand_the_action_catalog():
    use(PUMP)
    catalog = set(gating.names())
    for pid in [p["id"] for p in playbooks.list_playbooks()]:
        for s in playbooks.resolve(pid, _PIVOT_BUNDLE)["steps"]:
            if s["kind"] == "action" and s.get("available"):
                assert s["action"] in catalog, f"{pid} proposes uncatalogued action {s['action']}"


def test_llm_playbook_selection_is_suggestion_only(monkeypatch):
    # Invariant 1 with playbooks in the path: LLM output -> playbook SUGGESTION ->
    # the resolved actions are STILL code-derived and STILL gated. The pick fires nothing.
    use(PUMP)
    metas = [{"id": "pump_it_ot_intrusion", "name": "a"},
             {"id": "pump_unauthorized_ot_command", "name": "b"}]
    bundle = {"incident": {"summary": "x", "techniques": [{"id": "T0855"}]}}
    monkeypatch.setattr(llm, "ollama_json",
                        lambda *a, **k: ({"playbook_id": "pump_unauthorized_ot_command", "why": "y"}, {}))
    pick = appmain._llm_pick_playbook(metas, bundle, "INC-1")
    assert pick["recommended"] == "pump_unauthorized_ot_command" and pick["recommended_source"] == "llm"
    # the suggested playbook still gates every OT step (selection changed nothing)
    ot = [s for s in playbooks.resolve(pick["recommended"], _PIVOT_BUNDLE)["steps"]
          if s["kind"] == "action" and s["domain"] == "OT"]
    assert ot and all(s["requires_human_approval"] for s in ot)
    # a hallucinated, non-candidate id is refused -> falls back to a code pick
    monkeypatch.setattr(llm, "ollama_json", lambda *a, **k: ({"playbook_id": "auto_fire_everything"}, {}))
    pick2 = appmain._llm_pick_playbook(metas, bundle, "INC-1")
    assert pick2["recommended"] in {m["id"] for m in metas} and pick2["recommended_source"] == "code"


# --- F6: SIEM / CEF export (internal destination, real identity, one-way out) -

_SIEM_INC = {"id": "INC-9", "severity": "critical", "cross_domain": True, "domains": ["IT", "OT"],
             "techniques": [{"id": "T0855"}, {"id": "T0836"}], "summary": "ews pivot | write = bad", "last_seen": 1.0}
_SIEM_EVENTS = [{"domain": "OT", "src": "172.30.0.12", "dst": "172.30.0.10", "evidence": {"service": "s7comm"}}]


def test_cef_is_valid_and_roundtrips():
    use(PUMP)
    p = cef.parse(cef.incident_to_cef(_SIEM_INC, _SIEM_EVENTS))
    assert p["vendor"] == "Traboda" and p["product"] == "Kaaval" and p["severity"] == 10
    assert p["extension"]["externalId"] == "INC-9"          # SIEM correlation key
    assert p["extension"]["cs1"] == "T0855,T0836"           # ATT&CK techniques
    assert p["extension"]["msg"] == "ews pivot | write = bad"   # '|' and '=' survived escaping
    # approval CEF gives the SIEM the audit reference
    ap = {"incident_id": "INC-9", "action": "rearm_interlock", "approver": "andre",
          "decision": "approved", "gated": True, "result_ok": True, "ts": 1.0, "gating_reason": "control plane"}
    pa = cef.parse(cef.approval_to_cef(ap))
    assert pa["extension"]["externalId"] == "INC-9" and pa["extension"]["duser"] == "andre"
    assert pa["extension"]["act"] == "approved" and pa["extension"]["cs1"] == "rearm_interlock"


def test_cef_severity_mapping():
    assert [cef.cef_severity(s) for s in ("info", "low", "medium", "high", "critical")] == [0, 3, 5, 8, 10]
    assert cef.cef_severity("nonsense") == 5 and cef.cef_severity(7) == 7


def test_siem_carries_real_identity_not_pseudonymized():
    # The internal, on-prem SIEM gets REAL identity (that is its purpose) and is
    # explicitly NOT routed through the cloud pseudonymizer.
    use(PUMP)
    line = cef.incident_to_cef(_SIEM_INC, _SIEM_EVENTS)
    assert "172.30.0.10" in line and "172.30.0.12" in line
    assert "shost=ews" in line and "dhost=plc" in line
    for tok in ("PLC_", "HOST_", "GW_", "EXT_", "«UNTRUSTED"):
        assert tok not in line, f"SIEM feed must NOT be pseudonymized (found {tok})"


def test_siem_is_one_way_no_execution_path():
    import inspect
    for forbidden in ("actions", "gating", "execute_it", "execute_ot", "agents"):
        assert forbidden not in siem.__dict__ and forbidden not in cef.__dict__
    # the transport opens only client sockets — no listener / inbound primitives
    src = inspect.getsource(siem)
    for banned in (".bind(", ".listen(", ".accept(", ".recv("):
        assert banned not in src, f"SIEM transport must not {banned} — one-way out only"


def test_siem_off_by_default_and_fails_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SIEM_CONFIG_PATH", str(tmp_path / "siem.json"))
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "s.sqlite"))
    monkeypatch.setattr(siem, "_cfg_cache", None)
    siem._QUEUE.clear()
    # off unless configured -> nothing is sent
    assert siem.get_config()["enabled"] is False
    assert siem._forward(["x"], kind="t").get("skipped") is True
    # enabled but unreachable -> NO raise, queued, recorded as a failure (SOC keeps running)
    siem.set_config({"enabled": True, "host": "127.0.0.1", "port": 1, "protocol": "tcp", "timeout": 1.0})
    r = siem.forward_incident(_SIEM_INC, _SIEM_EVENTS)
    assert r["ok"] is False and r.get("queued", 0) >= 1
    conn = store.connect(); store.init(conn); rows = store.get_siem_log(conn); conn.close()
    assert rows and rows[0]["ok"] is False
    monkeypatch.setattr(siem, "_cfg_cache", None); siem._QUEUE.clear()


def test_siem_config_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SIEM_CONFIG_PATH", str(tmp_path / "siem.json"))
    monkeypatch.setattr(siem, "_cfg_cache", None)
    assert siem.set_config({"protocol": "bogus"})["protocol"] == "udp"   # invalid -> safe default
    assert siem.set_config({"protocol": "tls", "port": "6514"})["protocol"] == "tls"
    assert siem.get_config()["port"] == 6514
    monkeypatch.setattr(siem, "_cfg_cache", None)


def test_siem_tcp_roundtrip_delivers_parseable_cef(tmp_path, monkeypatch):
    import socket as _s, threading
    monkeypatch.setattr(config, "SIEM_CONFIG_PATH", str(tmp_path / "siem.json"))
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "s.sqlite"))
    monkeypatch.setattr(siem, "_cfg_cache", None); siem._QUEUE.clear()
    got = []
    srv = _s.socket(); srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    def serve():
        srv.settimeout(4); c, _ = srv.accept(); c.settimeout(2); data = b""
        try:
            while (ch := c.recv(4096)):
                data += ch
        except Exception:
            pass
        got.append(data.decode()); c.close()
    th = threading.Thread(target=serve); th.start()
    siem.set_config({"enabled": True, "host": "127.0.0.1", "port": port, "protocol": "tcp", "timeout": 3.0})
    res = siem.forward_incident(_SIEM_INC, _SIEM_EVENTS)
    th.join(5); srv.close()
    assert res["ok"] is True and got
    parsed = cef.parse(got[0])                 # the SIEM receives REAL, parseable CEF
    assert parsed["product"] == "Kaaval" and parsed["extension"]["src"] == "172.30.0.12"
    monkeypatch.setattr(siem, "_cfg_cache", None); siem._QUEUE.clear()


# --- F7: case management (workflow + chain-of-custody; NO action/gate path) ---

OP = {"name": "olivia", "role": "operator"}
APR = {"name": "andre", "role": "approver"}

_CASE_DETAIL = {"id": "INC-CW", "incident": {"id": "INC-CW", "summary": "ews pivoted to PLC; unauthorized S7 write",
                "severity": "critical", "cross_domain": True, "domains": ["IT", "OT"],
                "techniques": [{"id": "T0855"}], "first_seen": 1.0},
                "events": [{"rule": "ot.unauthorized_s7_command", "domain": "OT", "src": "172.30.0.12",
                            "dst": "172.30.0.10", "summary": "unauthorized write from ews to plc",
                            "techniques": [{"id": "T0855"}]}],
                "actions": [{"name": "rearm_interlock", "title": "Re-arm interlock", "domain": "OT",
                             "status": "approved", "requires_human_approval": True}],
                "agents": {"triage": {"summary": "cross-domain intrusion"}},
                "metrics": {"it_events": 4, "ot_events": 1, "resolved": True}}


def test_case_lifecycle_and_chain_of_custody(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cw.sqlite"))
    iid = "INC-CW"
    # derived status defaults the workflow state, override is allowed + logged
    assert casework.get(iid, "triaged")["state"] == "investigating"
    casework.assign(iid, OP, "olivia")
    casework.comment(iid, OP, "Confirmed S7 write from ews; isolating.")
    casework.transition(iid, OP, "contained", "IT containment applied")
    c = casework.close(iid, APR, "true_positive_remediated", "interlock restored")
    assert c["state"] == "closed" and c["assignee"] == "olivia"
    assert c["disposition"] == "true_positive_remediated" and c["closed_by"] == "andre"
    # the history is a chain-of-custody trail: who/what/when, verified principal
    kinds = [(h["kind"], h["actor"], h["role"]) for h in c["history"]]
    assert ("assign", "olivia", "operator") in kinds
    assert ("comment", "olivia", "operator") in kinds
    assert ("transition", "olivia", "operator") in kinds
    assert ("close", "andre", "approver") in kinds
    # reopen clears the closed disposition and is itself audited
    r = casework.reopen(iid, APR, "new evidence")
    assert r["state"] == "investigating" and r["disposition"] is None
    assert any(h["kind"] == "reopen" for h in r["history"])


def test_case_state_override_is_logged(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cw.sqlite"))
    casework.transition("INC-X", OP, "resolved", "manually marked resolved by analyst")
    c = casework.get("INC-X", "open")           # derived says open; human overrode
    assert c["state"] == "resolved" and c["state_overridden"] is True
    assert "manually marked resolved" in [h["detail"] for h in c["history"]][-1]


def test_case_management_has_no_action_or_gate_path():
    for forbidden in ("actions", "gating", "execute_it", "execute_ot"):
        assert forbidden not in casework.__dict__, f"casework must not reference {forbidden}"
        assert forbidden not in case_report.__dict__, f"case_report must not reference {forbidden}"


def test_case_report_facts_from_store_not_llm(monkeypatch):
    # The LLM only drafts prose; facts/timeline/evidence come from the store and the
    # model cannot change them.
    facts = case_report.build_facts(_CASE_DETAIL)
    assert facts["severity"] == "critical" and facts["techniques"] == ["T0855"]
    assert facts["timeline"] and any("approval" in t["label"].lower() or "Detected" in t["label"] for t in facts["timeline"])
    monkeypatch.setattr(llm, "ollama_json",
                        lambda *a, **k: ({"what_happened": "Nothing happened; all systems nominal.",
                                          "impact": "none", "response": "none"}, {"provider": "stub"}))
    n = case_report.draft_narrative(facts)
    assert n["source"].startswith("llm:")
    # even with a lying narrative, the authoritative facts are untouched
    assert case_report.build_facts(_CASE_DETAIL)["severity"] == "critical"


def test_case_report_narrative_egress_masked_in_cloud(tmp_path, monkeypatch):
    import urllib.error
    use(PUMP)
    monkeypatch.setattr(config, "LLM_CONFIG_PATH", str(tmp_path / "llm.json"))
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "e.sqlite"))
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(llm, "_cfg_cache", None)
    llm.set_config({"mode": "cloud", "provider": "openrouter", "openrouter_model": "m", "openrouter_api_key": "k"})
    captured = {}
    def cap(provider, model, key, system, user_msgs, **kw):
        captured["blob"] = system + json.dumps(user_msgs)
        raise urllib.error.URLError("stop")
    monkeypatch.setattr(egress, "_http", cap)
    case_report.draft_narrative(case_report.build_facts(_CASE_DETAIL))
    blob = captured["blob"]
    for ident in ("172.30.0.10", "172.30.0.12", "plc", "ews"):
        assert ident not in blob, f"identity '{ident}' leaked into the case-report cloud payload"
    monkeypatch.setattr(llm, "_cfg_cache", None)


def test_case_report_renders_branded_docx_and_pdf():
    facts = case_report.build_facts(_CASE_DETAIL)
    md = case_report.to_markdown(facts, case_report._fallback(facts))
    assert case_report.to_docx(md, {"report_status": "draft", "incident_id": "INC-CW"})[:2] == b"PK"
    assert case_report.to_pdf(md, {"report_status": "final", "report_by": "andre", "incident_id": "INC-CW"})[:5] == b"%PDF-"


# --- F8: executor adapter interface (HOW execution runs; gate stays in front) -

def test_executor_adapters_registered_and_honestly_labeled():
    names = {a["name"]: a for a in executors.list_adapters()}
    assert names["lab"]["kind"] == "lab" and names["lab"]["supports_ot"] is True
    assert names["firewall_rest"]["kind"] == "real-integration" and names["firewall_rest"]["supports_ot"] is False
    # defaults to the lab adapter unless the profile/config selects otherwise
    assert executors.active_it().name == "lab" and executors.active_ot().name == "lab"


def test_executor_op_mapping_is_code_derived():
    use(PUMP)
    want = {"isolate_ews_ot": ("isolate_segment", "it", False), "block_c2_egress": ("block_ip", "it", False),
            "disable_ews_account": ("disable_account", "it", False),
            "rearm_interlock": ("ot_write", "ot", True), "restore_setpoint": ("ot_write", "ot", True)}
    for name, (op, kind, gated) in want.items():
        req = actions.build_request(name, approved=False)
        assert (req.op, req.kind, req.gated) == (op, kind, gated), f"{name} mis-mapped: {req}"


def test_adapter_cannot_run_ungated_or_unapproved_action():
    """The defining F8 safety property: an adapter fails CLOSED on anything that is
    not the right, approved, gated action — re-proving invariants 1 & 2 at the
    execution layer. (The endpoint gate is separately enforced.)"""
    use(PUMP)
    lab = executors.get("lab")
    # 1) a GATED OT action cannot run on the IT/auto path
    assert actions.execute_it("rearm_interlock")["ok"] is False
    gated_req = actions.build_request("rearm_interlock", approved=False)
    assert lab.execute_it(gated_req).refused is True
    # 2) an OT write that was NOT approved is refused by the adapter (fail closed)
    r_unappr = asyncio.get_event_loop().run_until_complete(lab.execute_ot(gated_req))
    assert r_unappr.ok is False and r_unappr.refused is True
    # 3) an IT action cannot be smuggled through the OT path
    it_req = actions.build_request("isolate_ews_ot", approved=True)
    r_wrongpath = asyncio.get_event_loop().run_until_complete(lab.execute_ot(it_req))
    assert r_wrongpath.refused is True
    # 4) an unknown action never builds a request
    assert actions.build_request("delete_everything", approved=True) is None


def test_firewall_rest_real_shape_fails_closed_when_unconfigured(monkeypatch):
    use(PUMP)
    monkeypatch.setattr(config, "FIREWALL_API_URL", "")          # no appliance configured
    fw = executors.get("firewall_rest")
    res = fw.execute_it(actions.build_request("isolate_ews_ot", approved=False))
    assert res.ok is False and res.refused is True and "failing closed" in res.detail.lower()
    # the firewall/NAC adapter performs NO OT control — it fails closed there too
    otr = asyncio.get_event_loop().run_until_complete(fw.execute_ot(actions.build_request("rearm_interlock", approved=True)))
    assert otr.ok is False and otr.refused is True


def test_executor_layer_has_no_llm_path():
    # Invariant 1: nothing the LLM says reaches an adapter. The execution layer
    # imports no agents/llm/chat; the action set stays code-derived (gating).
    for mod in (actions, executors, executors.base, executors.lab, executors.firewall_rest):
        for forbidden in ("agents", "llm", "chat"):
            assert forbidden not in mod.__dict__, f"{mod.__name__} must not reference {forbidden}"
    # the gate order is unchanged: approve still needs approver, apply still operator
    assert auth.required_role("POST", "/api/actions/x/approve") == "approver"
    assert auth.required_role("POST", "/api/actions/x/apply") == "operator"


# --- adversary not pre-seeded; scope from ranges; label is a correlation conclusion ---

def test_adversary_and_c2_not_pre_declared():
    for p in (PUMP, REACTOR):
        use(p)
        ids = {a["id"] for a in profile.assets()}
        assert "attacker" not in ids and "c2" not in ids, f"{p} still declares the adversary"
        # passive name resolution returns the raw IP — discovery stays honest
        assert profile.name_for_ip("172.30.0.14") == "172.30.0.14"
        assert profile.name_for_ip("172.30.0.13") == "172.30.0.13"


def test_discovery_scope_internal_vs_external(tmp_path, monkeypatch):
    use(PUMP)
    monkeypatch.setattr(config, "INVENTORY_PATH", str(tmp_path / "inv.json"))
    logdir = tmp_path / "logs"; logdir.mkdir()
    (logdir / "conn.log").write_text(
        # in-range, undeclared plant device (SSH client) -> internal, enrollable
        json.dumps({"id.orig_h": "172.30.0.50", "id.resp_h": "172.30.0.11", "id.resp_p": 22,
                    "proto": "tcp", "orig_ip_bytes": 50, "resp_ip_bytes": 20, "ts": 1.0}) + "\n"
        # out-of-range host -> external
        + json.dumps({"id.orig_h": "203.0.113.9", "id.resp_h": "172.30.0.12", "id.resp_p": 443,
                      "proto": "tcp", "orig_ip_bytes": 50, "resp_ip_bytes": 20, "ts": 2.0}) + "\n")
    by = {a["ip"]: a for a in asset_discovery.discover(str(logdir))["assets"]}
    # a legitimate not-yet-declared plant device reads INTERNAL (not external)
    internal = by["172.30.0.50"]
    assert internal["scope"] == "internal" and internal["domain"] != "external"
    assert internal["unmanaged"] is True and internal["enrollment_candidate"] is True
    # anything outside the plant ranges is external
    ext = by["203.0.113.9"]
    assert ext["scope"] == "external" and ext["domain"] == "external"
    assert ext["enrollment_candidate"] is False


def test_monitored_ranges_is_the_source_of_truth(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INVENTORY_PATH", str(tmp_path / "inv.json"))
    inventory.set_network({"subnet": "172.30.0.0/24", "monitored_ranges": ["10.10.0.0/16"]})
    logdir = tmp_path / "logs"; logdir.mkdir()
    (logdir / "conn.log").write_text(
        json.dumps({"id.orig_h": "10.10.5.5", "id.resp_h": "172.30.0.11", "id.resp_p": 22,
                    "proto": "tcp", "orig_ip_bytes": 10, "resp_ip_bytes": 10, "ts": 1.0}) + "\n")
    by = {a["ip"]: a for a in asset_discovery.discover(str(logdir))["assets"]}
    # a host in a declared monitored range is INTERNAL even though it's outside the subnet
    assert by["10.10.5.5"]["scope"] == "internal"


def test_adversary_label_is_a_correlation_conclusion_only():
    use(PUMP)
    events = [
        {"rule": "it.external_remote_access", "src": "172.30.0.14", "dst": "ews", "domain": "IT"},
        {"rule": "it.c2_beaconing", "src": "ews", "dst": "172.30.0.13", "domain": "IT"},
        {"rule": "ot.unauthorized_s7_command", "src": "ews", "dst": "plc", "domain": "OT"},
    ]
    labels = adversary.label_hosts(events)
    assert labels.get("172.30.0.14") == "external adversary host"   # unmanaged remote-access source
    assert labels.get("172.30.0.13") == "C2 endpoint"               # unmanaged beacon destination
    assert "ews" not in labels and "plc" not in labels             # managed assets never relabeled
    # the label substitutes into narrative text...
    txt = adversary.relabel("Inbound from 172.30.0.14 → beacon to 172.30.0.13", labels)
    assert "external adversary host" in txt and "C2 endpoint" in txt and "172.30.0.14" not in txt
    # ...but discovery never carries it (asset_discovery doesn't import adversary)
    assert "adversary" not in asset_discovery.__dict__


def test_rogue_devices_derived_from_unmanaged_hosts():
    use(PUMP)
    events = [
        {"rule": "it.external_remote_access", "src": "172.30.0.14", "dst": "ews", "domain": "IT"},
        {"rule": "it.c2_beaconing", "src": "ews", "dst": "172.30.0.13", "domain": "IT"},
        {"rule": "ot.unauthorized_s7_command", "src": "ews", "dst": "plc", "domain": "OT"},
    ]
    rogues = adversary.rogue_devices(events)
    assert rogues == ["172.30.0.13", "172.30.0.14"]   # the unmanaged hosts, sorted
    assert "ews" not in rogues and "plc" not in rogues   # managed assets are never rogue


def test_rogue_devices_persist_on_the_case(tmp_path, monkeypatch):
    conn = _tmpdb(tmp_path, monkeypatch)
    c = appmain.Case("INC-ROGUE", 1.0)
    c.rogue_devices = ["172.30.0.14"]
    store.save_case(conn, c.persist_dict())
    # survives a reload (durable attribute, not a transient event)
    rows = store.load_cases(conn)
    restored = appmain.Case.from_persist(rows[0])
    assert restored.rogue_devices == ["172.30.0.14"]
    assert "rogue_devices" in restored.detail()
    conn.close()


def test_discovery_and_adversary_dont_touch_gate_authz_detection():
    # This change touches classification + narrative ONLY. Re-confirm the gate,
    # authorization, and detection-rule paths did not move.
    for mod in (adversary, asset_discovery):
        for forbidden in ("gating", "actions", "agents"):
            assert forbidden not in mod.__dict__, f"{mod.__name__} must not reference {forbidden}"
    use(PUMP)
    # authorization is unchanged (the adversary was never an allowed client anyway)
    assert profile.is_authorized_client("s7comm", "172.30.0.12") is False   # ews
    assert profile.is_authorized_client("s7comm", "172.30.0.11") is True    # gateway
    # the gate roles are unchanged
    assert auth.required_role("POST", "/api/actions/x/approve") == "approver"
