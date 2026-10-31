# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Kaaval backend — FastAPI + WebSocket orchestrator.

Streams live process state (OPC UA, ~4 Hz), runs detection/correlation over the
Zeek logs, fires the agent pipeline on the first incident, auto-executes the
reversible IT containment, and holds the OT control actions at the human gate.
Approving them issues real OPC UA writes and the plant recovers on screen.

The OT-safety gate is re-enforced here: a gated action only runs through the
explicit /approve endpoint, and only if gating.py marks it gated.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request

from fastapi import Body, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse

from . import actions, adversary, agents, asset_discovery, assets, auth, capabilities, case_report, casework, chat, compliance, compliance_render, config, detect, discovery_detect, egress, enrichment, gating, inventory, llm, playbooks, profile, rule_assist, rules_store, siem, store, telemetry, topology, zeek_stats
from .opc import OpcClient
from . import pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("kaaval")

app = FastAPI(title="Kaaval Backend", version="1.0")

# Lock browser access to an explicit origin allowlist (never "*").
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _auth(request: Request, call_next):
    """Mandatory auth + RBAC, fail-closed. Resolves the principal and attaches it to
    request.state; reads (GET/HEAD/OPTIONS) need only a viewer; every mutating request
    needs the role for its path (operator / approver for OT approve / admin). Outside
    DEV_MODE, no valid token => 401. This is what makes the approval gate, the audit
    identity, and the offline guarantee enforceable rather than honor-system."""
    principal = auth.authenticate(request)
    request.state.principal = principal
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        need = auth.required_role(request.method, request.url.path)
        if not auth.authorized(principal, need):
            code = 401 if principal is None else 403
            log.warning("auth reject %s %s (need %s, principal %s)", request.method,
                        request.url.path, need, (principal or {}).get("name"))
            return JSONResponse(
                {"ok": False, "error": "authentication required" if code == 401 else f"requires role: {need}"},
                status_code=code)
    return await call_next(request)


def _principal(request: Request) -> dict:
    # On mutating endpoints the middleware has already resolved + authorized a real
    # principal, so this returns it. The fallback is a non-privileged 'system' viewer
    # (never admin) as defence-in-depth — it is not reachable on auth-gated routes.
    return getattr(request.state, "principal", None) or {"name": "system", "role": "viewer"}


ATTACKER_BASE = config.ATTACKER_URL
ATTACKER_RUN_URL = f"{ATTACKER_BASE}/run"


# --- shared runtime state ---------------------------------------------------

class Case:
    """One correlated incident and everything the SOC tracks for it — its own
    events, agent assessment, recommended fix, gate state, and verification. A real
    SOC runs a QUEUE of these concurrently; each is triaged and remediated on its
    own. `detect_ts` is wall-clock first-observed; `attack_start` is the first
    detected Zeek event ts (honest, detection-anchored TTD)."""

    def __init__(self, inc_id: str, detect_ts: float):
        self.id = inc_id
        self.incident: dict | None = None
        self.events: list = []
        self.bundle: dict | None = None
        self.agents: dict | None = None
        self.actions: list = []
        self.last_response: dict | None = None
        self.agents_done = False
        self.agents_running = False
        self.agents_event_count = 0
        self.detect_ts = detect_ts
        self.contain_ts: float | None = None
        self.remediated_ts: float | None = None
        self.resolution: dict | None = None
        # Durable rogue-device attribute: unmanaged hosts that contributed to this
        # incident, ACCUMULATED at formation and never removed — so the rogue device
        # is still shown after the transient F1 rogue_asset alert ages out.
        self.rogue_devices: list = []
        self._last_count = -1
        self._stable_since: float | None = None

    @property
    def attack_start(self) -> float | None:
        return (self.incident or {}).get("first_seen")

    def status(self) -> str:
        if self.resolution and self.resolution.get("resolved"):
            return "resolved"
        if self.remediated_ts:
            return "remediating"
        if self.contain_ts:
            return "contained"
        if self.agents_done:
            return "triaged"
        return "open"

    def metrics(self) -> dict:
        a = self.attack_start
        ttd = (self.detect_ts - a) if (self.detect_ts and a) else None
        ttc = (self.contain_ts - a) if (self.contain_ts and a) else None
        inc = self.incident or {}
        techs = inc.get("techniques", [])
        it = len([e for e in self.events if e.get("domain") == "IT"])
        ot = len([e for e in self.events if e.get("domain") == "OT"])
        return {
            "techniques": techs, "n_techniques": len(techs), "it_events": it, "ot_events": ot,
            "time_to_detect_s": round(ttd, 1) if ttd is not None else None,
            "time_to_contain_s": round(ttc, 1) if ttc is not None else None,
            "remediated": self.remediated_ts is not None,
            "resolved": bool(self.resolution and self.resolution.get("resolved")),
            "resolution": self.resolution,
        }

    def detail(self) -> dict:
        # Narrative-layer relabel: name the unmanaged adversary/C2 hosts for DISPLAY
        # (kill-chain, event table). self.events stay honest IPs for the store/audit;
        # discovery never sees these labels.
        labels = adversary.label_hosts(self.events)

        def _disp(e):
            if not labels:
                return e
            c = dict(e)
            for k in ("src", "dst"):
                v = c.get(k)
                host = str(v).split(":")[0] if v else None
                if host and host in labels:
                    c[k] = str(v).replace(host, labels[host])
            return c

        return {"id": self.id, "incident": self.incident,
                "events": [_disp(e) for e in self.events], "host_labels": labels,
                "rogue_devices": self.rogue_devices,
                "agents": self.agents, "actions": self.actions,
                "status": self.status(), "metrics": self.metrics()}

    def persist_dict(self) -> dict:
        """The analyst-facing state worth surviving a restart (triage + gate state +
        timestamps). Events/bundle are re-derived from the logs by detection."""
        return {"id": self.id, "detect_ts": self.detect_ts, "contain_ts": self.contain_ts,
                "remediated_ts": self.remediated_ts, "agents_done": self.agents_done,
                "agents_event_count": self.agents_event_count, "agents": self.agents,
                "actions": self.actions, "last_response": self.last_response,
                "resolution": self.resolution, "rogue_devices": self.rogue_devices}

    @classmethod
    def from_persist(cls, d: dict) -> "Case":
        c = cls(d["id"], d.get("detect_ts") or 0.0)
        c.contain_ts = d.get("contain_ts")
        c.remediated_ts = d.get("remediated_ts")
        c.agents_done = bool(d.get("agents_done"))
        c.agents_event_count = d.get("agents_event_count") or 0
        c.agents = d.get("agents")
        c.actions = d.get("actions") or []
        c.last_response = d.get("last_response")
        c.resolution = d.get("resolution")
        c.rogue_devices = d.get("rogue_devices") or []
        return c


class Hub:
    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.state: dict = {}
        self.cases: dict[str, Case] = {}    # incident id -> Case (the queue)
        self.autonomy = False              # off => operator must Apply even IT actions
        self.autonomy_enabled_by = None    # admin who enabled the auto-containment policy
        self.state_ts = 0.0                # last successful OPC state read (freshness)
        self.model_warm = False
        self.ews_isolated = False          # IT containment active => manual OT writes blocked
        self._contain_checked = 0.0        # last containment probe (throttle)
        self.lock = asyncio.Lock()

    # --- queue helpers ------------------------------------------------------
    def cases_sorted(self) -> list[Case]:
        return sorted(self.cases.values(), key=lambda c: c.detect_ts or 0)

    def primary(self) -> Case | None:
        """Most-recently-detected case — what the legacy single-incident views show."""
        cs = self.cases_sorted()
        return cs[-1] if cs else None

    def case(self, inc_id: str | None) -> Case | None:
        if inc_id and inc_id in self.cases:
            return self.cases[inc_id]
        return self.primary()

    async def register(self, ws: WebSocket):
        self.clients.add(ws)
        snap = [("state", self.state), ("autonomy", {"enabled": self.autonomy}),
                ("incidents", [c.detail() for c in self.cases_sorted()])]
        p = self.primary()
        if p:
            snap += [("incident", p.incident), ("events", p.events), ("agents", p.agents),
                     ("actions", p.actions), ("scoreboard", self.scoreboard())]
        for t, payload in snap:
            if payload not in (None, [], {}):
                await ws.send_text(json.dumps({"type": t, "data": payload}))

    def unregister(self, ws: WebSocket):
        self.clients.discard(ws)

    async def broadcast(self, mtype: str, data):
        msg = json.dumps({"type": mtype, "data": data})
        for ws in list(self.clients):
            try:
                await ws.send_text(msg)
            except Exception:
                self.unregister(ws)

    async def push(self):
        """Broadcast the full queue + mirror the primary case into the legacy
        single-incident messages (so the existing SOC views keep working)."""
        await self.broadcast("incidents", [c.detail() for c in self.cases_sorted()])
        p = self.primary()
        await self.broadcast("incident", p.incident if p else None)
        await self.broadcast("events", p.events if p else [])
        await self.broadcast("agents", p.agents if p else None)
        await self.broadcast("actions", p.actions if p else [])
        await self.broadcast("scoreboard", self.scoreboard())

    def scoreboard(self) -> dict:
        p = self.primary()
        m = p.metrics() if p else {
            "techniques": [], "n_techniques": 0, "it_events": 0, "ot_events": 0,
            "time_to_detect_s": None, "time_to_contain_s": None,
            "remediated": False, "resolved": False, "resolution": None}
        m["n_incidents"] = len(self.cases)
        return m


hub = Hub()


# --- persistence helpers (P2: state survives restart; approvals are audited) --

def _save_case(case: Case) -> None:
    try:
        conn = store.connect()
        store.init(conn)
        store.save_case(conn, case.persist_dict())
        conn.close()
    except Exception:
        log.exception("failed to persist case %s", case.id)


def _record_auto_action(case: Case, action: dict, res: dict) -> None:
    """Audit an autonomy-policy auto-execution to its OWN channel — never conflated
    with the human-approval log. Only reversible IT containment reaches here."""
    try:
        conn = store.connect(); store.init(conn)
        store.add_auto_action(conn, ts=time.time(), action=action.get("name", "?"),
                              incident_id=case.id, policy="autonomy:reversible-it-containment",
                              enabled_by=hub.autonomy_enabled_by or "unknown",
                              result_ok=bool(res.get("ok")))
        conn.close()
    except Exception:
        log.exception("failed to record auto-action for %s", case.id)


def _record_approval(case: Case, action: dict, approver: str, decision: str,
                     result_ok: bool) -> None:
    try:
        conn = store.connect()
        store.init(conn)
        store.add_approval(
            conn, ts=time.time(), approver=approver or "operator",
            action=action.get("name", "?"), incident_id=case.id, decision=decision,
            gated=bool(action.get("requires_human_approval")),
            rationale=action.get("rationale", ""),
            gating_reason=action.get("gating_reason", ""), result_ok=result_ok)
        conn.close()
    except Exception:
        log.exception("failed to record approval for %s", case.id)


async def _refresh_containment(force: bool = False) -> None:
    """Probe live IT containment (throttled) and cache it on the hub, so both the
    SOC and Range surfaces can warn that the ews is isolated and manual OT writes
    will be blocked. Cheap docker exec; checked at most every ~3s."""
    now = time.time()
    if not force and (now - hub._contain_checked) < 3.0:
        return
    hub._contain_checked = now
    try:
        loop = asyncio.get_running_loop()
        st = await loop.run_in_executor(None, actions.containment_active)
        hub.ews_isolated = bool(st.get("isolated"))
    except Exception:
        log.exception("containment probe failed")


def _rehydrate_cases() -> None:
    """On boot, restore persisted case triage/gate state so a restart does not erase
    the analyst's work. Detection reconciles each against the live logs next cycle —
    a case whose telemetry is gone is dropped; one still present keeps its triage."""
    try:
        conn = store.connect()
        store.init(conn)
        rows = store.load_cases(conn)
        conn.close()
        for d in rows:
            hub.cases[d["id"]] = Case.from_persist(d)
        if rows:
            log.info("rehydrated %d case(s) from store", len(rows))
    except Exception:
        log.exception("case rehydration failed")


def _danger_bar() -> float | None:
    """The profile's danger threshold for the safety variable (UI 'burst' marker)."""
    return profile.safety().get("danger")


def _in_band(state: dict) -> bool:
    """Is the profile's safety variable back within (or below) its band? Used to
    decide containment/recovery in a scenario-agnostic way."""
    s = profile.safety()
    var, band = s.get("variable"), s.get("band") or [None, None]
    hi = band[1] if len(band) > 1 else None
    v = state.get(var)
    if v is None or hi is None:
        return False
    return v <= hi


def _status(state: dict) -> str:
    """Scenario-agnostic process status from the profile's safety descriptor:
    the danger threshold, the nominal band, and the interlock tag. No hardcoded
    plant numbers — pump and reactor both flow through this."""
    s = profile.safety()
    var = s.get("variable")
    band = s.get("band") or [None, None]
    lo = band[0] if len(band) > 0 else None
    hi = band[1] if len(band) > 1 else None
    danger = s.get("danger")
    interlock_tag = s.get("interlock_tag")
    v = state.get(var)
    if v is None:
        return "unknown"
    if danger is not None and v >= danger:
        return "burst"
    # Above the midpoint between band-high and danger, or interlock defeated:
    if hi is not None and danger is not None and v >= (hi + danger) / 2.0:
        return "danger"
    if interlock_tag and interlock_tag in state and not state.get(interlock_tag):
        return "danger"
    if (hi is not None and v > hi) or (lo is not None and v < lo):
        return "warning"
    return "ok"


# --- background loops -------------------------------------------------------

async def state_loop():
    client = OpcClient()
    while True:
        try:
            await client.connect()
            while True:
                st = await client.read_state()
                st["status"] = _status(st)
                st["burst_bar"] = _danger_bar()      # generic danger marker (per profile)
                await _refresh_containment()          # throttled; cheap when cached
                st["ews_isolated"] = hub.ews_isolated
                hub.state = st
                hub.state_ts = time.time()
                await hub.broadcast("state", st)
                await asyncio.sleep(0.25)   # ~4 Hz
        except Exception as e:
            log.warning("state_loop: OPC read failed, reconnecting (%r)", e)
            await asyncio.sleep(1.0)
            try:
                await client.disconnect()
            except Exception:
                pass


STABLE_S = 6.0   # wait for the incident to stop growing (Zeek flush) before running agents


def _case_history(incident_id: str, kind: str, detail: str, actor: str = "system", role: str = "detection"):
    """Append a durable entry to the case chain-of-custody timeline (F7)."""
    try:
        conn = store.connect(); store.init(conn)
        store.add_case_history(conn, ts=time.time(), incident_id=incident_id, actor=actor,
                               role=role, kind=kind, detail=detail)
        conn.close()
    except Exception:
        log.exception("case history write failed for %s", incident_id)


def _restore_rogue(case: "Case"):
    """Seed a (re)created case's durable rogue set from its persisted record, so a
    re-clustering drop/recreate neither loses the attribute nor re-writes its history."""
    try:
        conn = store.connect(); store.init(conn)
        row = next((c for c in store.load_cases(conn) if c["id"] == case.id), None)
        conn.close()
        if row:
            case.rogue_devices = row.get("rogue_devices") or []
    except Exception:
        log.exception("rogue restore failed for %s", case.id)


def _capture_rogue_devices(case: "Case"):
    """Accumulate the UNMANAGED hosts implicated in this case as a durable incident
    attribute (read-only/derived). Recorded ONCE per device — the F1 rogue_asset alert
    itself stays transient (fires once, dedupes); this just remembers what it found so
    the incident still shows the rogue device after that alert ages out."""
    new = [r for r in adversary.rogue_devices(case.events) if r not in case.rogue_devices]
    if not new:
        return
    case.rogue_devices.extend(new)
    for ip in new:
        _case_history(case.id, "rogue",
                      f"rogue device {ip} involved — unmanaged host on the monitored segment, "
                      "not in the asset inventory (flagged by rogue-host detection at formation)")
    _save_case(case)


async def detection_loop():
    loop = asyncio.get_running_loop()
    while True:
        try:
            await loop.run_in_executor(None, detect.run_detection)
            bundles = await loop.run_in_executor(None, pipeline.all_incident_bundles)
            present = {b["incident"]["id"] for b in bundles}
            # Drop cases whose incident no longer exists (logs cleared / re-clustered).
            for cid in list(hub.cases):
                if cid not in present:
                    del hub.cases[cid]
            now = time.time()
            for b in bundles:
                cid = b["incident"]["id"]
                case = hub.cases.get(cid)
                if case is None:
                    case = Case(cid, now)
                    _restore_rogue(case)            # re-clustering must not lose the durable set
                    hub.cases[cid] = case
                case.incident, case.events, case.bundle = b["incident"], b["events"], b
                _capture_rogue_devices(case)        # durable rogue-device attribute
                n = len(b["events"])
                if n != case._last_count:
                    case._last_count, case._stable_since = n, now
                # Triage each case once it settles; re-run only if more stages flush
                # in AND nothing has been actioned yet (never clobber operator state).
                settled = case._stable_since and (now - case._stable_since >= STABLE_S)
                untouched = all(a.get("status", "pending") == "pending" for a in case.actions)
                grew = case.agents_done and n > case.agents_event_count and untouched
                if settled and not case.agents_running and (not case.agents_done or grew):
                    await run_agents(case)
                elif case.agents_done:
                    rebuilt = _rebuild_actions(case)
                    if [a["name"] for a in rebuilt] != [a["name"] for a in case.actions]:
                        case.actions = rebuilt
            await hub.push()
        except Exception:
            log.exception("detection_loop: cycle failed")
        await asyncio.sleep(2.0)


async def run_agents(case: Case):
    case.agents_running = True
    case.agents_event_count = len(case.events)       # what this analysis covered
    loop = asyncio.get_running_loop()
    bundle = case.bundle or {"incident": case.incident, "events": case.events}

    # Stream each agent's result as it completes so the cards fill progressively.
    result: dict = {"triage": None, "investigation": None, "response": None}
    for name, fn in (("triage", agents.triage),
                     ("investigation", agents.investigate),
                     ("response", agents.respond)):
        result[name] = await loop.run_in_executor(None, fn, bundle)
        case.agents = dict(result)
        await hub.push()

    # AUTONOMY POLICY (explicit, admin-enabled, separately audited): only reversible
    # IT containment may auto-execute, and ONLY when an admin has enabled autonomy.
    # Each such action is recorded to the auto_actions audit channel (NOT the human-
    # approval log). OT/control-plane actions are NEVER auto-executed — they always
    # require human approval through /api/actions/{name}/approve (gating.is_gated).
    case.last_response = result["response"]
    case.actions = []
    for a in result["response"]["actions"]:
        item = {**a, "status": "pending"}
        if a.get("auto_executable") and not gating.is_gated_name(a["name"]) and hub.autonomy:
            res = await loop.run_in_executor(None, actions.execute_it, a["name"])
            item["status"] = "executed" if res.get("ok") else "failed"
            item["result"] = res
            _record_auto_action(case, a, res)
        case.actions.append(item)
    case.agents_done = True
    case.agents_running = False
    _save_case(case)                 # triage survives a restart
    await hub.push()
    # One-way SIEM forward of the correlated incident (best-effort; never blocks).
    if siem.get_config().get("enabled") and not getattr(case, "_siem_sent", False):
        setattr(case, "_siem_sent", True)
        try:
            await loop.run_in_executor(None, siem.forward_incident, case.incident, case.events)
        except Exception:
            log.exception("SIEM incident forward failed for %s", case.id)


def _rebuild_actions(case: Case) -> list:
    """Recompute a case's recommended-action set from its CURRENT events (preserving
    any apply/approve status), so a late stage adds its action without re-running the
    agents. Pure/no LLM."""
    relevant = gating.relevant_actions(case.bundle or {"events": case.events})
    prev = {a["name"]: a for a in case.actions}
    resp = {a["name"]: a for a in (case.last_response or {}).get("actions", [])}
    out = []
    for name in relevant:
        base = prev.get(name) or resp.get(name) or {}
        stamped = gating.apply([{ "name": name,
                                  "rationale": base.get("rationale", (gating.spec(name) or {}).get("rationale", "")),
                                  "gating_reason": base.get("gating_reason", "")}])[0]
        stamped["status"] = base.get("status", "pending")
        for k in ("result", "verified", "verify_detail"):
            if k in base:
                stamped[k] = base[k]
        out.append(stamped)
    return out


# --- REST -------------------------------------------------------------------

@app.get("/api/state")
def get_state():
    return hub.state


@app.get("/api/incident")
def get_incident():
    """Back-compat: the primary (most-recent) case, single-incident shape."""
    p = hub.primary()
    if not p:
        return {"incident": None, "agents": None, "actions": [], "scoreboard": hub.scoreboard()}
    return {"incident": p.incident, "agents": p.agents, "actions": p.actions,
            "scoreboard": hub.scoreboard()}


@app.get("/api/incidents")
def get_incidents():
    """The full SOC incident QUEUE — every correlated incident with its own triage,
    recommended fix, gate state, and metrics. Each is remediated independently."""
    return {"incidents": [c.detail() for c in hub.cases_sorted()]}


@app.get("/api/scoreboard")
def get_scoreboard():
    return hub.scoreboard()


def _range_disabled():
    """The range/attack affordance is a LAB tool that issues real OT writes. It is
    admin-gated (RBAC) AND can be compiled out of a production build (KAAVAL_RANGE=0)."""
    if not config.RANGE_ENABLED:
        return JSONResponse({"ok": False, "error": "range/attack affordance disabled in this build"},
                            status_code=404)
    return None


def _post_attacker(path: str) -> dict:
    req = urllib.request.Request(f"{ATTACKER_BASE}{path}", data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


@app.post("/api/attack/run")
async def attack_run():
    if (d := _range_disabled()):
        return d
    # The click only kicks off the attacker; incidents form from detected telemetry.
    # We do NOT clear existing cases — a new campaign forms its own incident in the
    # queue. Record a campaign boundary so this launch correlates as its own incident
    # even though it transits the same pivot as any prior one.
    detect.record_campaign_boundary()
    loop = asyncio.get_running_loop()
    try:
        res = await loop.run_in_executor(None, _post_attacker, "/run")
        return {"ok": res.get("ok", True), "stages": res.get("stages", [])}
    except Exception as e:
        return JSONResponse({"ok": False, "error": repr(e)}, status_code=502)


@app.get("/api/attack/scenarios")
async def attack_scenarios():
    """The catalog of launchable attack TYPES — each forms its own incident."""
    loop = asyncio.get_running_loop()
    try:
        def _get():
            with urllib.request.urlopen(f"{ATTACKER_BASE}/scenarios", timeout=10) as r:
                return json.loads(r.read().decode())
        return await loop.run_in_executor(None, _get)
    except Exception as e:
        return JSONResponse({"scenarios": [], "error": repr(e)}, status_code=502)


@app.post("/api/attack/scenario/{name}")
async def attack_scenario(name: str):
    """Launch one named attack type as its OWN campaign (own incident in the queue)."""
    if (d := _range_disabled()):
        return d
    detect.record_campaign_boundary()
    loop = asyncio.get_running_loop()
    try:
        res = await loop.run_in_executor(None, _post_attacker, f"/scenario/{name}")
        return {"ok": res.get("ok", True), "scenario": name, "stages": res.get("stages", [])}
    except Exception as e:
        return JSONResponse({"ok": False, "error": repr(e)}, status_code=502)


@app.get("/api/assets")
def get_assets():
    return {"assets": assets.list_assets()}


@app.post("/api/inventory/assets")
def add_inventory_asset(asset: dict = Body(...)):
    """Add/update a managed asset (enriches the inventory + network map). Detection
    authorization stays profile-driven — a new host is never auto-trusted."""
    try:
        rec = inventory.add_asset(asset)
        return {"ok": True, "asset": rec, "assets": assets.list_assets()}
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.delete("/api/inventory/assets/{asset_id}")
def delete_inventory_asset(asset_id: str):
    return {"ok": inventory.delete_asset(asset_id), "assets": assets.list_assets()}


@app.get("/api/inventory/network")
def get_network():
    return inventory.network()


@app.put("/api/inventory/network")
def set_network(patch: dict = Body(...)):
    return {"ok": True, "network": inventory.set_network(patch)}


@app.get("/api/autonomy")
def get_autonomy():
    return {"enabled": hub.autonomy}


@app.post("/api/autonomy")
async def set_autonomy(request: Request, body: dict = Body(...)):
    # Admin-only (RBAC). Records WHO enabled the auto-containment policy so every
    # later auto-action in the auto_actions log attributes to a real admin.
    enabled = bool(body.get("enabled"))
    who = _principal(request)["name"]
    hub.autonomy = enabled
    hub.autonomy_enabled_by = who if enabled else None
    log.info("autonomy policy %s by %s", "ENABLED" if enabled else "disabled", who)
    await hub.broadcast("autonomy", {"enabled": hub.autonomy, "enabled_by": hub.autonomy_enabled_by})
    return {"enabled": hub.autonomy, "enabled_by": hub.autonomy_enabled_by}


@app.post("/api/attack/stage/{name}")
async def attack_stage(name: str):
    if (d := _range_disabled()):
        return d
    loop = asyncio.get_running_loop()

    def _launch():
        req = urllib.request.Request(f"{ATTACKER_BASE}/stage/{name}", data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read().decode())
    try:
        return await loop.run_in_executor(None, _launch)
    except Exception as e:
        return JSONResponse({"ok": False, "error": repr(e)}, status_code=502)


@app.post("/api/range/malicious")
async def range_malicious(body: dict = Body(...)):
    if (d := _range_disabled()):
        return d
    op = body.get("op", "setpoint")
    value = body.get("value")
    detect.record_campaign_boundary()      # each manual tamper is its own campaign
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, actions.range_malicious, op, value)
    return res


@app.post("/api/range/legitimate")
async def range_legitimate(body: dict = Body(...)):
    if (d := _range_disabled()):
        return d
    value = body.get("value", 50)
    return await actions.range_legitimate_setpoint(value)


def _stamp(case: Case, name: str, status: str, res: dict, v: dict):
    for a in case.actions:
        if a["name"] == name:
            a["status"] = status if res.get("ok") else "failed"
            a["result"] = res
            a["verified"] = v["ok"]
            a["verify_detail"] = v["detail"]
    _save_case(case)                 # action/gate state survives a restart


@app.post("/api/actions/{name}/apply")
async def apply_action(request: Request, name: str, incident_id: str | None = None):
    # Runs ONLY non-gated (reversible IT) actions, scoped to one case's fix.
    if gating.spec(name) is None or gating.is_gated_name(name):
        return JSONResponse({"ok": False, "error": f"{name} is not an auto-applicable IT action"},
                            status_code=400)
    case = hub.case(incident_id)
    if case is None:
        return JSONResponse({"ok": False, "error": "no such incident"}, status_code=404)
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, actions.execute_it, name)
    v = await actions.verify(name) if res.get("ok") else {"ok": False, "detail": "not executed"}
    _stamp(case, name, "executed", res, v)
    act = next((a for a in case.actions if a["name"] == name), {"name": name})
    _record_approval(case, act, _principal(request)["name"], "applied", bool(res.get("ok")))
    await _refresh_containment(force=True)     # reflect new isolation state immediately
    await hub.push()
    return {"ok": res.get("ok"), "action": name, "incident_id": case.id, "result": res, "verified": v}


@app.post("/api/actions/{name}/approve")
async def approve(request: Request, name: str, incident_id: str | None = None):
    # Server-side gate: only gated (control/process-affecting) actions go through approval.
    # RBAC already required the `approver` role to reach here (separation of duties).
    if gating.spec(name) is None or not gating.is_gated_name(name):
        return JSONResponse({"ok": False, "error": f"{name} is not a gated action"}, status_code=400)
    case = hub.case(incident_id)
    if case is None:
        return JSONResponse({"ok": False, "error": "no such incident"}, status_code=404)
    principal = _principal(request)
    res = await actions.execute_ot(name)
    v = await actions.verify(name) if res.get("ok") else {"ok": False, "detail": "not executed"}
    _stamp(case, name, "approved", res, v)
    # Immutable audit: the VERIFIED approver (not a client-supplied string).
    act = next((a for a in case.actions if a["name"] == name), {"name": name})
    _record_approval(case, act, principal["name"], "approved", bool(res.get("ok")))
    log.info("OT action approved: %s on %s by %s(%s) -> ok=%s",
             name, case.id, principal["name"], principal["role"], res.get("ok"))
    # One-way SIEM forward of the approval audit record (fire-and-forget; the gate
    # response never waits on or depends on the SIEM being reachable).
    if siem.get_config().get("enabled"):
        ap = {"incident_id": case.id, "action": name, "approver": principal["name"],
              "decision": "approved", "gated": True, "result_ok": bool(res.get("ok")),
              "ts": time.time(), "gating_reason": act.get("gating_reason", ""),
              "rationale": act.get("rationale", "")}
        asyncio.get_running_loop().run_in_executor(None, siem.forward_approval, ap)
    await hub.push()

    # This case is contained once ITS gated OT actions are approved + plant in band.
    ot_in_case = [a for a in case.actions if a["name"] in set(gating.ot_action_names())]
    ot_done = ot_in_case and all(a["status"] == "approved" for a in ot_in_case)
    if ot_done and case.contain_ts is None:
        for _ in range(40):                       # wait up to ~10s for recovery
            if _in_band(hub.state):
                break
            await asyncio.sleep(0.25)
        case.contain_ts = time.time()
        # Mark the remediation moment and kick off fresh-window verification for THIS
        # case: "resolved" comes from detection going quiet on telemetry gathered
        # AFTER this point, not from re-reading the historical logs.
        case.remediated_ts = time.time()
        _save_case(case)
        await hub.push()
        asyncio.create_task(verify_resolution(case, config.RESOLUTION_SETTLE_S))
    return {"ok": res.get("ok"), "action": name, "incident_id": case.id, "result": res}


async def verify_resolution(case: Case, settle_s: float) -> dict:
    """Wait for Zeek to flush a fresh window, then run the rule engine over ONLY
    post-remediation telemetry. Resolved == no triggering condition fires on fresh
    data (the threat actually stopped), independent of the historical attack logs."""
    if case.remediated_ts is None:
        return {"resolved": False, "detail": "no remediation timestamp"}
    loop = asyncio.get_running_loop()
    await asyncio.sleep(max(0.0, settle_s))
    since = case.remediated_ts
    fresh = await loop.run_in_executor(None, detect.fresh_events, since)
    offending = sorted({e.rule for e in fresh})
    case.resolution = {
        "resolved": len(fresh) == 0,
        "fresh_event_count": len(fresh),
        "offending_rules": offending,
        "window_since": since,
        "settle_s": settle_s,
        "checked_at": time.time(),
    }
    _save_case(case)
    await hub.push()
    return case.resolution


@app.get("/api/approvals")
def get_approvals(incident_id: str | None = None):
    """The immutable approval/decision audit trail — who approved which control
    action, when, and why it was gated. Scoped to one incident if given."""
    try:
        conn = store.connect()
        store.init(conn)
        rows = store.get_approvals(conn, incident_id)
        conn.close()
        return {"approvals": rows}
    except Exception:
        log.exception("failed to read approvals")
        return {"approvals": []}


@app.get("/api/whoami")
def whoami(request: Request):
    """The authenticated principal + role, so the UI can show/hide controls. Reads
    are open (viewer); an anonymous caller is reported as such (NOT admin). In
    DEV_MODE with no tokens provisioned this is the implicit local admin."""
    p = getattr(request.state, "principal", None)
    if p is None:
        return {"name": "anonymous", "role": "viewer", "authenticated": False,
                "dev": False, "can": {"approve": False, "admin": False}}
    return {"name": p["name"], "role": p["role"], "authenticated": True, "dev": bool(p.get("dev")),
            "can": {"approve": auth.rank(p["role"]) >= auth.rank("approver"),
                    "admin": auth.rank(p["role"]) >= auth.rank("admin")}}


@app.get("/api/egress")
def get_egress():
    """Immutable cloud-egress audit — every outbound LLM call (provider/model/bytes/
    incident/principal). Proves what left the box when mode=cloud."""
    try:
        conn = store.connect(); store.init(conn)
        rows = store.get_egress(conn); conn.close()
        return {"egress": rows, "mode": llm.mode()}
    except Exception:
        log.exception("failed to read egress log")
        return {"egress": [], "mode": llm.mode()}


@app.get("/api/auto-actions")
def get_auto_actions():
    """The separate audit channel for autonomy-policy auto-containment actions."""
    try:
        conn = store.connect(); store.init(conn)
        rows = store.get_auto_actions(conn); conn.close()
        return {"auto_actions": rows}
    except Exception:
        return {"auto_actions": []}


@app.get("/api/resolution")
def get_resolution(incident_id: str | None = None):
    case = hub.case(incident_id)
    return (case.resolution if case and case.resolution
            else {"resolved": None, "detail": "no remediation yet"})


@app.post("/api/verify/fresh")
async def verify_fresh(incident_id: str | None = None):
    """On-demand re-check: is the threat still active on telemetry gathered since
    this case's remediation? Re-evaluates the fresh window (short settle)."""
    case = hub.case(incident_id)
    if case is None or case.remediated_ts is None:
        return JSONResponse({"ok": False, "error": "nothing remediated yet"}, status_code=400)
    return await verify_resolution(case, 2.0)


@app.post("/api/reset")
async def reset():
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, actions.reset_plant)
    hub.cases.clear()                       # clear the whole in-memory queue
    detect.clear_boundaries()               # fresh campaign segmentation

    def _clear():
        conn = store.connect(); store.init(conn)
        store.clear_cases(conn)             # drop persisted cases (audit log kept)
        store.clear_discovery_baseline(conn)  # re-baseline first-seen detection
        conn.close()
    await loop.run_in_executor(None, _clear)
    hub.ews_isolated = False                # reset flushes IT containment
    await _refresh_containment(force=True)
    await hub.push()
    return {"ok": True}


# --- R1: capabilities, rules CRUD, telemetry, chat ------------------------

@app.get("/api/capabilities")
def get_capabilities():
    return capabilities.capabilities()


@app.get("/api/llm")
def get_llm():
    """Active LLM provider/model + options (never returns the API key)."""
    return llm.status()


@app.post("/api/llm")
async def set_llm(body: dict = Body(...)):
    """Switch provider (local Ollama / Claude API), model, or set the API key.
    Selecting 'anthropic' sends incident data off-box — the UI warns about this."""
    cfg = llm.set_config(body)
    s = llm.status()
    # Verify the active provider with a cheap call so the UI can show the REAL error
    # (bad key, no credit, no network) instead of a silent failure.
    test = await asyncio.get_running_loop().run_in_executor(None, llm.test_connection)
    await hub.broadcast("llm", s)
    return {"ok": True, "status": s, "test": test,
            "saved": {k: cfg[k] for k in cfg if k not in llm._SECRET_KEYS}}


@app.get("/api/llm/test")
async def test_llm():
    return await asyncio.get_running_loop().run_in_executor(None, llm.test_connection)


@app.get("/api/profile")
def get_profile():
    """The active deployment profile's identity + safety descriptor + process-view
    hint, so the UI renders the right plant for ANY profile (not just the pump)."""
    return {
        "name": profile.name(),
        "safety": profile.safety(),
        "process_view": profile.process_view(),
        "assets": assets.list_assets(),
    }


@app.get("/api/telemetry/recent")
def get_telemetry_recent():
    return {"logs": telemetry.recent()}


@app.get("/api/discovery")
def get_discovery():
    """Passive asset discovery: the inventory derived from observed Zeek traffic,
    fingerprinted + classified, with undeclared hosts flagged UNMANAGED (rogue)."""
    try:
        return asset_discovery.discover()
    except Exception:
        log.exception("asset discovery failed")
        return JSONResponse({"assets": [], "summary": {}, "error": "discovery unavailable"}, status_code=500)


@app.get("/api/zeek/overview")
def get_zeek_overview():
    """Protocol-aware Zeek analytics: conversations, edges, DNS/TLS/SSH, and the OT
    protocol breakdown (S7comm / OPC UA) with authorization flagged from the profile."""
    try:
        return zeek_stats.overview()
    except Exception:
        log.exception("zeek overview failed")
        return JSONResponse({"error": "zeek analytics unavailable"}, status_code=500)


def _bundle_for(incident_id: str | None) -> tuple[object, dict]:
    case = hub.case(incident_id)
    if case is None:
        return None, {}
    return case, (case.bundle or {"incident": case.incident, "events": case.events})


_PLAYBOOK_PICK_SCHEMA = {"type": "object",
                        "properties": {"playbook_id": {"type": "string"}, "why": {"type": "string"}},
                        "required": ["playbook_id"]}


def _llm_pick_playbook(candidate_metas: list[dict], bundle: dict, incident_id: str | None) -> dict:
    """The LLM may SUGGEST which of the code-matched playbooks fits best. It can only
    choose among candidates supplied here — it cannot invent a playbook or an action,
    and its pick triggers NOTHING (resolve still gates every step). Falls back to the
    first code candidate."""
    fallback = {"recommended": candidate_metas[0]["id"], "recommended_source": "code", "why": ""}
    if len(candidate_metas) < 2:
        return fallback
    ids = {m["id"] for m in candidate_metas}
    system = ("You help an OT-SOC analyst pick the single most relevant response PLAYBOOK "
              "for an incident. Choose ONLY from the candidate ids provided; do not invent one. "
              "Your choice is a SUGGESTION the analyst may accept — it does not execute anything. "
              "Reply JSON {\"playbook_id\": \"<one of the candidate ids>\", \"why\": \"<one sentence>\"}.")
    payload = {"candidates": candidate_metas,
               "incident": {"summary": (bundle.get("incident") or {}).get("summary"),
                            "techniques": [t.get("id") if isinstance(t, dict) else t
                                           for t in (bundle.get("incident") or {}).get("techniques") or []]}}
    try:
        obj, _ = llm.ollama_json(system, json.dumps(payload), _PLAYBOOK_PICK_SCHEMA,
                                 incident_id=incident_id, principal="playbook-suggest", purpose="playbook-select")
    except Exception:
        obj = None
    if obj and obj.get("playbook_id") in ids:
        return {"recommended": obj["playbook_id"], "recommended_source": "llm", "why": obj.get("why", "")}
    return fallback


# --- case management (workflow over existing incidents; NO action/gate path) ---

@app.get("/api/cases/{incident_id}")
def case_get(incident_id: str):
    """Merged case view: the detection-derived incident + the workflow layer
    (assignee, state, disposition) + the chain-of-custody history."""
    case = hub.case(incident_id)
    derived = case.status() if case else None
    cw = casework.get(incident_id, derived)
    return {"incident": case.detail() if case else None, "derived_status": derived, "case": cw}


@app.post("/api/cases/{incident_id}/assign")
def case_assign(request: Request, incident_id: str, body: dict = Body(default={})):
    return casework.assign(incident_id, _principal(request), (body or {}).get("assignee") or "")


@app.post("/api/cases/{incident_id}/comment")
def case_comment(request: Request, incident_id: str, body: dict = Body(default={})):
    try:
        return casework.comment(incident_id, _principal(request), (body or {}).get("text", ""))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.post("/api/cases/{incident_id}/transition")
def case_transition(request: Request, incident_id: str, body: dict = Body(default={})):
    try:
        return casework.transition(incident_id, _principal(request),
                                   (body or {}).get("state", ""), (body or {}).get("reason"))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.post("/api/cases/{incident_id}/close")
def case_close(request: Request, incident_id: str, body: dict = Body(default={})):
    return casework.close(incident_id, _principal(request),
                          (body or {}).get("disposition") or "true_positive_remediated", (body or {}).get("reason"))


@app.post("/api/cases/{incident_id}/reopen")
def case_reopen(request: Request, incident_id: str, body: dict = Body(default={})):
    return casework.reopen(incident_id, _principal(request), (body or {}).get("reason"))


@app.post("/api/cases/{incident_id}/report/draft")
async def case_report_draft(request: Request, incident_id: str):
    """Generate an AI-drafted report: facts/timeline/evidence from the store, prose
    from the LLM (egress-routed + pseudonymized in cloud mode). Saved as a DRAFT."""
    case = hub.case(incident_id)
    if case is None:
        return JSONResponse({"error": "no such incident"}, status_code=404)
    loop = asyncio.get_running_loop()
    facts = case_report.build_facts(case.detail())
    narrative = await loop.run_in_executor(None, case_report.draft_narrative, facts)
    md = case_report.to_markdown(facts, narrative)
    cw = casework.save_report(incident_id, _principal(request), md, ai_drafted=True)
    return {"markdown": md, "narrative_source": narrative.get("source"), "case": cw}


@app.put("/api/cases/{incident_id}/report")
def case_report_save(request: Request, incident_id: str, body: dict = Body(...)):
    """Save the human-edited report draft."""
    return {"case": casework.save_report(incident_id, _principal(request), body.get("markdown", ""), ai_drafted=False)}


@app.post("/api/cases/{incident_id}/report/signoff")
def case_report_signoff(request: Request, incident_id: str):
    try:
        return {"case": casework.signoff_report(incident_id, _principal(request))}
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.get("/api/cases/{incident_id}/report")
def case_report_get(incident_id: str):
    return casework.get_report(incident_id)


@app.get("/api/cases/{incident_id}/report.docx")
def case_report_docx(incident_id: str):
    r = casework.get_report(incident_id)
    if not r.get("markdown"):
        return JSONResponse({"error": "no report; generate a draft first"}, status_code=404)
    meta = {**r, "incident_id": incident_id, "report_status": r.get("status")}
    data = case_report.to_docx(r["markdown"], meta)
    return Response(content=data, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": f'attachment; filename="kaaval-incident-{incident_id}.docx"'})


@app.get("/api/cases/{incident_id}/report.pdf")
def case_report_pdf(incident_id: str):
    r = casework.get_report(incident_id)
    if not r.get("markdown"):
        return JSONResponse({"error": "no report; generate a draft first"}, status_code=404)
    meta = {**r, "incident_id": incident_id, "report_status": r.get("status")}
    data = case_report.to_pdf(r["markdown"], meta)
    return Response(content=data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="kaaval-incident-{incident_id}.pdf"'})


@app.get("/api/executors")
def executors_status():
    """Active executor adapters (IT + OT) and the catalog of available adapters,
    each labeled lab vs real-integration. Selecting an adapter changes HOW an
    approved action runs — never whether/when (the gate stays in front)."""
    from . import executors as _ex
    return _ex.status()


@app.get("/api/siem")
def siem_status():
    """SIEM/CEF forwarding configuration + last-send status + queue depth."""
    return siem.status()


@app.put("/api/siem")
def siem_set(patch: dict = Body(...)):
    """Admin: configure the SIEM target (host/port/protocol udp|tcp|tls, facility,
    TLS verification). Forwarding stays OFF until enabled with a host set."""
    return siem.set_config(patch)


@app.post("/api/siem/test")
def siem_test():
    """Admin: send a single CEF heartbeat to validate connectivity/transport."""
    return siem.test_connection()


@app.get("/api/siem/preview")
def siem_preview(incident: str | None = None):
    """Preview the exact CEF + syslog line for an incident WITHOUT sending. Read-only.
    Carries real asset identity by design (internal, on-prem SIEM destination)."""
    case, bundle = _bundle_for(incident)
    if case is None:
        return JSONResponse({"error": "no incident"}, status_code=404)
    return siem.preview_incident(case.incident, case.events)


@app.post("/api/siem/forward")
async def siem_forward(incident: str | None = None):
    """Admin: forward an existing incident to the SIEM now. Read-only-derived — emits
    a representation of an incident that already exists; creates/triggers nothing."""
    case, bundle = _bundle_for(incident)
    if case is None:
        return JSONResponse({"error": "no incident"}, status_code=404)
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, siem.forward_incident, case.incident, case.events)
    return res


@app.get("/api/siem/log")
def siem_log():
    conn = store.connect(); store.init(conn)
    rows = store.get_siem_log(conn); conn.close()
    return {"events": rows}


@app.get("/api/playbooks")
def list_playbooks():
    """Versioned, profile-bound response playbooks available for the active profile."""
    return {"profile": profile.name(), "playbooks": playbooks.list_playbooks()}


@app.get("/api/playbooks/suggest")
def suggest_playbooks(incident: str | None = None):
    """Code-matched playbook candidates for an incident, each fully RESOLVED (steps
    with the authoritative gate decision). The LLM may recommend one of the candidates;
    that recommendation is a suggestion and executes nothing."""
    case, bundle = _bundle_for(incident)
    if case is None:
        return {"incident": None, "candidates": [], "recommended": None, "recommended_source": "code"}
    cand_ids = playbooks.match(bundle)
    resolved = [r for cid in cand_ids if (r := playbooks.resolve(cid, bundle))]
    pick = _llm_pick_playbook([playbooks._meta(playbooks._find(c)["playbook"]) for c in cand_ids],
                              bundle, case.id) if cand_ids else {"recommended": None, "recommended_source": "code", "why": ""}
    return {"incident": case.id, "candidates": resolved, **pick}


@app.get("/api/playbooks/{pb_id}")
def get_playbook(pb_id: str, incident: str | None = None):
    """Resolve one playbook against an incident: ordered steps, each action stamped
    with the code-derived gate decision (never the YAML). Read-only — proposes only."""
    _, bundle = _bundle_for(incident)
    r = playbooks.resolve(pb_id, bundle)
    if r is None:
        return JSONResponse({"error": f"unknown playbook '{pb_id}'"}, status_code=404)
    return r


@app.get("/api/topology")
def get_topology():
    """Inferred Purdue-model topology from real Zeek flows + the asset inventory.
    Zones come from the same source detection/authz use; boundary violations are
    judged by the same authorization function (a red edge IS a real finding).
    Read-only; no egress, no LLM, no action path."""
    try:
        return topology.graph()
    except Exception:
        log.exception("topology inference failed")
        return JSONResponse({"nodes": [], "edges": [], "findings": [], "error": "topology unavailable"}, status_code=500)


@app.get("/api/enrichment")
def get_enrichment():
    """Per-asset enrichment + CVE posture. Asset->CPE resolves locally; only the CPE
    is sent to NVD (cloud) or matched against the offline snapshot (local). The
    asset<->CPE<->CVE join is reassembled locally. CVE data is informational only —
    it never triggers an action or changes a gating decision."""
    try:
        return enrichment.enrich(ts=time.time())
    except Exception:
        log.exception("asset enrichment failed")
        return JSONResponse({"assets": [], "summary": {}, "error": "enrichment unavailable"}, status_code=500)


@app.get("/api/compliance/frameworks")
def compliance_frameworks():
    """Versioned framework catalog (IEC 62443-3-3, NIST SP 800-82 Rev 3, CEA+NCIIPC)."""
    return {"frameworks": compliance.list_frameworks()}


def _build_report(framework_id: str, with_narrative: bool = True) -> dict:
    """Deterministic assessment + (optional) executive prose. Status is always
    code-derived from store evidence; the LLM only drafts the summary paragraph."""
    report = compliance.assess(framework_id, generated_ts=time.time())
    if "error" in report:
        return report
    report["narrative"] = compliance.narrative(report) if with_narrative else {
        "text": compliance._fallback_narrative(report), "source": "deterministic-fallback"}
    return report


@app.get("/api/compliance/report")
def compliance_report(framework: str, narrative: int = 1):
    report = _build_report(framework, with_narrative=bool(narrative))
    if "error" in report:
        return JSONResponse(report, status_code=404)
    return report


@app.get("/api/compliance/report.docx")
def compliance_report_docx(framework: str, narrative: int = 1):
    report = _build_report(framework, with_narrative=bool(narrative))
    if "error" in report:
        return JSONResponse(report, status_code=404)
    data = compliance_render.to_docx(report, report["narrative"]["text"])
    fn = f"kaaval-compliance-{framework}.docx"
    return Response(content=data,
                    media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": f'attachment; filename="{fn}"'})


@app.get("/api/compliance/report.pdf")
def compliance_report_pdf(framework: str, narrative: int = 1):
    report = _build_report(framework, with_narrative=bool(narrative))
    if "error" in report:
        return JSONResponse(report, status_code=404)
    data = compliance_render.to_pdf(report, report["narrative"]["text"])
    fn = f"kaaval-compliance-{framework}.pdf"
    return Response(content=data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fn}"'})


@app.get("/api/rules")
def list_rules():
    return {"rules": rules_store.list_rules()}


@app.post("/api/rules")
def create_rule(rule: dict = Body(...)):
    try:
        return rules_store.create_rule(rule)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.post("/api/rules/assist")
async def assist_rule(body: dict = Body(...)):
    """LLM-assisted rule authoring: propose a grounded rule from a plain-language
    intent. Returns a proposal only — the analyst reviews/edits and saves it via
    POST /api/rules. Nothing is activated here."""
    intent = (body.get("intent") or "").strip()
    if not intent:
        return JSONResponse({"ok": False, "error": "intent is required"}, status_code=400)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, rule_assist.propose, intent, body.get("sample"))


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: str, patch: dict = Body(...)):
    try:
        return rules_store.update_rule(rule_id, patch)
    except KeyError:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.post("/api/rules/{rule_id}/toggle")
def toggle_rule(rule_id: str):
    try:
        return rules_store.toggle_rule(rule_id)
    except KeyError:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str):
    try:
        rules_store.delete_rule(rule_id)
        return {"ok": True}
    except KeyError:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.post("/api/chat")
async def chat_endpoint(body: dict = Body(...)):
    message = body.get("message", "")
    incident_id = body.get("incident_id")
    history = body.get("history") or []
    plain = body.get("plain", True)     # plain-language (non-technical) answers by default
    # Pass the product's last-collected process snapshot (read-plane only); the
    # chat must never open a live device connection (REDESIGN D1).
    return StreamingResponse(chat.chat_sse(message, incident_id, history, dict(hub.state or {}), plain=plain),
                             media_type="text/event-stream")


@app.websocket("/ws/telemetry")
async def ws_telemetry(websocket: WebSocket):
    await websocket.accept()
    stop = asyncio.Event()
    try:
        async for rec in telemetry.tail(stop):
            await websocket.send_text(json.dumps({"type": "log", "data": rec}))
    except WebSocketDisconnect:
        stop.set()
    except Exception:
        stop.set()


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    await hub.register(websocket)
    try:
        while True:
            await websocket.receive_text()   # keepalive; client doesn't send commands
    except WebSocketDisconnect:
        hub.unregister(websocket)


# --- health + warm-on-boot --------------------------------------------------

def _ollama_status() -> str:
    """warm = model resident; loaded = pulled but not resident; down = no server."""
    try:
        with urllib.request.urlopen(f"{config.OLLAMA_HOST}/api/ps", timeout=3) as r:
            ps = json.loads(r.read().decode())
        if any(config.MODEL_TAG in (m.get("name", "") or m.get("model", "")) for m in ps.get("models", [])):
            return "warm"
        return "loaded"
    except Exception:
        return "down"


def _warm() -> float:
    """Load the model resident so the first agent/chat never cold-starts."""
    payload = {"model": config.MODEL_TAG, "prompt": "ok", "stream": False,
               "keep_alive": config.KEEP_ALIVE, "options": {"num_predict": 1}}
    t0 = time.time()
    req = urllib.request.Request(f"{config.OLLAMA_HOST}/api/generate",
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=300):
        pass
    return time.time() - t0


@app.get("/api/health")
async def health():
    loop = asyncio.get_running_loop()
    ollama = await loop.run_in_executor(None, _ollama_status)
    gateway_up = (time.time() - hub.state_ts) < 3.0 and bool(hub.state)
    ls = llm.status()
    return {
        "ollama": ollama,
        "model": config.MODEL_TAG,
        "model_warm": hub.model_warm or ollama == "warm",
        "gateway": "up" if gateway_up else "down",
        "sensor_logs": bool(telemetry.recent(per_log=1)),
        "ews_isolated": hub.ews_isolated,
        "autonomy": hub.autonomy,
        "llm_provider": ls["provider"],
        "llm_model": ls["model"],
        "llm_offline": ls["offline"],
        "llm_ready": ls["ready"],
    }


async def warm_loop():
    # Only the local Ollama provider has a resident model to warm. In cloud mode
    # (the shipped OpenRouter default) there is no local server — skip quietly so a
    # box without Ollama doesn't log a spurious connection failure on every boot.
    if llm.mode() != "local":
        log.info("warm-on-boot skipped: LLM mode is '%s' (no local model to warm)", llm.mode())
        return
    loop = asyncio.get_running_loop()
    try:
        dt = await loop.run_in_executor(None, _warm)
        hub.model_warm = True
        log.info("model warmed in %.1fs", dt)
    except Exception as e:
        log.warning("warm-on-boot skipped (%r)", e)


async def _clear_stale_containment():
    """On boot, reverse any leftover IT containment (e.g. an isolate_ews_ot that
    survived a backend restart). Otherwise the ews stays blackholed from the PLC and
    every manual/attack OT write silently times out — a nasty demo footgun."""
    loop = asyncio.get_running_loop()
    try:
        res = await loop.run_in_executor(None, actions.flush)
        log.info("startup containment flush: %s", res.get("detail"))
    except Exception as e:
        log.warning("startup flush skipped (%r)", e)


@app.on_event("startup")
async def _startup():
    _rehydrate_cases()                       # restore persisted triage/gate state
    asyncio.create_task(_clear_stale_containment())
    asyncio.create_task(state_loop())
    asyncio.create_task(detection_loop())
    asyncio.create_task(warm_loop())
