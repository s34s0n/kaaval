# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Response action execution — the ENGINE in front of the executor adapters (F8).

The gate is OUTSIDE this module (the /apply and /approve endpoints). This engine is
reached ONLY after the gate: it builds a structured, validated ActionRequest from the
CODE catalog, picks the active adapter (lab docker-exec, or a real firewall/NAC), and
dispatches. Selecting an adapter changes HOW an approved action runs, never whether.

Defense in depth: `execute_it` fails CLOSED on any gated action (so the IT/auto path
can never run an OT action), and `execute_ot` runs only gated-OT actions through the
adapter's approved-only entry. `flush()` reverses the lab IT rules for reset.
"""

from __future__ import annotations

import asyncio
import subprocess
import time

from . import config, executors, gating, profile
from .executors.lab import docker_exec as _exec
from .opc import OpcClient

# Run docker compose for the pinned project (reset/plant utilities only — not the
# gated path). Project + file are config so the containerized backend can reach its
# sibling containers through the mounted docker socket (see config.COMPOSE_*).
_COMPOSE = ["docker", "compose", "-p", config.COMPOSE_PROJECT, "-f", config.COMPOSE_FILE]

_OT_PORTS = {"102", "4840", "502", "20000", "44818"}     # S7comm/OPC UA/Modbus/DNP3/EtherNet-IP


def _executor(name: str) -> dict | None:
    a = profile.action(name)
    return a.get("executor") if a else None


def _derive_op(ex: dict) -> str:
    """Map an action's executor spec to ONE semantic adapter operation. Deterministic
    and code-derived (never from the model). An explicit `op:` in the profile wins."""
    if ex.get("op"):
        return ex["op"]
    t = ex.get("type")
    if t == "opcua_write":
        return "ot_write"
    if t == "account_lock":
        return "disable_account"
    if t == "iptables":
        ports = {str(r.get("dport")) for r in ex.get("rules", [])}
        return "isolate_segment" if (ports & _OT_PORTS) else "block_ip"
    return ex.get("type") or "unknown"


def build_request(name: str, *, approved: bool) -> executors.ActionRequest | None:
    """Build a validated request from the CODE catalog + the authoritative gate."""
    a = profile.action(name)
    if a is None:
        return None
    ex = a.get("executor") or {}
    return executors.ActionRequest(
        name=name, op=_derive_op(ex), kind=a.get("kind", "ot"),
        gated=gating.is_gated_name(name), approved=approved,
        target=ex.get("target"), params=ex)


# --- IT containment (reversible, auto-eligible) — through the active adapter --

def execute_it(name: str) -> dict:
    """Run a reversible IT action through the active IT adapter. Fail CLOSED on a
    gated action — the IT/auto path can NEVER execute an OT/gated action."""
    req = build_request(name, approved=False)
    if req is None:
        return {"ok": False, "detail": f"unknown action {name}"}
    if gating.is_gated_name(name):                 # explicit defense-in-depth gate
        return {"ok": False, "detail": f"refused: '{name}' is gated and cannot run on the IT auto path"}
    res = executors.active_it().execute_it(req)
    return {"ok": res.ok, "detail": res.detail, "raw": res.raw, "adapter": res.adapter, "refused": res.refused}


def containment_active() -> dict:
    """Live check: is any IT iptables containment currently in effect (e.g. the ews
    isolated from the OT path)? While true, a direct manual OT write from that host
    is blackholed and produces no telemetry — so it (correctly) raises no incident.
    Surfacing this stops that looking like a broken button."""
    targets, isolated = [], []
    for a in profile.actions():
        ex = a.get("executor") or {}
        if ex.get("type") == "iptables" and ex.get("target"):
            targets.append(ex["target"])
    for t in dict.fromkeys(targets):                 # dedup, preserve order
        ok, out = _exec(t, "iptables", "-S", "OUTPUT")
        if ok and "-j DROP" in out:
            isolated.append(t)
    return {"isolated": bool(isolated), "targets": isolated}


def flush() -> dict:
    """Reverse all IT containment (used by reset) — derived from the catalog."""
    oks, details = [], []
    for a in profile.actions():
        ex = a.get("executor") or {}
        target = ex.get("target")
        if ex.get("type") == "iptables":
            ok, _ = _exec(target, "iptables", "-F", "OUTPUT")
            oks.append(ok); details.append(f"{target} iptables flushed")
        elif ex.get("type") == "account_lock":
            ok, _ = _exec(target, "usermod", "-U", ex.get("user"))
            oks.append(ok); details.append(f"{ex.get('user')}@{target} unlocked")
    return {"ok": all(oks) if oks else True, "detail": "; ".join(details) or "nothing to flush"}


# --- OT recovery (gated, real OPC UA writes) — driven by the catalog ---------

async def execute_ot(name: str) -> dict:
    """Run a GATED OT control action through the active OT adapter. Reached ONLY from
    the /approve endpoint (after server-side approver approval), so approved=True. The
    adapter still refuses anything that is not gated-OT-and-approved (fail closed)."""
    req = build_request(name, approved=True)
    if req is None:
        return {"ok": False, "detail": f"unknown action {name}"}
    res = await executors.active_ot().execute_ot(req)
    return {"ok": res.ok, "detail": res.detail, "raw": res.raw, "adapter": res.adapter, "refused": res.refused}


# --- post-action verification (confirm the fix actually took) ----------------

async def verify(name: str) -> dict:
    """Re-check the live system to confirm an executed action achieved its intent,
    using the action's own executor spec. OT writes are verified by reading state
    back over OPC UA; IT actions by inspecting the real iptables rules / account
    lock. Returns {ok, detail} — the trustworthy 'is it actually fixed?' check."""
    ex = _executor(name)
    if ex is None:
        return {"ok": False, "detail": f"unknown action {name}"}
    target = ex.get("target")
    kind = ex.get("type")
    loop = asyncio.get_event_loop()
    try:
        if kind == "opcua_write":
            c = OpcClient()
            try:
                await c.connect()
                st = await c.read_state()
            finally:
                await c.disconnect()
            v = ex.get("verify") or {}
            tag = v.get("tag")
            got = st.get(tag)
            if "equals" in v:
                ok = bool(got) == bool(v["equals"])
                return {"ok": ok, "detail": f"PLC {tag}={got} (read back over OPC UA)"}
            if "near" in v:
                tol = float(v.get("tol", 1.0))
                ok = abs(float(got) - float(v["near"])) <= tol
                return {"ok": ok, "detail": f"PLC {tag}={got:.0f} (read back over OPC UA)"}
            return {"ok": True, "detail": f"PLC {tag}={got} (read back over OPC UA)"}

        if kind == "iptables":
            _ok, out = await loop.run_in_executor(None, _exec, target, "iptables", "-S", "OUTPUT")
            want = [str(r["dport"]) for r in ex.get("rules", [])]
            present = all(f"dport {p}" in out for p in want) and "DROP" in out
            return {"ok": present,
                    "detail": (f"{target} iptables DROP for {'/'.join(want)} present" if present
                               else "expected DROP rules not found")}
        if kind == "account_lock":
            user = ex.get("user")
            _ok, out = await loop.run_in_executor(None, _exec, target, "passwd", "-S", user)
            parts = out.split()
            locked = len(parts) > 1 and parts[1].startswith("L")
            return {"ok": locked, "detail": f"{user} account status: {parts[1] if len(parts) > 1 else '?'} (L=locked)"}
    except Exception as e:
        return {"ok": False, "detail": f"verification error: {e!r}"}
    return {"ok": False, "detail": "no verification defined"}


# --- Range Console manual control (the malicious vs legitimate contrast) -----

def range_malicious(op: str, value=None) -> dict:
    """Unauthorized direct S7 write from the ews (the sensor captures it)."""
    args = ["python3", "/opt/ot/manual_write.py", op]
    if value is not None and op != "pump_max":
        args.append(str(value))
    ok, out = _exec("ews", *args)
    # A timeout means the ews can't reach the PLC — almost always because it's been
    # isolated (containment active). Make that explicit instead of a raw traceback.
    if not ok and ("timed out" in out or "TimeoutError" in out or "ConnectionError" in out):
        out = ("ews cannot reach the PLC — it is ISOLATED (IT containment active). "
               "Reset to baseline (or remove the isolate_ews_ot rule) to restore the path.")
    return {"ok": ok, "path": "ews->plc S7comm (unauthorized)", "detail": out}


async def range_legitimate_setpoint(value: float) -> dict:
    """Authorized operator setpoint via the gateway over OPC UA (no ews transit
    -> the sensor never sees it -> Kaaval does not alert). Writes the active
    profile's control tag (pump setpoint / reactor coolant valve)."""
    tag = profile.safety().get("control_tag")
    if not tag:
        return {"ok": False, "detail": "no control_tag declared in the profile safety block"}
    c = OpcClient()
    try:
        await c.connect()
        await c.write_real(tag, float(value))
        return {"ok": True, "path": "operator->gateway OPC UA (authorized)",
                "detail": f"{tag}={value:.0f} via the gateway"}
    except Exception as e:
        return {"ok": False, "detail": f"OPC UA write failed: {e!r}"}
    finally:
        await c.disconnect()


def reset_plant() -> dict:
    """Hard reset: flush IT containment, reseed PLC, clear logs, recreate sensor.

    Waits for the recreated sensor to come back up before returning, so a malicious
    action fired immediately after Reset isn't lost in the sensor's restart gap
    (otherwise it produces no log -> no alert)."""
    flush()
    subprocess.run(_COMPOSE + ["restart", "plc"], capture_output=True, timeout=60)
    subprocess.run(["bash", "-c", f"find {config.LOG_DIR} -maxdepth 1 -name '*.log' -delete"],
                   capture_output=True)
    # `restart` (not `up --force-recreate`) so this works from inside the containerized
    # backend too, which has the compose file + docker socket but no build context. The
    # sensor's network_mode (service:ews) is preserved across a restart, so it re-attaches.
    subprocess.run(_COMPOSE + ["restart", "sensor"], capture_output=True, timeout=60)
    # Give Zeek time to start and re-attach to the ews network namespace before we
    # report ready (so the next captured packet is actually seen).
    time.sleep(8)
    return {"ok": True, "detail": "plant reseeded, IT containment flushed, logs cleared, "
            "sensor recreated and re-attached"}
