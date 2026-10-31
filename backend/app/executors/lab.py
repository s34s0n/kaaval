# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Lab / reference executor adapter (F8).

This is the demo-plant adapter: IT containment via real iptables rules applied with
`docker compose exec` inside the target container, and OT recovery via genuine OPC UA
writes through the gateway (the same control path a real HMI uses) — but targeting the
SIMULATED plant. It is explicitly labeled "lab" everywhere; it is NOT a production
integration. A real deployment selects a real-integration adapter (e.g. firewall_rest)
without touching the gate.
"""

from __future__ import annotations

import subprocess

from .. import config
from ..opc import OpcClient
from . import base
from .base import ActionRequest, ActionResult, register

_COMPOSE = ["docker", "compose", "-p", config.COMPOSE_PROJECT, "-f", config.COMPOSE_FILE]


def docker_exec(service: str, *args: str) -> tuple[bool, str]:
    """Run a command inside a compose service container (service == asset id).
    The single docker-exec primitive used by the lab adapter and plant utilities."""
    cmd = _COMPOSE + ["exec", "-T", service] + list(args)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return cp.returncode == 0, (cp.stdout + cp.stderr).strip()
    except Exception as e:
        return False, repr(e)


@register
class LabAdapter(base.ExecutorAdapter):
    name = "lab"
    label = "Lab / reference (docker-exec + OPC UA)"
    kind = "lab"
    supports_ot = True

    def _drop(self, req: ActionRequest, what: str) -> ActionResult:
        target = req.target
        rules = req.params.get("rules", [])
        if not target or not rules:
            return ActionResult(False, f"{req.name}: no target/rules in executor spec", refused=True)
        oks, raws, specs = [], [], []
        for r in rules:
            proto, dport = str(r["proto"]), str(r["dport"])
            ok, out = docker_exec(target, "iptables", "-A", "OUTPUT", "-p", proto, "--dport", dport, "-j", "DROP")
            oks.append(ok); raws.append(out); specs.append(f"{proto}/{dport}")
        return ActionResult(all(oks), f"{target} {what}: OUTPUT DROP for {', '.join(specs)}", raw="".join(raws))

    def block_ip(self, req: ActionRequest) -> ActionResult:
        return self._drop(req, "egress block")

    def isolate_segment(self, req: ActionRequest) -> ActionResult:
        return self._drop(req, "segment isolation")

    def disable_account(self, req: ActionRequest) -> ActionResult:
        target, user = req.target, req.params.get("user")
        if not target or not user:
            return ActionResult(False, f"{req.name}: no target/user", refused=True)
        ok, out = docker_exec(target, "usermod", "-L", user)
        docker_exec(target, "pkill", "-KILL", "-u", user)      # best-effort
        return ActionResult(ok, f"{user}@{target} locked and sessions killed", raw=out)

    async def ot_write(self, req: ActionRequest) -> ActionResult:
        writes = req.params.get("writes", [])
        if not writes:
            return ActionResult(False, f"{req.name}: no OPC UA writes in executor spec", refused=True)
        try:
            c = OpcClient(); await c.connect()
            try:
                done = []
                for w in writes:
                    tag, val, vtype = w["tag"], w["value"], w.get("vtype", "real")
                    if vtype == "bool":
                        await c.write_bool(tag, bool(val))
                    else:
                        await c.write_real(tag, float(val))
                    done.append(f"{tag}={val}")
            finally:
                await c.disconnect()
            return ActionResult(True, f"{', '.join(done)} written via OPC UA (gateway control path)")
        except Exception as e:
            return ActionResult(False, f"OPC UA write failed: {e!r}")
