# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Firewall / NAC executor adapter — REAL-INTEGRATION shape (F8).

A production IT-containment adapter that pushes deny rules / NAC quarantine to a
firewall or Network Access Control appliance over its REST API. The request/response
CONTRACT is real (below); the HTTP call is genuine code. Where there is no appliance
to test against, it is STUBBED by failing CLOSED — if no API URL is configured it
reports failure and touches no device (it never fakes success).

Documented contract (generic; adapt per vendor):
  Auth:     Authorization: Bearer <FIREWALL_API_TOKEN>
  Block:    POST  {API_URL}/api/v1/rules
            { "action": "deny", "scope": "egress" | "segment",
              "src": "<host-or-ip>", "ports": [{"proto":"tcp","port":443}, ...],
              "comment": "kaaval:<action-id>" }
            -> 200 { "id": "<rule-id>", "status": "applied" }
  Quarantine (NAC): POST {API_URL}/api/v1/nac/quarantine
            { "host": "<host-or-ip>", "user": "<user>", "comment": "kaaval:<action-id>" }
            -> 200 { "status": "quarantined" }

This adapter is IT-only; OT control is NOT in scope (supports_ot = False), so any OT
write through it fails closed — OT recovery must use an OT control adapter.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .. import config
from . import base
from .base import ActionRequest, ActionResult, register


@register
class FirewallNacAdapter(base.ExecutorAdapter):
    name = "firewall_rest"
    label = "Firewall / NAC (REST API)"
    kind = "real-integration"
    supports_ot = False

    def _post(self, path: str, payload: dict) -> ActionResult:
        url = config.FIREWALL_API_URL
        if not url:
            # STUB / fail-closed: no appliance configured -> no device is touched.
            return ActionResult(False, "firewall_rest not configured (set KAAVAL_FIREWALL_API_URL) — "
                                "failing closed; no device touched.", adapter=self.name, refused=True)
        body = json.dumps(payload).encode("utf-8")
        headers = {"content-type": "application/json"}
        if config.FIREWALL_API_TOKEN:
            headers["authorization"] = f"Bearer {config.FIREWALL_API_TOKEN}"
        req = urllib.request.Request(url.rstrip("/") + path, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            status = data.get("status")
            ok = status in ("applied", "quarantined")
            return ActionResult(ok, f"firewall/NAC: {status or 'unknown response'} (rule {data.get('id', '-')})",
                                raw=json.dumps(data)[:400])
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as e:
            # A real failure: report it, do not claim success (caller audits + verifies).
            return ActionResult(False, f"firewall/NAC API call failed: {e!r}", adapter=self.name)

    def _ports(self, req: ActionRequest):
        return [{"proto": r["proto"], "port": r["dport"]} for r in req.params.get("rules", [])]

    def block_ip(self, req: ActionRequest) -> ActionResult:
        return self._post("/api/v1/rules", {"action": "deny", "scope": "egress", "src": req.target,
                                            "ports": self._ports(req), "comment": f"kaaval:{req.name}"})

    def isolate_segment(self, req: ActionRequest) -> ActionResult:
        return self._post("/api/v1/rules", {"action": "deny", "scope": "segment", "src": req.target,
                                            "ports": self._ports(req), "comment": f"kaaval:{req.name}"})

    def disable_account(self, req: ActionRequest) -> ActionResult:
        return self._post("/api/v1/nac/quarantine", {"host": req.target, "user": req.params.get("user"),
                                                     "comment": f"kaaval:{req.name}"})

    async def ot_write(self, req: ActionRequest) -> ActionResult:
        # Defense in depth (base also guards): a firewall never performs OT control.
        return ActionResult(False, "firewall/NAC adapter does not perform OT control — "
                            "use an OT control adapter.", adapter=self.name, refused=True)
