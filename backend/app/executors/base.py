# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Executor adapter interface (F8) — HOW an approved action runs, never WHETHER.

The gate lives OUTSIDE this layer, in front of it: detection → code-derived proposal
→ human approval (server-side, approver role, audited) → ONLY THEN an adapter runs.
Selecting a different adapter swaps the mechanism (docker-exec vs a real firewall/NAC
REST API) and changes nothing about the gate.

Defense in depth lives in the base class: `execute_it` refuses any gated/OT action,
and `execute_ot` refuses any action that is not gated-OT-AND-approved. So even a
direct, mis-wired call to an adapter fails CLOSED — an adapter cannot run an un-gated
or un-approved action, and the LLM (which never reaches this layer) cannot either.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

# The semantic operations an adapter implements. An action's executor maps to exactly
# one of these (code-derived from the profile catalog, never from the model).
IT_OPS = ("isolate_segment", "block_ip", "disable_account")
OT_OPS = ("ot_write",)


@dataclass
class ActionRequest:
    """A structured, validated execution request built from the CODE catalog."""
    name: str                       # action id from gating.spec (code-derived)
    op: str                         # one of IT_OPS / OT_OPS
    kind: str                       # "it" | "ot"
    gated: bool                     # authoritative gate decision (gating.is_gated_name)
    approved: bool                  # was the human gate satisfied before this call?
    target: str | None = None
    params: dict = field(default_factory=dict)


@dataclass
class ActionResult:
    ok: bool
    detail: str
    raw: str = ""
    adapter: str = ""
    refused: bool = False           # True when the adapter fail-closed (vs a device failure)


class ExecutorAdapter(ABC):
    name: str = "base"
    label: str = "Base adapter"
    kind: str = "abstract"          # "lab" | "real-integration"
    supports_ot: bool = False

    # --- per-operation implementations (subclasses) -------------------------
    @abstractmethod
    def block_ip(self, req: ActionRequest) -> ActionResult: ...
    @abstractmethod
    def isolate_segment(self, req: ActionRequest) -> ActionResult: ...
    @abstractmethod
    def disable_account(self, req: ActionRequest) -> ActionResult: ...
    @abstractmethod
    async def ot_write(self, req: ActionRequest) -> ActionResult: ...

    # --- gated entry points (the ONLY way the engine reaches an adapter) -----
    def execute_it(self, req: ActionRequest) -> ActionResult:
        """Reversible IT containment. Fail CLOSED on anything gated or non-IT."""
        if req.kind != "it" or req.gated:
            return ActionResult(False, f"refused: '{req.name}' is not an un-gated IT action — "
                                "OT/gated actions never run through the IT executor path.",
                                adapter=self.name, refused=True)
        impl = {"isolate_segment": self.isolate_segment, "block_ip": self.block_ip,
                "disable_account": self.disable_account}.get(req.op)
        if impl is None:
            return ActionResult(False, f"refused: unknown IT operation '{req.op}'", adapter=self.name, refused=True)
        r = impl(req)
        r.adapter = r.adapter or self.name
        return r

    async def execute_ot(self, req: ActionRequest) -> ActionResult:
        """Gated OT control. Fail CLOSED unless the action is gated-OT AND approved."""
        if req.kind != "ot" or not req.gated:
            return ActionResult(False, f"refused: '{req.name}' is not a gated OT control action",
                                adapter=self.name, refused=True)
        if not req.approved:
            return ActionResult(False, f"refused: '{req.name}' has not been human-approved — "
                                "OT writes require approval regardless of adapter.",
                                adapter=self.name, refused=True)
        if not self.supports_ot:
            return ActionResult(False, f"refused: adapter '{self.name}' does not implement OT control — "
                                "configure an OT control adapter.", adapter=self.name, refused=True)
        r = await self.ot_write(req)
        r.adapter = r.adapter or self.name
        return r


# --- registry + active-adapter selection ------------------------------------

_REGISTRY: dict[str, type[ExecutorAdapter]] = {}


def register(cls: type[ExecutorAdapter]) -> type[ExecutorAdapter]:
    _REGISTRY[cls.name] = cls
    return cls


def get(name: str) -> ExecutorAdapter | None:
    cls = _REGISTRY.get(name)
    return cls() if cls else None


def list_adapters() -> list[dict]:
    return [{"name": c.name, "label": c.label, "kind": c.kind, "supports_ot": c.supports_ot}
            for c in _REGISTRY.values()]
