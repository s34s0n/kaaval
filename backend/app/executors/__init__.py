# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Executor adapters — the ONLY thing that touches a device, and ONLY with an
approved, gated, code-derived action. See base.ExecutorAdapter for the fail-closed
contract. Importing this package registers the shipped adapters."""

from .. import config, profile
from . import base, firewall_rest, lab          # noqa: F401 — import registers the adapters
from .base import (IT_OPS, OT_OPS, ActionRequest, ActionResult, ExecutorAdapter,  # noqa: F401
                   get, list_adapters, register)


def _profile_choice(slot: str) -> str | None:
    try:
        return (profile.executor_config() or {}).get(slot)
    except Exception:
        return None


def active_it() -> ExecutorAdapter:
    name = _profile_choice("it") or config.EXECUTOR_IT_ADAPTER or "lab"
    return get(name) or get("lab")


def active_ot() -> ExecutorAdapter:
    name = _profile_choice("ot") or config.EXECUTOR_OT_ADAPTER or "lab"
    return get(name) or get("lab")


def status() -> dict:
    it, ot = active_it(), active_ot()
    return {
        "it": {"name": it.name, "label": it.label, "kind": it.kind},
        "ot": {"name": ot.name, "label": ot.label, "kind": ot.kind, "supports_ot": ot.supports_ot},
        "available": list_adapters(),
    }
