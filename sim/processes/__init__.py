# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Process registry — selects the active simulated plant by ``KAAVAL_PROCESS``.

The simulator is generic; each plant lives in its own module here (pump, reactor,
…). ``load()`` returns the active process module. Unknown/empty selections fail
safe to the pump (profile #1), logging the fallback rather than crashing — a real
product must never hard-crash on a bad deployment variable.
"""

from __future__ import annotations

import importlib
import os
import sys

DEFAULT = "pump"
_AVAILABLE = ("pump", "reactor")

# A sibling file (sim/active_process) lets the switch script pin the process for
# clients that don't inherit env — notably the ews OT scripts, which are launched
# over SSH and so never see the container's docker `environment:` vars. The env
# var wins when set (plc/gateway run as PID1 and do get it).
_FILE = os.path.join(os.path.dirname(__file__), os.pardir, "active_process")


def _from_file() -> str | None:
    try:
        with open(_FILE) as f:
            return f.read().strip().lower() or None
    except OSError:
        return None


def active_name() -> str:
    name = (os.environ.get("KAAVAL_PROCESS") or _from_file() or DEFAULT).strip().lower()
    if name not in _AVAILABLE:
        print(f"[sim] unknown process {name!r}; falling back to {DEFAULT!r}", file=sys.stderr)
        return DEFAULT
    return name


def load():
    """Import and return the active process module."""
    return importlib.import_module(f"processes.{active_name()}")
