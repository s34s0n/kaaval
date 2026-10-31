# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MAC OUI -> vendor lookup. Fully LOCAL (no egress) — reads a shipped IEEE OUI
subset. A production deployment swaps in the full registry by pointing KAAVAL_OUI
at it; the interface is unchanged."""

from __future__ import annotations

import json
import os
import re

from . import config

_cache = {"mtime": None, "table": {}}


def _table() -> dict:
    try:
        m = os.path.getmtime(config.OUI_PATH)
    except OSError:
        return {}
    if _cache["mtime"] != m:
        try:
            with open(config.OUI_PATH) as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError):
            raw = {}
        _cache.update(mtime=m, table={k.upper(): v for k, v in raw.items() if not k.startswith("_")})
    return _cache["table"]


def vendor_for_mac(mac: str | None) -> str | None:
    """Vendor for a MAC's 24-bit OUI prefix, or None if unknown/absent."""
    if not mac:
        return None
    h = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(h) < 6:
        return None
    return _table().get(h[:6])
