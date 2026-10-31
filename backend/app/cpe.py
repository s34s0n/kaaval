# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Local asset -> CPE 2.3 resolution. This join happens entirely on-box; only the
resulting CPE string is ever handed to the NVD egress. Driven by versioned config
(data/cpe_map.yaml): explicit (vendor, product) rules and passive-banner regexes."""

from __future__ import annotations

import os
import re

import yaml

from . import config

_cache = {"mtime": None, "map": {"products": [], "banners": []}}


def _map() -> dict:
    try:
        m = os.path.getmtime(config.CPE_MAP_PATH)
    except OSError:
        return _cache["map"]
    if _cache["mtime"] != m:
        try:
            with open(config.CPE_MAP_PATH) as f:
                _cache["map"] = yaml.safe_load(f) or {"products": [], "banners": []}
        except (OSError, yaml.YAMLError):
            _cache["map"] = {"products": [], "banners": []}
        _cache["mtime"] = m
    return _cache["map"]


def _ver(v: str | None) -> str:
    """CPE version field: keep the dotted version, '*' for unknown."""
    v = (v or "").strip()
    return re.sub(r"\s+", "_", v) if v and v != "*" else "*"


def resolve(meta: dict) -> str | None:
    """meta: {vendor, product, version, banners:[str,...]} -> a CPE 2.3 string or
    None when nothing matches (caller renders that as 'not assessed', never 'safe')."""
    m = _map()
    vendor = (meta.get("vendor") or "").lower()
    product = (meta.get("product") or "").lower()
    version = meta.get("version")

    # 1) explicit device metadata (declared / OUI-inferred)
    for p in m.get("products", []):
        mt = p.get("match", {})
        mv = (mt.get("vendor") or "").lower()
        pc = (mt.get("product_contains") or "").lower()
        if mv and mv in vendor and (not pc or pc in product):
            return p["cpe"].replace("{version}", _ver(version))

    # 2) passively observed banners (Zeek ssh/ssl/http software strings)
    for b in m.get("banners", []):
        rx = b.get("match_re")
        if not rx:
            continue
        for text in meta.get("banners", []) or []:
            mo = re.search(rx, text)
            if not mo:
                continue
            cpe = b["cpe"].replace("{version}", _ver(mo.group(1) if mo.groups() else None))
            for i, g in enumerate(mo.groups(), 1):
                cpe = cpe.replace("{%d}" % i, _ver(g))
            return cpe
    return None
