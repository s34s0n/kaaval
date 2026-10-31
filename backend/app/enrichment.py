# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Asset enrichment + CVE correlation (F3).

Pipeline, per the egress discipline:
  (a) enrich each asset LOCALLY — MAC/OUI vendor (local table), passive
      banner/version parsing from existing Zeek data, declared device metadata;
  (b) resolve enriched asset -> CPE LOCALLY (cpe.resolve);
  (c) CPE -> CVE via nvd.lookup, which sends ONLY the CPE off-box (cloud) or reads
      the offline snapshot (local) — never an asset name/IP/MAC/count.
The asset<->CPE<->CVE join is reassembled HERE, locally, after the lookup.

CVE data is INFORMATIONAL ONLY. This module never touches gating, never proposes
or fires an action, and uses no LLM. Invariant 1 holds by construction.
"""

from __future__ import annotations

import json
import os

from . import assets as assets_mod, config, cpe as cpe_mod, llm, nvd, oui, profile

_VENDOR_HINTS = ("siemens", "rockwell", "schneider", "honeywell", "yokogawa", "allen-bradley")


def _vendor_from_role(role: str | None) -> str | None:
    r = (role or "").lower()
    for v in _VENDOR_HINTS:
        if v in r:
            return v.capitalize()
    return None


def _read_log(name: str) -> list[dict]:
    path = os.path.join(config.LOG_DIR, f"{name}.log")
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass
    return rows


def _collect_banners() -> dict[str, list[str]]:
    """ip -> [software/version banner strings] passively observed in Zeek logs.
    The banner is attributed to the host that SERVED it (the responder)."""
    banners: dict[str, list[str]] = {}
    def add(ip, s):
        if ip and s:
            banners.setdefault(ip, [])
            if s not in banners[ip]:
                banners[ip].append(s)
    for r in _read_log("ssh"):
        add(r.get("id.resp_h"), r.get("server"))   # server's SSH software string
        add(r.get("id.orig_h"), r.get("client"))   # client's SSH software string
    for r in _read_log("http"):
        add(r.get("id.resp_h"), r.get("server"))   # HTTP Server: header
    for r in _read_log("ssl"):
        # SNI/cert CN isn't a version but can carry a product name; keep for display.
        add(r.get("id.resp_h"), r.get("server_name"))
    return banners


def enrich(*, ts: float | None = None) -> dict:
    """Enriched inventory with per-asset CVE posture. Read-only."""
    base = assets_mod.list_assets()
    raw = {a.get("id"): a for a in profile.assets()}          # mac/vendor/product/firmware (if declared)
    banners = _collect_banners()
    out = []
    for a in base:
        ips = a.get("ips") or []
        praw = raw.get(a["name"], {})
        mac = praw.get("mac")
        oui_vendor = oui.vendor_for_mac(mac)
        vendor = oui_vendor or praw.get("vendor") or _vendor_from_role(a.get("role"))
        product = praw.get("product")
        version = praw.get("firmware") or praw.get("version")
        host_banners = [b for ip in ips for b in banners.get(ip, [])]
        cpe = cpe_mod.resolve({"vendor": vendor, "product": product,
                               "version": version, "banners": host_banners})
        cve = nvd.lookup(cpe, ts=ts)                          # only the CPE leaves the box
        out.append({
            "name": a["name"], "domain": a.get("domain"), "role": a.get("role"),
            "criticality": a.get("criticality"), "ips": ips, "mac": mac,
            "vendor": vendor, "oui_vendor": oui_vendor, "product": product, "version": version,
            "banners": host_banners, "cpe": cpe, "cve": cve,
        })
    return {"assets": out, "summary": _summary(out), "mode": llm.mode()}


def _summary(rows: list[dict]) -> dict:
    s = {"total": len(rows), "vulnerable": 0, "none_known": 0, "not_assessed": 0,
         "cve_count": 0, "max_cvss": 0}
    for r in rows:
        st = r["cve"]["status"]
        s[st] = s.get(st, 0) + 1
        s["cve_count"] += len(r["cve"].get("cves", []))
        s["max_cvss"] = max(s["max_cvss"], r["cve"].get("max_cvss", 0))
    return s
