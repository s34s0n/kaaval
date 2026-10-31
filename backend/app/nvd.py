# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""CPE -> CVE lookup with the SAME interface in both modes:
  - cloud mode: query NVD live through the egress boundary (egress.nvd_cve),
    which transmits ONLY the CPE string.
  - local mode: read a shipped offline snapshot (data/nvd_snapshot.json).
Results cache locally keyed on CPE, so a CPE is never re-queried.

Three honest states (mirrors the compliance MET/GAP/NOT-ASSESSED discipline):
  vulnerable    — CVEs found for this CPE.
  none_known    — this CPE was assessed and has no known CVEs (a real result).
  not_assessed  — no CPE resolved, or no data for it. Absence of data is NEVER
                  rendered as 'safe'.
"""

from __future__ import annotations

import json
import os
import time

from . import config, egress, llm, store

_snap_cache = {"mtime": None, "data": {}}


def _snapshot() -> dict:
    try:
        m = os.path.getmtime(config.NVD_SNAPSHOT_PATH)
    except OSError:
        return {}
    if _snap_cache["mtime"] != m:
        try:
            with open(config.NVD_SNAPSHOT_PATH) as f:
                _snap_cache["data"] = json.load(f)
        except (OSError, json.JSONDecodeError):
            _snap_cache["data"] = {}
        _snap_cache["mtime"] = m
    return _snap_cache["data"]


def _prefix(cpe: str) -> str:
    """Product-prefix = first 5 CPE fields (cpe:2.3:<part>:<vendor>:<product>)."""
    parts = cpe.split(":")
    return ":".join(parts[:5]) if len(parts) >= 5 else cpe


def _snapshot_for(cpe: str):
    """CVE list for a CPE from the offline snapshot, or None if the product is
    ABSENT from the snapshot (=> not assessed, distinct from present-but-empty)."""
    entry = _snapshot().get(_prefix(cpe))
    if entry is None:
        return None
    return entry.get("cves", [])


def _parse_nvd(raw: dict) -> list[dict]:
    out = []
    for v in raw.get("vulnerabilities", []):
        cve = v.get("cve", {})
        desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        cvss = sev = vector = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cd = metrics[key][0].get("cvssData", {})
                cvss = cd.get("baseScore")
                vector = cd.get("vectorString")
                sev = metrics[key][0].get("baseSeverity") or cd.get("baseSeverity")
                break
        out.append({"id": cve.get("id"), "cvss": cvss, "severity": sev,
                    "vector": vector, "summary": desc, "affected": ""})
    return out


def _shape(cpe: str, cves: list, source: str) -> dict:
    return {"cpe": cpe, "status": "vulnerable" if cves else "none_known",
            "cves": cves, "source": source,
            "max_cvss": max([c.get("cvss") or 0 for c in cves], default=0)}


def lookup(cpe: str | None, *, ts: float | None = None) -> dict:
    """Resolve CVEs for one CPE. Never raises; never invents safety."""
    if not cpe:
        return {"cpe": None, "status": "not_assessed", "cves": [], "source": "none",
                "reason": "no CPE could be resolved for this asset (unknown firmware/version)"}
    ts = ts or time.time()
    conn = store.connect(); store.init(conn)
    cached = store.get_cve_cache(conn, cpe)
    if cached:
        conn.close()
        return _shape(cpe, cached["data"], cached["source"] + "+cache")

    if llm.mode() == "cloud":
        try:
            cves = _parse_nvd(egress.nvd_cve(cpe, api_key=config.NVD_API_KEY))
            store.set_cve_cache(conn, cpe=cpe, source="nvd", data=cves, ts=ts)
            conn.close()
            return _shape(cpe, cves, "nvd")
        except Exception:
            conn.close()
            snap = _snapshot_for(cpe)            # graceful offline fallback
            if snap is not None:
                return _shape(cpe, snap, "snapshot-fallback")
            return {"cpe": cpe, "status": "not_assessed", "cves": [], "source": "error",
                    "reason": "NVD unreachable and no offline data for this CPE — not assessed"}

    # local mode: shipped snapshot only
    snap = _snapshot_for(cpe)
    if snap is None:
        conn.close()
        return {"cpe": cpe, "status": "not_assessed", "cves": [], "source": "snapshot",
                "reason": "no offline NVD data for this CPE — not assessed (not the same as safe)"}
    store.set_cve_cache(conn, cpe=cpe, source="snapshot", data=snap, ts=ts)
    conn.close()
    return _shape(cpe, snap, "snapshot")
