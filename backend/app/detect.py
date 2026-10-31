# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Detection orchestrator — logs -> events -> correlated incidents -> SQLite.

Run as: (from backend/)  ../.venv/bin/python -m app.detect
"""

from __future__ import annotations

import threading
import time

from . import config, correlate, discovery_detect, rules_engine, store
from .model import load_logs

# Campaign boundaries: wall-clock timestamps recorded when an operator launches a
# fresh attack. Correlation will not link events across one, so several distinct
# campaigns through the same pivot form several distinct incidents. Cleared on reset.
_block = threading.Lock()
_boundaries: list[float] = []


def record_campaign_boundary(ts: float | None = None) -> None:
    with _block:
        _boundaries.append(ts if ts is not None else time.time())


def clear_boundaries() -> None:
    with _block:
        _boundaries.clear()


def get_boundaries() -> list[float]:
    with _block:
        return sorted(_boundaries)


def fresh_events(since_ts: float, log_dir: str = None):
    """Run the generic rule engine over ONLY telemetry newer than `since_ts`, and
    write nothing to the store. Used to verify remediation: if the triggering
    conditions no longer fire on a fresh post-remediation window, the threat is
    gone — as opposed to re-scanning the historical logs that still hold the attack."""
    log_dir = log_dir or config.LOG_DIR
    logs = load_logs(log_dir, since=since_ts)
    return rules_engine.evaluate(logs)


def run_detection(log_dir: str = None):
    log_dir = log_dir or config.LOG_DIR
    logs = load_logs(log_dir)

    # All detection is config now: the generic engine evaluates every enabled rule
    # (built-in + user) from the rules store, with authorization from the profile.
    events = rules_engine.evaluate(logs)
    # First-seen / rogue-device detection (discovery wired into detection): a novel
    # host or conversation pair on the segment raises a real Event that correlates
    # into an incident, instead of only showing in the Assets view.
    events += discovery_detect.detect(logs)
    incidents = correlate.correlate(events, boundaries=get_boundaries())
    pivot = incidents[0].pivot if incidents else None

    conn = store.connect()
    store.init(conn)
    store.replace_all(conn, events, incidents)   # atomic swap; no reader sees a gap
    conn.close()
    return events, incidents, pivot


# --- pretty printer (the Phase 4 observable) --------------------------------

C = {"crit": "\033[1;31m", "warn": "\033[1;33m", "ok": "\033[1;32m",
     "dim": "\033[2m", "r": "\033[0m"}


def _sev_color(sev: str) -> str:
    return {"critical": C["crit"], "high": C["warn"], "medium": C["warn"]}.get(sev, C["dim"])


def main() -> int:
    events, incidents, pivot = run_detection()

    print(f"Kaaval detection — log dir {config.LOG_DIR}")
    print(f"pivot (unauthorized source asset): {pivot or '(none)'}\n")

    it = [e for e in events if e.domain == "IT"]
    ot = [e for e in events if e.domain == "OT"]
    print(f"EVENTS: {len(events)} ({len(it)} IT, {len(ot)} OT)")
    for e in events:
        tids = ",".join(t["id"] for t in e.techniques)
        print(f"  {_sev_color(e.severity)}[{e.severity:<8}]{C['r']} {e.domain} {e.rule:<26} "
              f"{tids:<20} {e.src} -> {e.dst}")
        print(f"            {C['dim']}{e.summary}{C['r']}")

    print(f"\nINCIDENTS: {len(incidents)}")
    for inc in incidents:
        span = inc.last_seen - inc.first_seen
        tids = ", ".join(t["id"] for t in inc.techniques)
        print(f"  {_sev_color(inc.severity)}{inc.id} [{inc.severity}]{C['r']} "
              f"pivot={inc.pivot} domains={'+'.join(inc.domains)} "
              f"cross_domain={inc.cross_domain} span={span:.1f}s")
        print(f"     techniques: {tids}")
        print(f"     {inc.summary}")

    # PASS line.
    print()
    if not events:
        print(f"{C['ok']}BASELINE CLEAN{C['r']} — 0 events, 0 incidents.")
        return 0
    one_cross = len(incidents) == 1 and incidents[0].cross_domain
    if one_cross:
        print(f"{C['ok']}PHASE 4 PASS{C['r']} — {len(events)} events correlated into "
              f"exactly 1 cross-domain (IT+OT) incident.")
        return 0
    print(f"{C['crit']}PHASE 4 CHECK{C['r']} — expected exactly 1 cross-domain incident, "
          f"got {len(incidents)}.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
