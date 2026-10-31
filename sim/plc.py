# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Kaaval PLC — Siemens-style S7comm server + pump-station physics.

Runs an S7 server (python-snap7, pure Python) exposing DB1 on TCP/102, and a
physics loop that advances the process in real time. The loop and the server
share one bytearray (the DB): the loop writes RO/output tags into it and the
server serves them to S7 clients; clients (the gateway, and the Phase-3
attacker) write RW/control tags into it and the loop reads them back.

The loop must never write RW tags — doing so would clobber client writes (see
the RW/RO split in tags.py). It reads RW tags from the buffer every iteration.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time

from snap7.server import Server
from snap7.type import SrvArea

import process_model as pm
import tags

LOG = logging.getLogger("kaaval.plc")

S7_PORT = int(os.environ.get("S7_PORT", "102"))
TICK_HZ = float(os.environ.get("PLC_TICK_HZ", "10"))
LOG_EVERY_S = 5.0


def pack_all(buf: bytearray, state: dict) -> None:
    """Write every tag (RO and RW) into the buffer — used once at startup."""
    for t in tags.TAGS:
        tags.write_tag(buf, t, state[t.name])


def pack_outputs(buf: bytearray, state: dict) -> None:
    """Write only RO/output tags — used every loop iteration."""
    for t in tags.RO_TAGS:
        tags.write_tag(buf, t, state[t.name])


def load_inputs(buf: bytearray, state: dict) -> None:
    """Read RW/control tags from the buffer into state (honor client writes)."""
    for t in tags.RW_TAGS:
        state[t.name] = tags.read_tag(buf, t)


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    buf = bytearray(tags.DB_SIZE)
    state = pm.initial_state()
    pack_all(buf, state)  # seed DB with baseline values incl. RW defaults

    server = Server(log=False)
    server.register_area(SrvArea.DB, tags.DB_NUMBER, buf)
    server.start(tcp_port=S7_PORT)  # non-blocking: serves in a daemon thread
    LOG.info("PLC S7 server listening on 0.0.0.0:%d, serving DB%d (%d bytes)",
             S7_PORT, tags.DB_NUMBER, tags.DB_SIZE)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    dt = 1.0 / TICK_HZ
    last_log = 0.0
    next_tick = time.monotonic()
    while not stop.is_set():
        load_inputs(buf, state)      # pick up gateway/attacker writes
        pm.tick(state, dt)
        pack_outputs(buf, state)     # publish physics outputs (never RW tags)

        now = time.monotonic()
        if now - last_log >= LOG_EVERY_S:
            # Process-agnostic heartbeat: log the safety variable + interlock for
            # whichever plant is active (pump pressure / reactor temperature / …).
            sv = tags.SAFETY["variable"]
            itl = tags.SAFETY["interlock_tag"]
            LOG.info("%s: %s=%.2f interlock(%s)=%s", tags.NAME,
                     sv, state.get(sv, float("nan")), itl, state.get(itl))
            last_log = now

        next_tick += dt
        sleep = next_tick - time.monotonic()
        if sleep > 0:
            stop.wait(sleep)
        else:
            next_tick = time.monotonic()  # fell behind; resync

    LOG.info("PLC shutting down")
    server.stop()


if __name__ == "__main__":
    main()
