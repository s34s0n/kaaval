#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Read the PLC's data block directly over S7comm from the engineering workstation.

The ews is NOT an authorized S7 client (only the gateway/HMI are), so this direct
S7comm session to the PLC is anomalous by definition — the pivot a real intruder
makes after boundary recon. Run on the ews; the Zeek sidecar captures it into
s7comm.log / cotp.log. This phase only *reads*; the Phase-3 attacker will write.
"""

import os
import struct

from snap7.client import Client

PLC_HOST = os.environ.get("PLC_HOST", "plc")
PLC_PORT = int(os.environ.get("S7_PORT", "102"))
DB_NUMBER = 1
DB_SIZE = 32


def main():
    print(f"[ews] S7comm read -> {PLC_HOST}:{PLC_PORT} DB{DB_NUMBER}")
    cli = Client()
    cli.connect(PLC_HOST, 0, 1, tcp_port=PLC_PORT)
    data = cli.db_read(DB_NUMBER, 0, DB_SIZE)
    pressure = struct.unpack_from(">f", data, 0)[0]
    setpoint = struct.unpack_from(">f", data, 16)[0]
    interlock = bool(data[24] & 0x01)
    print(f"[ews] DB1 read OK: discharge_pressure={pressure:.2f} bar  "
          f"setpoint={setpoint:.0f}%  interlock_enabled={interlock}")
    cli.disconnect()


if __name__ == "__main__":
    main()
