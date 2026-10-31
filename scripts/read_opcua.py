#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Phase 1 observable for Kaaval.

Connects to the gateway's OPC UA endpoint and prints discharge pressure and
interlock state once per second for 60 s, asserting the plant stays in band.
This is the legitimate IT-side read path (the same one the backend dashboard
uses), proving the PLC physics + S7comm->OPC UA mirror work end to end.

Run natively in the project .venv (asyncua is pure Python):
    .venv/bin/python scripts/read_opcua.py
Exits 0 if every sample is in band with the interlock armed; non-zero otherwise.
"""

from __future__ import annotations

import asyncio
import sys

from asyncua import Client, ua

ENDPOINT = "opc.tcp://127.0.0.1:4840/kaaval/"
NS_URI = "http://traboda.com/kaaval/pumpstation"
DURATION_S = 60
PRESSURE_BAND = (4.0, 6.0)


async def main() -> int:
    print(f"Kaaval Phase 1 — reading process state over OPC UA ({ENDPOINT})")
    print(f"  expecting discharge pressure in {PRESSURE_BAND} bar, interlock armed, for {DURATION_S}s\n")

    async with Client(ENDPOINT) as client:
        idx = await client.get_namespace_index(NS_URI)

        def node(opc_id: str):
            return client.get_node(ua.NodeId(opc_id, idx))

        pressure = node("PumpStation.DischargePressure")
        flow = node("PumpStation.FlowRate")
        speed = node("PumpStation.PumpSpeed")
        setpoint = node("PumpStation.PumpSetpoint")
        interlock_en = node("PumpStation.InterlockEnabled")
        tripped = node("PumpStation.InterlockTripped")

        out_of_band = 0
        for i in range(DURATION_S):
            p = await pressure.read_value()
            f = await flow.read_value()
            sp = await setpoint.read_value()
            spd = await speed.read_value()
            il = await interlock_en.read_value()
            tr = await tripped.read_value()

            in_band = PRESSURE_BAND[0] <= p <= PRESSURE_BAND[1] and il and not tr
            flag = "OK " if in_band else "!! "
            if not in_band:
                out_of_band += 1
            print(f"{flag}t={i:02d}s  pressure={p:5.2f} bar  flow={f:5.0f} m3/h  "
                  f"speed={spd:3.0f}%  setpoint={sp:3.0f}%  interlock={'ARMED' if il else 'OFF'}  "
                  f"tripped={tr}")
            await asyncio.sleep(1)

    print()
    if out_of_band == 0:
        print(f"PASS: all {DURATION_S} samples in band [{PRESSURE_BAND[0]}, {PRESSURE_BAND[1]}] bar, "
              f"interlock armed.")
        return 0
    print(f"FAIL: {out_of_band}/{DURATION_S} samples out of band or interlock not armed.")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (ConnectionRefusedError, OSError) as e:
        print(f"ERROR: cannot reach gateway at {ENDPOINT} ({e}).", file=sys.stderr)
        print("       Is the plant up?  docker compose up -d plc gateway", file=sys.stderr)
        sys.exit(2)
