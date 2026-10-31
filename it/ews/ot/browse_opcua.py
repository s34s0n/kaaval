#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Browse the OPC UA gateway's address space from the engineering workstation.

Generates an OPC UA *browse* against the IT/OT gateway — the boundary recon a
real intruder performs to discover control tags before pivoting. Run on the ews;
the Zeek sidecar captures it into opcua_binary*.log.
"""

import asyncio
import os

from asyncua import Client

ENDPOINT = os.environ.get("OPC_ENDPOINT", "opc.tcp://gateway:4840/kaaval/")


async def walk(node, depth=0, seen=0, limit=200):
    for child in await node.get_children():
        try:
            name = (await child.read_browse_name()).Name
        except Exception:
            name = "?"
        print("  " * depth + f"- {name} [{child.nodeid.to_string()}]")
        seen += 1
        if seen < limit:
            seen = await walk(child, depth + 1, seen, limit)
    return seen


async def main():
    print(f"[ews] OPC UA browse -> {ENDPOINT}")
    async with Client(ENDPOINT) as client:
        n = await walk(client.nodes.objects)
    print(f"[ews] browsed {n} nodes")


if __name__ == "__main__":
    asyncio.run(main())
