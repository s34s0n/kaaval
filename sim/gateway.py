# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Kaaval IT/OT gateway — S7comm client + OPC UA server (the boundary).

Polls the PLC's DB1 over S7comm and mirrors every tag onto an OPC UA server, so
IT-side clients (the backend dashboard, the authorized HMI) speak modern OPC UA
while the PLC speaks S7comm. This is the legitimate IT/OT boundary; the Phase-3
attacker deliberately bypasses it by speaking S7comm to the PLC directly.

Data direction per cycle (~5 Hz), with the PLC as the source of truth:
  * RO tags  -> mirror PLC value onto the OPC UA node (read-only display).
  * RW tags  -> if an OPC UA client changed the node, forward that write down to
                the PLC; otherwise mirror the PLC value up. This means a control
                write the *attacker* makes directly on the PLC is reflected here
                (not overwritten), while an operator's OPC UA write is pushed to
                the PLC. The gateway never blindly re-pushes RW values.
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct

from asyncua import Server, ua
from snap7.client import Client

import tags

LOG = logging.getLogger("kaaval.gateway")

PLC_HOST = os.environ.get("PLC_HOST", "plc")
PLC_PORT = int(os.environ.get("S7_PORT", "102"))
OPC_ENDPOINT = os.environ.get("OPC_ENDPOINT", "opc.tcp://0.0.0.0:4840/kaaval/")
NAMESPACE_URI = tags.NAMESPACE_URI          # per active process (KAAVAL_PROCESS)
POLL_HZ = float(os.environ.get("GATEWAY_POLL_HZ", "5"))
FLOAT_TOL = 1e-3


def _vtype(tag: tags.Tag) -> ua.VariantType:
    return ua.VariantType.Float if tag.kind == "REAL" else ua.VariantType.Boolean


def _variant(tag: tags.Tag, value):
    if tag.kind == "REAL":
        return ua.Variant(float(value), ua.VariantType.Float)
    return ua.Variant(bool(value), ua.VariantType.Boolean)


def _changed(tag: tags.Tag, a, b) -> bool:
    if tag.kind == "REAL":
        return abs(float(a) - float(b)) > FLOAT_TOL
    return bool(a) != bool(b)


# --- blocking S7 ops (run in an executor from the async loop) ----------------

def _s7_connect() -> Client:
    cli = Client()
    cli.connect(PLC_HOST, 0, 1, tcp_port=PLC_PORT)
    return cli


def _forward_to_plc(cli: Client, tag: tags.Tag, value, plc_buf: bytearray) -> None:
    """Write one RW tag down to the PLC over S7comm."""
    if tag.kind == "REAL":
        data = bytearray(4)
        struct.pack_into(">f", data, 0, float(value))
        cli.db_write(tags.DB_NUMBER, tag.offset, data)
    else:
        # RW bool byte is RW-only, so read-modify-write is safe (no RO bits).
        b = bytearray([plc_buf[tag.offset]])
        if value:
            b[0] |= (1 << tag.bit)
        else:
            b[0] &= ~(1 << tag.bit) & 0xFF
        cli.db_write(tags.DB_NUMBER, tag.offset, b)


async def build_server() -> tuple[Server, dict]:
    server = Server()
    await server.init()
    server.set_endpoint(OPC_ENDPOINT)
    server.set_server_name(f"Kaaval Gateway ({tags.OBJECT_NAME})")
    idx = await server.register_namespace(NAMESPACE_URI)

    station = await server.nodes.objects.add_object(
        ua.NodeId(tags.OBJECT_NAME, idx), tags.OBJECT_NAME)
    nodes: dict[str, object] = {}
    for t in tags.TAGS:
        node = await station.add_variable(
            ua.NodeId(t.opc_id, idx),
            t.name,
            _variant(t, 0.0 if t.kind == "REAL" else False),
            varianttype=_vtype(t),
        )
        if t.access == "RW":
            await node.set_writable()
        nodes[t.name] = node
    LOG.info("OPC UA server ready at %s (ns=%d, %d tags)", OPC_ENDPOINT, idx, len(nodes))
    return server, nodes


async def run() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    loop = asyncio.get_running_loop()
    server, nodes = await build_server()

    # Connect to the PLC with retry (it may come up slightly after the gateway).
    cli: Client | None = None
    while cli is None:
        try:
            cli = await loop.run_in_executor(None, _s7_connect)
            LOG.info("Connected to PLC %s:%d over S7comm", PLC_HOST, PLC_PORT)
        except Exception as e:
            LOG.warning("PLC connect failed (%s); retrying in 2s", e)
            await asyncio.sleep(2)

    # last_seen tracks the value we last set/forwarded for each RW node, so we
    # can tell an operator's OPC UA write apart from the steady mirror.
    last_seen = {t.name: (0.0 if t.kind == "REAL" else False) for t in tags.RW_TAGS}
    dt = 1.0 / POLL_HZ

    async with server:
        # Seed last_seen from the PLC's current RW values.
        first = await loop.run_in_executor(None, cli.db_read, tags.DB_NUMBER, 0, tags.DB_SIZE)
        for t in tags.RW_TAGS:
            v = tags.read_tag(first, t)
            last_seen[t.name] = v
            await nodes[t.name].write_value(_variant(t, v))

        while True:
            try:
                plc_buf = await loop.run_in_executor(
                    None, cli.db_read, tags.DB_NUMBER, 0, tags.DB_SIZE)
            except Exception as e:
                LOG.warning("PLC read failed (%s); reconnecting", e)
                try:
                    cli = await loop.run_in_executor(None, _s7_connect)
                except Exception:
                    pass
                await asyncio.sleep(dt)
                continue

            # RO: always mirror PLC -> OPC UA.
            for t in tags.RO_TAGS:
                await nodes[t.name].write_value(_variant(t, tags.read_tag(plc_buf, t)))

            # RW: forward operator writes down, otherwise reflect PLC up.
            for t in tags.RW_TAGS:
                node_val = await nodes[t.name].read_value()
                plc_val = tags.read_tag(plc_buf, t)
                if _changed(t, node_val, last_seen[t.name]):
                    # An OPC UA client changed it -> push to the PLC.
                    await loop.run_in_executor(None, _forward_to_plc, cli, t, node_val, plc_buf)
                    last_seen[t.name] = node_val
                    LOG.info("forwarded %s=%s to PLC", t.name, node_val)
                elif _changed(t, plc_val, node_val):
                    # PLC changed underneath us (e.g. attacker direct write).
                    await nodes[t.name].write_value(_variant(t, plc_val))
                    last_seen[t.name] = plc_val

            await asyncio.sleep(dt)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
