# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Generic S7/OPC tag spec — process-agnostic.

Holds the ``Tag`` dataclass and the big-endian struct pack/unpack helpers used by
every process model. The actual tag *list* and DB layout are per-process and live
in ``sim/processes/<name>.py``; this module is the shared machinery so the encoding
can never drift between processes.

ACCESS semantics (unchanged across processes):
  - RO  = physics output. The PLC physics loop *writes* it; clients read it.
  - RW  = control input. Clients (gateway / HMI / direct-S7 attacker) *write* it;
          the physics loop only *reads* it (never writes an RW tag, or it would
          clobber client writes). RW and RO bools live in separate bytes so a
          client writing the RW byte can't corrupt RO status bits and vice versa.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class Tag:
    name: str          # canonical tag name (used verbatim as the OPC UA node name)
    kind: str          # "REAL" or "BOOL"
    offset: int        # byte offset into the DB (BOOL: the byte holding the bit)
    bit: int | None    # bit index for BOOL, else None
    access: str        # "RO" or "RW"
    unit: str          # engineering unit (for docs / display)
    opc_id: str        # OPC UA string NodeId identifier (ns=2;s=<opc_id>)


# --- struct pack/unpack helpers (big-endian, in place on the DB buffer) ------

def read_real(buf: bytearray | bytes, offset: int) -> float:
    return struct.unpack_from(">f", buf, offset)[0]


def write_real(buf: bytearray, offset: int, value: float) -> None:
    struct.pack_into(">f", buf, offset, float(value))


def read_bool(buf: bytearray | bytes, byte: int, bit: int) -> bool:
    return bool(buf[byte] & (1 << bit))


def write_bool(buf: bytearray, byte: int, bit: int, value: bool) -> None:
    if value:
        buf[byte] |= (1 << bit)
    else:
        buf[byte] &= ~(1 << bit) & 0xFF


def read_tag(buf: bytearray | bytes, tag: Tag):
    if tag.kind == "REAL":
        return read_real(buf, tag.offset)
    return read_bool(buf, tag.offset, tag.bit)


def write_tag(buf: bytearray, tag: Tag, value) -> None:
    if tag.kind == "REAL":
        write_real(buf, tag.offset, value)
    else:
        write_bool(buf, tag.offset, tag.bit, bool(value))


def snapshot(tags: list[Tag], buf: bytearray | bytes) -> dict:
    """Decode the whole DB into a {tag_name: value} dict."""
    return {t.name: read_tag(buf, t) for t in tags}
