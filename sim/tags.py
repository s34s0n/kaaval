# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Active-process tag facade.

Historically this module held the pump tag map directly. The simulator is now
pluggable: the generic machinery lives in ``tagspec`` and each plant's tag list
lives in ``processes/<name>.py``. This facade re-exports the ACTIVE process's map
(selected by ``KAAVAL_PROCESS``) so ``plc.py`` and ``gateway.py`` keep importing
``tags`` unchanged. ``docs/TAGMAP.md`` documents the pump (profile #1) layout.
"""

from __future__ import annotations

from tagspec import (Tag, read_bool, read_real, read_tag, write_bool,  # noqa: F401
                     write_real, write_tag)
from tagspec import snapshot as _snapshot
import processes

_P = processes.load()

# Identity
NAME = _P.NAME
NAMESPACE_URI = _P.NAMESPACE_URI
OBJECT_NAME = _P.OBJECT_NAME

# DB layout + tag list (per active process)
DB_NUMBER = _P.DB_NUMBER
DB_SIZE = _P.DB_SIZE
TAGS = _P.TAGS
SAFETY = _P.SAFETY

TAGS_BY_NAME: dict[str, Tag] = {t.name: t for t in TAGS}
RW_TAGS = [t for t in TAGS if t.access == "RW"]
RO_TAGS = [t for t in TAGS if t.access == "RO"]


def snapshot(buf: bytearray | bytes) -> dict:
    """Decode the active DB into {tag_name: value}."""
    return _snapshot(TAGS, buf)
