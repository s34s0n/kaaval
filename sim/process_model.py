# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Active-process physics facade.

Re-exports the ACTIVE process's ``initial_state`` and ``tick`` (selected by
``KAAVAL_PROCESS``) so ``plc.py`` keeps importing ``process_model`` unchanged.
Each plant's physics lives in ``processes/<name>.py``.
"""

from __future__ import annotations

import processes

_P = processes.load()

initial_state = _P.initial_state
tick = _P.tick

# Convenience re-exports some callers/tests may reference for the pump.
SAFETY = _P.SAFETY
