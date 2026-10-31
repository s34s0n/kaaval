#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# One-click demo reset — the same action the SOC/Range Reset buttons call.
# Flushes IT containment, reseeds the PLC, clears logs, recreates the sensor,
# and clears the backend incident/agent state.
set -uo pipefail
API="${KAAVAL_API:-http://localhost:8000}"
TOKEN="${KAAVAL_ADMIN_TOKEN:-kaaval-admin}"   # reset is admin-gated (demo token by default)
echo "[reset] POST ${API}/api/reset ..."
curl -s -X POST -H "Authorization: Bearer ${TOKEN}" "${API}/api/reset" >/dev/null \
  && echo "[reset] done — clean pre-attack baseline." \
  || echo "[reset] failed — is the stack up and the token valid?"
