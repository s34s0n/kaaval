#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Launch the full ATT&CK-tagged attack chain via the attacker HTTP API and print
# the resulting timeline.
set -uo pipefail

API="${ATTACKER_API:-http://localhost:8090}"

echo "Kaaval — launching attack chain via ${API}/run"
resp="$(curl -s -X POST "${API}/run")"

if command -v jq >/dev/null 2>&1; then
  echo "$resp" | jq -r '"chain ok=\(.ok) duration=\(.duration_s)s",
    (.stages[] | "  [\(.status)] \(.stage)  (\(.techniques | map(.id) | join(","))) \(.duration_s)s")'
  echo
  echo "$resp" | jq -r '.stages[] | "== \(.stage) (\(.techniques | map(.id+" "+.name) | join("; "))) ==\n\(.output)\n"'
else
  echo "$resp"
fi
