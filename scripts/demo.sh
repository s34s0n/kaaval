#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Launch the full IT->OT attack chain and point the operator at the live result.
set -euo pipefail
API="${ATTACKER_API:-http://localhost:8090}"
SOC="${KAAVAL_SOC:-http://localhost:8080}"

echo "Launching the IT->OT attack chain via ${API}/run ..."
if curl -fsS -X POST "${API}/run" >/dev/null 2>&1; then
  echo "  attack launched."
else
  echo "  could not reach the attacker API at ${API}." >&2
  echo "  Is the stack up? Run 'make up' first." >&2
  exit 1
fi

cat <<EOF

Watch it unfold (a single correlated IT+OT incident forms in ~30-60s):

  Kaaval SOC    ${SOC}/            log in with token: kaaval-operator
                                     (or open ${SOC}/?token=kaaval-operator)
  Range console ${SOC}/range        live process + kill-chain view

The OT recovery action is HELD at the human-approval gate. Approve it as a
DISTINCT approver (token: kaaval-approver) to watch the plant recover on screen.
EOF
