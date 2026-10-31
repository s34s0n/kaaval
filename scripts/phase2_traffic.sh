#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Phase 2 traffic generator — drives IT and OT flows from/at the engineering
# workstation so the Zeek sidecar captures them. All flows cross the ews eth0,
# so the single sidecar sees the whole IT->OT chain. (Manual traffic; the
# orchestrated, ATT&CK-tagged attack chain arrives in Phase 3.)
set -uo pipefail

DC="docker compose"
say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

say "IT / SSH  — c2 logs into the ews over SSH"
$DC exec -T c2 sshpass -p engineer \
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  engineer@ews 'hostname; id; echo "[ssh] logged in"' || echo "ssh step returned $?"

say "IT / TLS  — ews opens a TLS connection to c2:443"
$DC exec -T ews curl -ks https://c2/ && echo

say "IT / SCAN — ews port-scans the OT subnet (plc, gateway, c2)"
$DC exec -T ews nmap -sT -Pn -p 22,102,443,4840 plc gateway c2 | tail -n 20

say "OT / OPC UA browse — ews browses the gateway address space"
$DC exec -T ews python3 /opt/ot/browse_opcua.py

say "OT / S7 read — ews reads the PLC DB directly over S7comm (anomalous)"
$DC exec -T ews python3 /opt/ot/read_s7.py

say "Done. Give Zeek a moment to flush, then run scripts/phase2_check.sh"
