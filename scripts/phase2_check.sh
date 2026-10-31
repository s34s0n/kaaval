#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Phase 2 observable — confirm the five flows landed in the right Zeek JSON logs
# and print a sample row from each. PASS only if every expected log is present
# and non-empty.
set -uo pipefail

LOGDIR="${LOGDIR:-./logs}"

# label  -> primary log file (OPC UA browse filename is resolved at runtime)
check() {
  local label="$1" file="$2"
  local path="$LOGDIR/$file"
  if [[ -s "$path" ]]; then
    printf '\033[1;32mPASS\033[0m %-22s %s (%d lines)\n' "$label" "$file" "$(wc -l < "$path")"
    echo "     sample: $(tail -n 1 "$path" | cut -c1-160)"
    return 0
  fi
  printf '\033[1;31mFAIL\033[0m %-22s %s missing/empty\n' "$label" "$file"
  return 1
}

echo "Kaaval Phase 2 — Zeek capture check ($LOGDIR)"
echo "Logs present:"; ls -1 "$LOGDIR"/*.log 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/^/  /'
echo

rc=0
check "IT/SSH"          ssh.log          || rc=1
check "IT/TLS"          ssl.log          || rc=1
check "IT/SCAN (conn)"  conn.log         || rc=1
# OPC UA: primary log always present; browse detail file name confirmed via ls.
check "OT/OPC UA"       opcua_binary.log || rc=1
# S7comm: cotp.log is the transport, s7comm.log the application layer.
check "OT/S7 (cotp)"    cotp.log         || rc=1
check "OT/S7 (s7comm)"  s7comm.log       || rc=1

echo
if [[ $rc -eq 0 ]]; then
  echo -e "\033[1;32mPHASE 2 PASS\033[0m — IT and OT flows captured from one sidecar."
else
  echo -e "\033[1;31mPHASE 2 INCOMPLETE\033[0m — see FAIL lines above."
fi
exit $rc
