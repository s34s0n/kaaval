#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Dev reset between attack runs: restore the plant to a clean baseline and clear
# the Zeek logs. Restarting the plc container reseeds DB1 with baseline values
# (setpoint 50, interlock armed). (The polished one-click reset is Phase 7.)
set -uo pipefail

echo "[reset] flushing ews containment (iptables, account lock) ..."
docker compose exec -T ews iptables -F OUTPUT 2>/dev/null || true
docker compose exec -T ews usermod -U engineer 2>/dev/null || true

echo "[reset] restarting plc to reseed baseline (setpoint=50, interlock armed) ..."
docker compose restart plc >/dev/null

echo "[reset] clearing Zeek logs ..."
find ./logs -maxdepth 1 -name '*.log' -delete 2>/dev/null || true
# Restart the sensor so it reopens fresh log files in the cleared dir.
docker compose restart sensor >/dev/null

sleep 4
echo "[reset] done. Plant baseline restored, logs cleared."
