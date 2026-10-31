#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Switch the running deployment between plants (one plant at a time).
#
#   scripts/use_profile.sh pump      # water pumping station (profile #1, default)
#   scripts/use_profile.sh reactor   # jacketed chemical reactor (profile #2)
#
# Sets the simulator process (KAAVAL_PROCESS) for the plant containers AND the
# matching deployment profile (KAAVAL_PROFILE) for the backend, then resets to a
# clean baseline. The detection/agent/gating/response engine is unchanged — only
# the plant + its profile differ, which is the whole point.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PLANT="${1:-}"
case "$PLANT" in
  pump)    PROFILE="profiles/pumpstation.yaml" ;;
  reactor) PROFILE="profiles/reactor.yaml" ;;
  *) echo "usage: $0 <pump|reactor>" >&2; exit 2 ;;
esac

API="${KAAVAL_API:-http://localhost:8000}"
echo "▶ switching to plant: $PLANT   (profile: $PROFILE)"

# 1) Pin the process for the sim containers (.env -> compose ${KAAVAL_PROCESS})
#    and for the ews OT scripts (sim/active_process, read live via the ro mount).
printf 'KAAVAL_PROCESS=%s\n' "$PLANT" > .env
printf '%s\n' "$PLANT" > sim/active_process

# 2) Rebuild + recreate the plant (new process) — plc reseeds to its baseline,
#    gateway re-serves the new node set, sensor re-attaches to the ews netns.
#    --build ensures the image carries the current sim/ (all process modules).
echo "  rebuilding + recreating plc / gateway / sensor …"
docker compose up -d --build --force-recreate plc gateway sensor >/dev/null 2>&1

# 3) Restart the native backend bound to the matching profile.
echo "  restarting backend (KAAVAL_PROFILE=$PROFILE) …"
pkill -f "uvicorn app.main:app" 2>/dev/null || true
sleep 2
( cd backend && KAAVAL_PROFILE="$ROOT/$PROFILE" nohup ../.venv/bin/uvicorn app.main:app \
    --host 0.0.0.0 --port 8000 > /tmp/kaaval_backend.log 2>&1 & )

# 4) Wait for the backend + a live OPC read, then reset to a clean baseline.
echo "  waiting for backend + plant …"
for _ in $(seq 1 60); do
  v=$(curl -s --max-time 4 "$API/api/state" 2>/dev/null \
        | python3 -c "import sys,json;d=json.load(sys.stdin);s=d.get('status');print(1 if s and s!='unknown' else 0)" 2>/dev/null || echo 0)
  [ "$v" = "1" ] && break
  sleep 2
done
curl -s --max-time 40 -X POST "$API/api/reset" >/dev/null || true
sleep 2

name=$(curl -s --max-time 5 "$API/api/profile" | python3 -c "import sys,json;print(json.load(sys.stdin)['name'])" 2>/dev/null || echo "?")
echo "✓ active: $name"
curl -s --max-time 5 "$API/api/profile" | python3 -c "
import sys,json
p=json.load(sys.stdin); s=p.get('safety',{})
print(f\"  protected variable: {s.get('label')} ({s.get('variable')}) band {s.get('band')} danger {s.get('danger')} {s.get('unit') or ''}\")" 2>/dev/null || true
echo "  (open the SOC at http://localhost:5173/ — it now shows the $name plant)"
