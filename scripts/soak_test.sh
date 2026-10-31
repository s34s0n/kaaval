#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Reliability soak — run the full detect→respond→recover→resolve loop N times via
# the API and report pass/fail per run. Exercises both gates (Apply IT / Approve OT),
# and records the detected-stage count, TTD/TTC, recovery, and fresh-window resolution.
# A run PASSES only if it is a cross-domain incident, the plant recovers to band, and
# fresh-telemetry verification reports resolved.
set -uo pipefail
API="${KAAVAL_API:-http://localhost:8000}"
RUNS="${1:-5}"

jq_get() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
# Profile-agnostic: the recommended actions (and which are gated) come from the
# incident itself, so the soak works for ANY plant/profile (pump or reactor).
auto_actions() { echo "$1" | python3 -c "import sys,json;print(' '.join(a['name'] for a in (json.load(sys.stdin).get('actions') or []) if not a.get('requires_human_approval')))" 2>/dev/null; }
gated_actions() { echo "$1" | python3 -c "import sys,json;print(' '.join(a['name'] for a in (json.load(sys.stdin).get('actions') or []) if a.get('requires_human_approval')))" 2>/dev/null; }

pass=0
counts=""
for run in $(seq 1 "$RUNS"); do
  echo "── run $run/$RUNS ──"
  curl -s -X POST "$API/api/reset" >/dev/null; sleep 4

  curl -s -X POST "$API/api/attack/run" >/dev/null
  # wait for the incident + agents + actions to be ready
  ready=0
  for _ in $(seq 1 60); do
    r=$(curl -s "$API/api/incident" | jq_get "1 if (d.get('agents',{}).get('response') and d.get('actions')) else 0")
    [ "$r" = "1" ] && { ready=1; break; }
    sleep 2
  done
  if [ "$ready" != "1" ]; then echo "  FAIL: agents/actions not ready"; continue; fi

  ttd=$(curl -s "$API/api/scoreboard" | jq_get "d.get('time_to_detect_s')")
  inc=$(curl -s "$API/api/incident")
  nev=$(echo "$inc" | jq_get "len((d.get('incident') or {}).get('event_ids') or [])")
  xd=$(echo "$inc" | jq_get "(d.get('incident') or {}).get('cross_domain')")
  counts="$counts $nev"

  # Apply auto (IT) actions, approve gated (OT) actions — names from the incident.
  for a in $(auto_actions "$inc"); do curl -s -X POST "$API/api/actions/$a/apply" >/dev/null; done
  for a in $(gated_actions "$inc"); do curl -s -X POST "$API/api/actions/$a/approve" >/dev/null; done

  # confirm recovery to band (thermal processes cool slower than hydraulic ones)
  svar=$(curl -s "$API/api/profile" | jq_get "d.get('safety',{}).get('variable') or 'discharge_pressure_bar'")
  ok=0; p="?"; st="?"
  for _ in $(seq 1 45); do
    s=$(curl -s "$API/api/state")
    p=$(echo "$s" | jq_get "round(d.get('$svar') or 0,2)")
    st=$(echo "$s" | jq_get "d['status']")
    [ "$st" = "ok" ] && { ok=1; break; }
    sleep 1
  done
  ttc=$(curl -s "$API/api/scoreboard" | jq_get "d.get('time_to_contain_s')")

  # fresh-window verification (detection quiet on telemetry gathered post-remediation)
  resolved="?"
  for _ in $(seq 1 8); do
    resolved=$(curl -s "$API/api/resolution" | jq_get "d.get('resolved')")
    [ "$resolved" = "True" ] && break
    sleep 2
  done

  if [ "$ok" = "1" ] && [ "$xd" = "True" ] && [ "$resolved" = "True" ]; then
    echo "  PASS  stages=${nev} cross_domain=${xd}  TTD=${ttd}s TTC=${ttc}s  pressure=${p}  resolved=${resolved}"
    pass=$((pass+1))
  else
    echo "  FAIL  stages=${nev} cross_domain=${xd}  recover=${ok}(p=${p},${st})  resolved=${resolved}"
  fi
done

curl -s -X POST "$API/api/reset" >/dev/null   # leave clean
echo
echo "stage counts per run:${counts}"
echo "SOAK: ${pass}/${RUNS} PASS"
[ "$pass" = "$RUNS" ] && exit 0 || exit 1
