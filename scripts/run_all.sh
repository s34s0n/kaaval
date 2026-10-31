#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Bring up the whole Kaaval demo: containers (plant + sensor + attacker),
# warm the model, then start the native backend and frontend.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

echo "==> Containers (plc, gateway, ews, c2, attacker, sensor)"
docker compose up -d --build
# Recreate the sensor so it binds to the current ews network namespace.
docker compose up -d --force-recreate sensor

echo "==> Warming the model"
bash scripts/warm_model.sh || echo "(warm skipped — is Ollama running?)"

echo "==> Backend (FastAPI on :8000)"
( cd backend && nohup ../.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 \
    > /tmp/kaaval_backend.log 2>&1 & echo "backend pid $!" )

echo "==> Frontend (Vite on :5173)"
( cd frontend && [ -d node_modules ] || npm install
  nohup npm run dev > /tmp/kaaval_frontend.log 2>&1 & echo "frontend pid $!" )

echo
echo "Kaaval is starting. Open the dashboard:  http://localhost:5173"
echo "  backend log : /tmp/kaaval_backend.log"
echo "  frontend log: /tmp/kaaval_frontend.log"
echo "  stop natives: pkill -f 'uvicorn app.main:app'; pkill -f vite"
