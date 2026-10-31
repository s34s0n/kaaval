#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Keep the Kaaval model resident in GPU memory so the first on-stage response
# never cold-starts. Sends a 1-token request with keep_alive=-1 (load forever),
# then prints `ollama ps` to confirm the model is loaded.
set -euo pipefail

OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
MODEL_TAG="${MODEL_TAG:-qwen3:30b-a3b}"

echo "Warming ${MODEL_TAG} on ${OLLAMA_HOST} (keep_alive=-1) ..."

if ! curl -fsS "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
  echo "ERROR: Ollama not reachable at ${OLLAMA_HOST}. Start it with: ollama serve" >&2
  exit 1
fi

# num_predict:1 -> minimal generation; keep_alive:-1 -> stay resident forever.
curl -fsS "${OLLAMA_HOST}/api/generate" \
  -H 'Content-Type: application/json' \
  -d "{\"model\":\"${MODEL_TAG}\",\"prompt\":\"ok\",\"stream\":false,\"keep_alive\":-1,\"options\":{\"num_predict\":1}}" \
  >/dev/null

echo "Done. Currently loaded models:"
ollama ps
