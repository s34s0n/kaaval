#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval prerequisite check + .env bootstrap (macOS / Linux / WSL2).
set -euo pipefail

red()  { printf '\033[31m%s\033[0m\n' "$1"; }
grn()  { printf '\033[32m%s\033[0m\n' "$1"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$1"; }

fail=0

# 1) Docker Engine present + running
if ! command -v docker >/dev/null 2>&1; then
  red "✗ docker not found. Install Docker Desktop (Mac/Windows) or Docker Engine (Linux)."
  fail=1
else
  ver="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
  if [ -z "$ver" ]; then
    red "✗ Docker is installed but the daemon is not reachable. Start Docker and retry."
    fail=1
  else
    grn "✓ Docker daemon $ver"
  fi
fi

# 2) Compose v2 plugin
if docker compose version >/dev/null 2>&1; then
  grn "✓ docker compose $(docker compose version --short 2>/dev/null || echo v2)"
else
  red "✗ 'docker compose' (v2) not available. Update Docker; the legacy docker-compose v1 is not supported."
  fail=1
fi

# 3) .env
if [ ! -f .env ]; then
  cp .env.example .env
  ylw "• created .env from .env.example"
fi

# 4) A usable LLM configuration
provider="$(grep -E '^KAAVAL_LLM_PROVIDER=' .env | head -1 | cut -d= -f2- | tr -d '[:space:]' || true)"
provider="${provider:-openrouter}"
key="$(grep -E '^OPENROUTER_API_KEY=' .env | head -1 | cut -d= -f2- | tr -d '[:space:]' || true)"
if [ "$provider" = "openrouter" ] && [ -z "$key" ]; then
  ylw "• OPENROUTER_API_KEY is empty in .env."
  ylw "  Add a key from https://openrouter.ai/keys to get agent narratives."
  ylw "  (The stack still runs and incidents still form & gate without it.)"
elif [ "$provider" = "local" ]; then
  grn "✓ LLM provider = local (Ollama). Use 'make local', or run Ollama on the host."
else
  grn "✓ LLM provider = $provider"
fi

if [ "$fail" -ne 0 ]; then
  echo
  red "Prerequisites missing — fix the ✗ items above, then re-run 'make up'."
  exit 1
fi
grn "Ready. Run 'make up' to build and start Kaaval."
