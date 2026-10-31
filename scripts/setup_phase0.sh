#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Phase 0 setup for Kaaval (by Traboda).
# Idempotent: installs the Python toolchain (uv + Python 3.12), installs and
# starts Ollama (native, Metal GPU), pulls the locked model, and warms it.
# Requires internet for this one-time setup; the running product is offline.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
MODEL_TAG="${MODEL_TAG:-qwen3:30b-a3b}"
PY_VERSION="3.12"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

command -v brew >/dev/null 2>&1 || die "Homebrew not found. Install from https://brew.sh first."

# ---------------------------------------------------------------------------
say "1/4  Python toolchain (uv + Python ${PY_VERSION})"
# ---------------------------------------------------------------------------
if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv via Homebrew ..."
  brew install uv
else
  echo "uv already installed: $(uv --version)"
fi

uv python install "$PY_VERSION"
if [ ! -d ".venv" ]; then
  echo "Creating .venv on Python ${PY_VERSION} ..."
  uv venv --python "$PY_VERSION"
else
  echo ".venv already exists."
fi
echo "Project Python: $(.venv/bin/python --version 2>/dev/null || echo 'unknown')"

# ---------------------------------------------------------------------------
say "2/4  Ollama (native, Metal GPU)"
# ---------------------------------------------------------------------------
# NOTE: we deliberately do NOT use `brew install ollama` (the formula). As of
# v0.30.6 the Homebrew bottle ships without the `llama-server` runner, so the
# server returns HTTP 500 on every generate ("llama-server binary not found").
# We install the official prebuilt tarball, which bundles the runner + libs.
OLLAMA_VERSION="${OLLAMA_VERSION:-v0.30.6}"
OLLAMA_DIR="${OLLAMA_DIR:-$HOME/.local/ollama}"
OLLAMA_TGZ_URL="https://github.com/ollama/ollama/releases/download/${OLLAMA_VERSION}/ollama-darwin.tgz"

# Remove a previously-installed broken Homebrew formula if present.
if brew list --formula 2>/dev/null | grep -qx ollama; then
  warn "Removing broken Homebrew 'ollama' formula (no llama-server runner)."
  brew services stop ollama >/dev/null 2>&1 || true
  brew uninstall ollama >/dev/null 2>&1 || true
fi

if [ ! -x "${OLLAMA_DIR}/ollama" ] || [ ! -x "${OLLAMA_DIR}/llama-server" ]; then
  echo "Installing official Ollama ${OLLAMA_VERSION} to ${OLLAMA_DIR} ..."
  mkdir -p "$OLLAMA_DIR"
  curl -fsSL -o /tmp/ollama-darwin.tgz "$OLLAMA_TGZ_URL"
  tar xzf /tmp/ollama-darwin.tgz -C "$OLLAMA_DIR"
  chmod +x "$OLLAMA_DIR/ollama" "$OLLAMA_DIR/llama-server" "$OLLAMA_DIR/llama-quantize" 2>/dev/null || true
  xattr -dr com.apple.quarantine "$OLLAMA_DIR" 2>/dev/null || true
else
  echo "Official Ollama already present at ${OLLAMA_DIR}."
fi

# Put a wrapper on PATH (execs the real binary so it finds its sibling runner).
WRAPPER="$(brew --prefix)/bin/ollama"
printf '#!/bin/sh\nexec "%s/ollama" "$@"\n' "$OLLAMA_DIR" > "$WRAPPER"
chmod +x "$WRAPPER"
hash -r 2>/dev/null || true
echo "ollama: $("$OLLAMA_DIR/ollama" --version 2>/dev/null | grep -i 'client version' || echo "${OLLAMA_VERSION}")"

# Start the server if it isn't already answering.
if ! curl -fsS "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
  echo "Starting Ollama server ..."
  nohup "$OLLAMA_DIR/ollama" serve >/tmp/ollama.log 2>&1 &
  for i in $(seq 1 30); do
    if curl -fsS "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then break; fi
    sleep 1
  done
fi
curl -fsS "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1 \
  || die "Ollama did not become ready at ${OLLAMA_HOST}. Check /tmp/ollama.log."
echo "Ollama is serving at ${OLLAMA_HOST}."

# ---------------------------------------------------------------------------
say "3/4  Pull model (${MODEL_TAG})"
# ---------------------------------------------------------------------------
if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$MODEL_TAG"; then
  echo "Model ${MODEL_TAG} already present."
elif ollama pull "$MODEL_TAG"; then
  echo "Pulled ${MODEL_TAG}."
else
  warn "Could not pull ${MODEL_TAG}. Available Qwen3 tags on the registry vary;"
  warn "falling back requires a manual choice. Listing local models:"
  ollama list || true
  die "Pull failed. Re-run with MODEL_TAG=<current qwen3 ~30B tag> set, and update config.py."
fi

echo
echo "Installed models:"
ollama list

# ---------------------------------------------------------------------------
say "4/4  Warm the model"
# ---------------------------------------------------------------------------
OLLAMA_HOST="$OLLAMA_HOST" MODEL_TAG="$MODEL_TAG" bash "$REPO_ROOT/scripts/warm_model.sh"

say "Phase 0 setup complete."
echo "Next: python3 scripts/phase0_smoke.py"
