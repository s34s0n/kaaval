#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Phase 5 observable — run the Triage -> Investigation -> Response agent pipeline
# (local Ollama) over the latest correlated incident, with OT-safety gating.
set -uo pipefail
cd "$(dirname "$0")/../backend"
exec ../.venv/bin/python -m app.pipeline
