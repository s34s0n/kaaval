#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Phase 4 observable — run detection + correlation over the current Zeek logs.
set -uo pipefail
cd "$(dirname "$0")/../backend"
exec ../.venv/bin/python -m app.detect
