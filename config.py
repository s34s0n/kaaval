# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Shared constants for Kaaval (by Traboda) — the agentic IT/OT-SOC demo.

Single source of truth for cross-cutting values. Imported by backend code and
the Phase 0 smoke/warm tooling. The frontend has its own product-name constant
(wired in Phase 6) that must match PRODUCT_NAME here.
"""

# Branding — the one product-name constant on the Python side.
PRODUCT_NAME = "Kaaval"
PRODUCT_VENDOR = "Traboda"

# Local model server (Ollama, native on the Mac, Metal GPU). Fully offline.
OLLAMA_HOST = "http://localhost:11434"

# Locked model. If this tag cannot be pulled, setup falls back to the current
# Qwen3 ~30B tag and reports the substitution; update this value to match.
MODEL_TAG = "qwen3:30b-a3b"

# Keep the model resident in GPU memory indefinitely so the first on-stage
# response never cold-starts. Passed as `keep_alive` to the Ollama API.
KEEP_ALIVE = -1
