# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Kaaval backend configuration — paths, thresholds, and severity ranks."""

from __future__ import annotations

import os

# Repo root = two levels up from this file (backend/app/config.py).
_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))

# Zeek JSON logs (host-mounted ./logs) and the SQLite store.
LOG_DIR = os.environ.get("KAAVAL_LOG_DIR", os.path.join(REPO_ROOT, "logs"))
DB_PATH = os.environ.get("KAAVAL_DB", os.path.join(REPO_ROOT, "backend", "kaaval.sqlite"))

# Editable stores (UI refactor): the rules store (hot-reloaded) and asset map.
RULES_PATH = os.environ.get("KAAVAL_RULES", os.path.join(REPO_ROOT, "backend", "rules.json"))
ASSETS_PATH = os.environ.get("KAAVAL_ASSETS", os.path.join(REPO_ROOT, "backend", "assets.json"))
# Managed-inventory overlay (user-added assets + network config), kept separate
# from the authoritative profile so the UI can manage it without rewriting the
# commented profile yaml. Merged into the asset list + the network map.
INVENTORY_PATH = os.environ.get("KAAVAL_INVENTORY", os.path.join(REPO_ROOT, "backend", "inventory.json"))

# Deployment profile (assets + per-protocol authorization). The engine is generic;
# this declares the environment. Swap the file to retarget a different plant.
PROFILE_PATH = os.environ.get("KAAVAL_PROFILE",
                              os.path.join(REPO_ROOT, "profiles", "pumpstation.yaml"))

# Gateway OPC UA endpoint (authorized control path the backend uses).
OPC_ENDPOINT = os.environ.get("OPC_ENDPOINT", "opc.tcp://127.0.0.1:4840/kaaval/")

# Red-team attacker HTTP API (lab affordance the Range Console drives). Native run
# reaches it on localhost; the containerized backend sets this to http://attacker:8090.
ATTACKER_URL = os.environ.get("KAAVAL_ATTACKER_URL", "http://localhost:8090").rstrip("/")

# Compose project + file used by the lab executor's docker-exec primitive and by
# reset. Pinned to "kaaval" (docker-compose.yml carries `name: kaaval`) so the
# containerized backend can reach its sibling containers through the mounted
# docker socket regardless of the host directory name.
COMPOSE_PROJECT = os.environ.get("KAAVAL_COMPOSE_PROJECT", "kaaval")
COMPOSE_FILE = os.environ.get("KAAVAL_COMPOSE_FILE", os.path.join(REPO_ROOT, "docker-compose.yml"))

# Local model server (Ollama, native, Metal GPU). Fully offline.
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL_TAG = os.environ.get("KAAVAL_MODEL", "qwen3:30b-a3b")
KEEP_ALIVE = -1            # keep the model resident; no cold start on stage
AGENT_TEMPERATURE = 0.2    # low temperature for stable, sensible JSON

# --- LLM provider (runtime-selectable: local Ollama OR the Claude API) -------
# Default is LOCAL (fully offline / air-gapped). Selecting the API is opt-in and
# sends incident data off-box — it breaks the offline guarantee. Runtime choice is
# persisted to LLM_CONFIG_PATH (gitignored).
LLM_CONFIG_PATH = os.environ.get("KAAVAL_LLM_CONFIG", os.path.join(REPO_ROOT, "backend", "llm.json"))
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_MODELS = ["claude-sonnet-4-6", "claude-opus-4-8", "claude-haiku-4-5-20251001"]
ANTHROPIC_DEFAULT_MODEL = "claude-sonnet-4-6"
ANTHROPIC_MAX_TOKENS = 2048

# OpenRouter (OpenAI-compatible). Sends data off-box like the Claude path, but lets
# you use a FREE hosted model with just an API key — a no-cost cloud option for
# demos without a local GPU. Free model ids carry the ":free" suffix.
OPENROUTER_URL = os.environ.get("KAAVAL_OPENROUTER_URL",
                                "https://openrouter.ai/api/v1/chat/completions")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
# Free models churn on OpenRouter — keep a few current ":free" ids; the UI also
# lets you type any model slug. Verified free at time of writing.
OPENROUTER_MODELS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "moonshotai/kimi-k2.6:free",
    "google/gemma-4-31b-it:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
]
OPENROUTER_DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct:free"

# --- default LLM provider/model (env-driven, so .env picks the provider) ------
# OpenRouter is the shipped default: a colleague only needs an OPENROUTER_API_KEY
# (no local GPU/Ollama). Set KAAVAL_LLM_PROVIDER=local to go fully offline on
# Ollama. KAAVAL_LLM_MODEL overrides the active provider's model (any slug).
# `or` (not a 2-arg get) so an env var present-but-EMPTY — which is how compose
# passes an unset "${VAR:-}" — falls back to the default instead of becoming "".
LLM_DEFAULT_PROVIDER = (os.environ.get("KAAVAL_LLM_PROVIDER") or "openrouter").strip().lower()
if LLM_DEFAULT_PROVIDER not in ("local", "anthropic", "openrouter"):
    LLM_DEFAULT_PROVIDER = "openrouter"
# A cloud provider implies cloud mode (routes through the pseudonymizing egress
# boundary); "local" implies local mode. KAAVAL_LLM_MODE can force either.
_DEFAULT_MODE = "local" if LLM_DEFAULT_PROVIDER == "local" else "cloud"
LLM_MODEL_OVERRIDE = os.environ.get("KAAVAL_LLM_MODEL", "").strip()

# Detection thresholds.
BEACON_MIN = int(os.environ.get("KAAVAL_BEACON_MIN", "3"))      # TLS+DNS hits to one dest
SCAN_MIN_TARGETS = int(os.environ.get("KAAVAL_SCAN_MIN", "4"))  # distinct (host,port)

# Correlation, multi-scale (P5):
#  - BURST window: events this close together (and sharing a host) are the same
#    contemporaneous activity. Tight, so a repeat of the SAME action later forms
#    its own incident. Also used by rules_engine to split per-burst events.
CORRELATION_WINDOW_S = int(os.environ.get("KAAVAL_CORR_WINDOW", "30"))
#  - CAMPAIGN window: a wider, rolling, entity-linked window. A later event that
#    shares a host with an open cluster AND introduces a NEW stage (a rule not yet
#    in that cluster) is treated as the campaign PROGRESSING — so a low-and-slow
#    IT->OT intrusion (hours/days between the foothold and the OT manipulation)
#    still fuses into ONE incident, while a mere repeat of an existing stage does
#    not. Rolling = measured from the cluster's most recent event, not its first.
CAMPAIGN_WINDOW_S = int(os.environ.get("KAAVAL_CAMPAIGN_WINDOW", "86400"))   # 24h/hop

# After remediation, wait this long for Zeek to flush a FRESH window of telemetry
# before judging whether detection has gone quiet (the authoritative "resolved").
RESOLUTION_SETTLE_S = int(os.environ.get("KAAVAL_RESOLUTION_SETTLE", "8"))

# --- API security -----------------------------------------------------------
# CORS: only these browser origins may call the API. Comma-separated env override;
# default covers the Vite dev server. Never widen to "*" once auth is enabled.
CORS_ORIGINS = [o.strip() for o in os.environ.get(
    "KAAVAL_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173").split(",") if o.strip()]

# --- Authentication / RBAC (mandatory, fail-closed) -------------------------
# Auth is REQUIRED on every mutating request. Bearer tokens map to a principal
# {name, role}; roles ascend viewer < operator < approver < admin. Token store:
# inline JSON in KAAVAL_AUTH_TOKENS, or a gitignored file (backend/auth.json),
# each mapping token -> {"name":..,"role":..}.
AUTH_TOKENS_ENV = os.environ.get("KAAVAL_AUTH_TOKENS", "")
AUTH_TOKENS_PATH = os.environ.get("KAAVAL_AUTH_TOKENS_FILE", os.path.join(REPO_ROOT, "backend", "auth.json"))
# Legacy single token (back-compat) — treated as an admin token if set.
AUTH_TOKEN = os.environ.get("KAAVAL_AUTH_TOKEN", "").strip()
# DEV MODE: only when explicitly enabled, an un-tokened request is treated as a
# local admin ("dev") so the demo runs without provisioning tokens. UNSET (prod)
# => fail closed: no token, no mutating request. NEVER enable in production.
DEV_MODE = os.environ.get("KAAVAL_DEV", "").strip().lower() not in ("", "0", "false", "no")

# DEMO USERS: when enabled AND no tokens are otherwise provisioned, seed three fixed
# demo bearer tokens — admin / approver / operator — so the gate + separation of
# duties are demonstrable immediately (log in as the operator, approve as a DISTINCT
# approver). This keeps auth fail-closed (unlike DEV_MODE, which makes every caller
# an admin). OFF by default; the demo compose turns it on. NEVER enable in production.
SEED_DEMO_USERS = os.environ.get("KAAVAL_SEED_DEMO_USERS", "").strip().lower() in ("1", "true", "yes", "on")
DEMO_TOKENS = {
    "kaaval-admin": {"name": "Demo Admin", "role": "admin"},
    "kaaval-approver": {"name": "Demo Approver", "role": "approver"},
    "kaaval-operator": {"name": "Demo Operator", "role": "operator"},
}

# Range/attack affordance is a LAB tool (it issues a direct OT write). It is
# admin-gated AND can be compiled out of a production build with KAAVAL_RANGE=0.
RANGE_ENABLED = os.environ.get("KAAVAL_RANGE", "1").strip().lower() not in ("0", "false", "no")

# --- Cloud LLM egress boundary ----------------------------------------------
# llm.mode = local | cloud. Cloud egress is admin-enabled and routes through the
# single sanitizing/audited boundary (egress.py). Default local.
LLM_DEFAULT_MODE = (os.environ.get("KAAVAL_LLM_MODE") or _DEFAULT_MODE).strip().lower()
# Field paths (dot-notation) stripped from any bundle/evidence before it leaves
# the box, on top of pseudonymization. Comma-separated env override.
EGRESS_DENYLIST = [s.strip() for s in os.environ.get(
    "KAAVAL_EGRESS_DENYLIST",
    "answers,TTLs,uid,parsed_fields.payload,parsed_fields.query,raw").split(",") if s.strip()]

# --- CVE / NVD asset enrichment (F3) ----------------------------------------
# CPE -> CVE lookups. ONLY the CPE string ever leaves the box — never an asset
# name, IP, MAC, or count ("is there a CVE for this CPE", not "this plant runs
# three of these"). Cloud mode queries NVD through the egress boundary; local mode
# reads a shipped offline snapshot. Same interface both ways. Results cache locally
# keyed on CPE so we never re-query the same CPE.
DATA_DIR = os.path.join(REPO_ROOT, "backend", "app", "data")
# SIEM / syslog CEF forwarding (F6). The SIEM is an INTERNAL, customer-configured
# destination ON their premises — it legitimately carries REAL asset identity and
# does NOT go through the cloud pseudonymizer (see CLAUDE.md "Trust boundaries").
# Off unless an admin configures+enables a target. Config (no secrets) persists here.
SIEM_CONFIG_PATH = os.environ.get("KAAVAL_SIEM_CONFIG", os.path.join(REPO_ROOT, "backend", "siem.json"))

# Executor adapters (F8): HOW an approved, gated, code-derived action actually runs.
# Selecting an adapter changes nothing about whether/when an action executes — the
# gate stays in front. Profile `executors:{it,ot}` wins; these are the fallback.
# "lab" = the docker-exec reference adapter (demo plant). Real integrations (e.g.
# "firewall_rest") are honestly labeled and fail closed when unconfigured.
EXECUTOR_IT_ADAPTER = os.environ.get("KAAVAL_EXECUTOR_IT", "lab")
EXECUTOR_OT_ADAPTER = os.environ.get("KAAVAL_EXECUTOR_OT", "lab")
FIREWALL_API_URL = os.environ.get("KAAVAL_FIREWALL_API_URL", "")     # off/stubbed unless set
FIREWALL_API_TOKEN = os.environ.get("KAAVAL_FIREWALL_API_TOKEN", "")

# Response playbooks (F5): profile-bound, versioned YAML keyed on technique/rule.
# A playbook PROPOSES an ordered sequence; it never executes — every action still
# routes through the existing gate + per-step human approval.
PLAYBOOKS_DIR = os.environ.get("KAAVAL_PLAYBOOKS", os.path.join(REPO_ROOT, "backend", "app", "playbooks"))
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")   # optional; only raises NVD rate limits
NVD_SNAPSHOT_PATH = os.environ.get("KAAVAL_NVD_SNAPSHOT", os.path.join(DATA_DIR, "nvd_snapshot.json"))
OUI_PATH = os.environ.get("KAAVAL_OUI", os.path.join(DATA_DIR, "oui.json"))
CPE_MAP_PATH = os.environ.get("KAAVAL_CPE_MAP", os.path.join(DATA_DIR, "cpe_map.yaml"))

# Severity ordering (low -> critical).
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def max_severity(severities) -> str:
    best = "info"
    for s in severities:
        if SEVERITY_RANK.get(s, 0) > SEVERITY_RANK.get(best, 0):
            best = s
    return best
