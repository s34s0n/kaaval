# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""LLM access for the agents — provider-pluggable, strict JSON, never raises.

Provider + mode are env-driven (config.LLM_DEFAULT_PROVIDER/MODE) and overridable at
runtime (persisted to config.LLM_CONFIG_PATH, minus secrets). The SHIPPED default is
OpenRouter (cloud), so a colleague needs only an API key — no local GPU. Three
providers:
  - openrouter: OpenAI-compatible cloud (the default). Off-box, so it routes through
                the single pseudonymizing + audited egress boundary (egress.py). Any
                model slug; base URL overridable via KAAVAL_OPENROUTER_URL.
  - anthropic : the Claude Messages API. Off-box — same egress boundary as above.
  - local     : Ollama on localhost (set KAAVAL_LLM_PROVIDER=local for fully offline /
                air-gapped). Uses the `format` JSON-schema grammar so output is valid
                JSON of the shape; the call never leaves the box.

mode is the single on-prem/off-prem switch: local => no outbound LLM call; cloud =>
the provider goes through egress.py (pseudonymized + logged). An unknown/empty
provider or mode fails safe to local.

`ollama_json(...)` keeps its name (callers unchanged) but dispatches to the active
provider. A transport error, missing key, or unparseable body yields (None, meta)
rather than raising, so a bad/absent model response can never crash the pipeline —
agents render a "degraded" card instead.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request

from . import config, egress

_lock = threading.Lock()
_cfg_cache: dict | None = None


# --- runtime provider config (persisted, gitignored) ------------------------

def _defaults() -> dict:
    # Provider + mode come from config (env-driven: KAAVAL_LLM_PROVIDER/MODE). The
    # shipped default is OpenRouter (cloud); KAAVAL_LLM_PROVIDER=local goes offline.
    d = {
        # mode is the SINGLE switch between cloud and local. local => the box never
        # makes an outbound LLM call; cloud => provider routes through the egress
        # boundary. Flipping this is the only change to go air-gapped.
        "mode": config.LLM_DEFAULT_MODE,                 # "local" | "cloud"
        "provider": config.LLM_DEFAULT_PROVIDER,         # "local" | "anthropic" | "openrouter"
        "local_model": config.MODEL_TAG,
        "anthropic_model": config.ANTHROPIC_DEFAULT_MODEL,
        "anthropic_api_key": config.ANTHROPIC_API_KEY,   # env seed; may be set via UI
        "openrouter_model": config.OPENROUTER_DEFAULT_MODEL,
        "openrouter_api_key": config.OPENROUTER_API_KEY,
    }
    # KAAVAL_LLM_MODEL (if set) overrides the model of whichever provider is active.
    if config.LLM_MODEL_OVERRIDE:
        d[{"local": "local_model", "anthropic": "anthropic_model",
           "openrouter": "openrouter_model"}[d["provider"]]] = config.LLM_MODEL_OVERRIDE
    return d


# API keys are SECRETS and are never persisted to disk. They are seeded from env
# vars and may be set at runtime via the UI, but live only in this process's memory
# — set_config() strips them before writing llm.json. Env always takes precedence so
# a deployment can inject keys out-of-band.
_SECRET_KEYS = ("anthropic_api_key", "openrouter_api_key")
_ENV_KEYS = {"anthropic_api_key": "ANTHROPIC_API_KEY", "openrouter_api_key": "OPENROUTER_API_KEY"}
_CONFIG_KEYS = ("mode", "provider", "local_model", "anthropic_model", "anthropic_api_key",
                "openrouter_model", "openrouter_api_key")


def get_config() -> dict:
    global _cfg_cache
    if _cfg_cache is None:
        cfg = _defaults()
        try:
            with open(config.LLM_CONFIG_PATH) as f:
                # Ignore any key a legacy/hand-edited file might still carry on disk.
                cfg.update({k: v for k, v in json.load(f).items()
                            if k in cfg and k not in _SECRET_KEYS})
        except (OSError, json.JSONDecodeError):
            pass
        # Env wins for the secrets, always.
        for sk, env in _ENV_KEYS.items():
            if os.environ.get(env):
                cfg[sk] = os.environ[env]
        _cfg_cache = cfg
    return dict(_cfg_cache)


def set_config(patch: dict) -> dict:
    global _cfg_cache
    with _lock:
        cfg = get_config()
        for k in _CONFIG_KEYS:
            if k in patch and patch[k] is not None:
                cfg[k] = patch[k]
        if cfg.get("provider") not in ("local", "anthropic", "openrouter"):
            cfg["provider"] = "local"
        if cfg.get("mode") not in ("local", "cloud"):
            cfg["mode"] = "local"
        # local mode can never carry a cloud provider — fail safe to local.
        if cfg["mode"] == "local":
            cfg["provider"] = "local"
        _cfg_cache = cfg
        try:
            os.makedirs(os.path.dirname(config.LLM_CONFIG_PATH), exist_ok=True)
            # Persist everything EXCEPT the secret — the key never touches disk.
            on_disk = {k: v for k, v in cfg.items() if k not in _SECRET_KEYS}
            with open(config.LLM_CONFIG_PATH, "w") as f:
                json.dump(on_disk, f, indent=2)
        except OSError:
            pass
        return dict(cfg)


def mode() -> str:
    return get_config().get("mode", "local")


def provider() -> str:
    """Effective provider: forced to local when mode is local (air-gapped)."""
    c = get_config()
    return c.get("provider", "local") if c.get("mode") == "cloud" else "local"


_MODEL_KEY = {"anthropic": "anthropic_model", "openrouter": "openrouter_model"}
_KEY_FIELD = {"anthropic": "anthropic_api_key", "openrouter": "openrouter_api_key"}


def active_model() -> str:
    c = get_config()
    return c.get(_MODEL_KEY.get(provider(), "local_model"), c["local_model"])


def _cloud_creds():
    """(provider, model, key) for the active cloud provider, or (None, None, None)."""
    c = get_config()
    p = provider()
    if p == "local":
        return None, None, None
    return p, c.get(_MODEL_KEY[p]), c.get(_KEY_FIELD[p])


def status() -> dict:
    """Provider/model/readiness for the UI (never leaks the API key)."""
    c = get_config()
    p = provider()
    keyfield = _KEY_FIELD.get(p)
    has_key = bool(c.get(keyfield)) if keyfield else False
    ready = True if keyfield is None else has_key
    return {
        "mode": c.get("mode", "local"),
        "provider": p,
        "model": active_model(),
        "offline": c.get("mode") == "local",
        "ready": ready,
        "has_key": has_key,
        "options": {"local": [config.MODEL_TAG], "anthropic": config.ANTHROPIC_MODELS,
                    "openrouter": config.OPENROUTER_MODELS},
    }


# --- public: provider-dispatched JSON completion (agents) -------------------

def ollama_json(system: str, user: str, schema: dict, *,
                retries: int = 1, num_predict: int = 1024,
                incident_id: str | None = None, principal: str = "agent-pipeline",
                purpose: str = "agent") -> tuple[dict | None, dict]:
    """Return (parsed_json, meta). Never raises. Local stays in-process; cloud routes
    through the single sanitizing/audited egress boundary (egress.cloud_json)."""
    if mode() == "local":
        return _ollama_json(system, user, schema, retries=retries, num_predict=num_predict)
    p, model, key = _cloud_creds()
    return egress.cloud_json(p, model, key, system, user, schema, retries=retries,
                             num_predict=num_predict, incident_id=incident_id,
                             principal=principal, purpose=purpose)


def _ollama_json(system, user, schema, *, retries=1, num_predict=1024):
    url = f"{config.OLLAMA_HOST}/api/chat"
    payload = {
        "model": get_config()["local_model"],
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "stream": False, "think": False, "format": schema, "keep_alive": config.KEEP_ALIVE,
        "options": {"temperature": config.AGENT_TEMPERATURE, "num_predict": num_predict},
    }
    data = json.dumps(payload).encode("utf-8")
    last_err = None
    for attempt in range(retries + 1):
        t0 = time.time()
        try:
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            content = (body.get("message") or {}).get("content", "")
            obj = _loads_lenient(content)
            meta = {"ok": obj is not None, "provider": "local", "latency_s": round(time.time() - t0, 2),
                    "attempt": attempt, "raw": content[:2000]}
            if obj is not None:
                return obj, meta
            last_err = "unparseable JSON content"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as e:
            last_err = repr(e)
        time.sleep(0.5)
    return None, {"ok": False, "provider": "local", "error": last_err, "latency_s": round(time.time() - t0, 2)}


def test_connection() -> dict:
    """Provider-aware connection test (used by the UI). Local is always ready; cloud
    routes the 1-token probe through the egress boundary."""
    if mode() == "local":
        return {"ok": True, "detail": "local model (offline)"}
    p, model, key = _cloud_creds()
    return egress.cloud_test(p, model, key)


def _loads_lenient(text: str):
    """Parse JSON; if the model wrapped it in prose/fences, extract the object."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None
