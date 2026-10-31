#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Phase 0 observable for Kaaval.

Sends a small SOC-flavored prompt to the local Ollama server and prints the
reply together with the generation rate in tokens/sec. Pure standard library
(no third-party deps) so it runs offline regardless of the project venv.

tokens/sec is computed from the Ollama response fields:
    eval_count       -> number of tokens generated
    eval_duration    -> generation time in nanoseconds
    rate = eval_count / (eval_duration / 1e9)

Exit codes: 0 success, 1 server unreachable / bad response, 2 model missing.
"""

import json
import sys
import time
import urllib.error
import urllib.request

# Inline the few constants we need so the script stays dependency-free and
# runnable from anywhere (it does not import the project package).
OLLAMA_HOST = "http://localhost:11434"
MODEL_TAG = "qwen3:30b-a3b"
KEEP_ALIVE = -1

PROMPT = (
    "In one sentence, what is the IT/OT boundary in a water pumping station, "
    "and why is it a high-value target?"
)


def post_json(url: str, payload: dict, timeout: float = 300.0) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fmt_ns(ns: float) -> str:
    return f"{ns / 1e9:.2f}s"


def main() -> int:
    url = f"{OLLAMA_HOST}/api/generate"
    payload = {
        "model": MODEL_TAG,
        "prompt": PROMPT,
        "stream": False,
        "keep_alive": KEEP_ALIVE,
        # qwen3 is a hybrid reasoning model; disable the <think> phase so the
        # whole token budget goes to the answer (agents in later phases will
        # opt into thinking where it helps). Keep it short and deterministic.
        "think": False,
        "options": {"temperature": 0.2, "num_predict": 256},
    }

    print(f"Kaaval Phase 0 smoke test")
    print(f"  server : {OLLAMA_HOST}")
    print(f"  model  : {MODEL_TAG}")
    print(f"  prompt : {PROMPT}\n")

    started = time.time()
    try:
        result = post_json(url, payload)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        if e.code == 404:
            print(f"ERROR: model '{MODEL_TAG}' not found on the server.", file=sys.stderr)
            print(f"       Run: ollama pull {MODEL_TAG}", file=sys.stderr)
            return 2
        print(f"ERROR: HTTP {e.code} from Ollama: {body}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"ERROR: cannot reach Ollama at {OLLAMA_HOST} ({e.reason}).", file=sys.stderr)
        print("       Is the server running?  Try: ollama serve", file=sys.stderr)
        return 1
    except (TimeoutError, json.JSONDecodeError) as e:
        print(f"ERROR: bad/incomplete response from Ollama: {e}", file=sys.stderr)
        return 1

    wall = time.time() - started

    reply = (result.get("response") or "").strip()
    thinking = (result.get("thinking") or "").strip()
    if not reply and thinking:
        # Defensive: if thinking wasn't disabled, still show something useful.
        reply = f"[thinking only]\n{thinking}"
    eval_count = result.get("eval_count")
    eval_duration = result.get("eval_duration")  # nanoseconds
    load_duration = result.get("load_duration")  # nanoseconds
    prompt_eval = result.get("prompt_eval_duration")  # nanoseconds

    print("--- reply " + "-" * 60)
    print(reply or "(empty response)")
    print("-" * 70)

    if not eval_count or not eval_duration:
        print("WARNING: response missing eval_count/eval_duration; cannot compute "
              "tokens/sec.", file=sys.stderr)
        return 1

    tok_per_s = eval_count / (eval_duration / 1e9)
    print(f"\n  generated tokens : {eval_count}")
    print(f"  tokens/sec       : {tok_per_s:.1f}")
    print(f"  generation time  : {fmt_ns(eval_duration)}")
    if load_duration is not None:
        print(f"  model load time  : {fmt_ns(load_duration)}  (0 ≈ already warm)")
    if prompt_eval is not None:
        print(f"  prompt eval time : {fmt_ns(prompt_eval)}")
    print(f"  wall clock       : {wall:.2f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
