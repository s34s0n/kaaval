# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Kaaval attacker service — HTTP API that runs the ATT&CK-tagged kill chain.

The dashboard's attacker console (Phase 6) and the Phase 4/5 pipeline consume
this. Each stage records its ATT&CK technique IDs and start/finish timestamps so
time-to-detect / time-to-contain can be computed later.
"""

from __future__ import annotations

import time

from fastapi import FastAPI, HTTPException

import attacks

app = FastAPI(title="Kaaval Attacker", version="1.0")

# In-memory record of the last run (a demo, single-operator service).
_state: dict = {"running": False, "stages": [], "started": None, "finished": None}


def _technique_objs(ids: list[str]) -> list[dict]:
    return [{"id": t, "name": attacks.TECHNIQUE_NAMES.get(t, t)} for t in ids]


def _run_stage(name: str) -> dict:
    meta = next(s for s in attacks.STAGES if s[0] == name)
    _, tids, desc = meta
    rec = {
        "stage": name,
        "techniques": _technique_objs(tids),
        "description": desc,
        "status": "running",
        "started": time.time(),
        "finished": None,
        "output": "",
    }
    try:
        rec["output"] = attacks.RUNNERS[name]()
        rec["status"] = "ok"
    except Exception as e:
        rec["status"] = "error"
        rec["output"] = str(e)
    rec["finished"] = time.time()
    rec["duration_s"] = round(rec["finished"] - rec["started"], 2)
    return rec


@app.get("/health")
def health():
    return {"ok": True, "service": "kaaval-attacker"}


@app.get("/techniques")
def techniques():
    return {
        "stages": [
            {"stage": n, "techniques": _technique_objs(t), "description": d}
            for (n, t, d) in attacks.STAGES
        ]
    }


@app.get("/status")
def status():
    return _state


@app.post("/stage/{name}")
def run_one(name: str):
    if name not in attacks.STAGE_NAMES:
        raise HTTPException(404, f"unknown stage '{name}'")
    rec = _run_stage(name)
    return rec


def _run_stages(names: list[str]) -> dict:
    _state.update(running=True, stages=[], started=time.time(), finished=None)
    for name in names:
        rec = _run_stage(name)
        _state["stages"].append(rec)
        if rec["status"] == "error":
            break  # stop the chain if a stage fails
    _state.update(running=False, finished=time.time())
    ok = all(s["status"] == "ok" for s in _state["stages"])
    return {"ok": ok, "duration_s": round(_state["finished"] - _state["started"], 2),
            "stages": _state["stages"]}


@app.post("/run")
def run_chain():
    return _run_stages(attacks.STAGE_NAMES)


@app.get("/scenarios")
def scenarios():
    return {"scenarios": [
        {"name": n, "stages": attacks.SCENARIOS[n], **attacks.SCENARIO_META.get(n, {})}
        for n in attacks.SCENARIOS
    ]}


@app.post("/scenario/{name}")
def run_scenario(name: str):
    if name not in attacks.SCENARIOS:
        raise HTTPException(404, f"unknown scenario '{name}'")
    return _run_stages(attacks.SCENARIOS[name])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
