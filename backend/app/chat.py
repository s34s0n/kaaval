# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Analyst chat — incident-grounded, read-only tools, streaming answer.

Grounds on the current incident bundle, runs a bounded read-only tool-calling
loop (query_events, get_asset, list_rules, get_latest_state) against the local
model, then streams the final answer token-by-token as SSE. May propose a
response action inline — as a *suggestion* only; applying it still routes through
the existing /api/actions approve endpoint and gating.py. Never executes here.

Read-plane boundary (REDESIGN D1): the analyst reads ONLY data the product has
already collected — incidents, events, assets, rules, and the last process
snapshot the backend polled. It has NO import or tool that opens a live device /
gateway / PLC connection.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request

from . import asset_discovery, assets, config, egress, gating, llm, rules_store, store, telemetry, zeek_stats
from .pipeline import latest_incident_bundle

MAX_TOOL_ROUNDS = 5

# All tools are strictly READ-ONLY (invariant 1): none can reach an action, open a
# device connection, or mutate state. The corpus tools (query_assets/flows/incidents,
# get_asset_detail) extend the chat from incident-scoped to the whole environment —
# "ask your network". Their output is pseudonymized by the egress boundary before any
# cloud call (constraint), same as every other prompt content.
TOOLS = [
    {"type": "function", "function": {
        "name": "query_events", "description": "List correlated detection events for the CURRENT incident. Optional filter by domain (IT/OT) or rule substring.",
        "parameters": {"type": "object", "properties": {
            "domain": {"type": "string"}, "rule": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "query_assets", "description": "Search the whole asset inventory (passive discovery). Filter by domain (IT/OT/external), criticality (critical/high/medium/low), or unmanaged=true (rogue/undeclared). Use for 'what assets…', 'which OT devices…', 'any rogue hosts…'.",
        "parameters": {"type": "object", "properties": {
            "domain": {"type": "string"}, "criticality": {"type": "string"}, "unmanaged": {"type": "boolean"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "query_flows", "description": "Search observed network conversations (Zeek). Filter by src, dst (host name or IP substring), proto/service (s7comm/opcua/ssh/tls/dns/https), or anomalous=true. Use for 'what is talking to the PLC', 'show OT traffic', 'who connects to <host>'.",
        "parameters": {"type": "object", "properties": {
            "src": {"type": "string"}, "dst": {"type": "string"}, "proto": {"type": "string"}, "anomalous": {"type": "boolean"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "query_incidents", "description": "List correlated incidents in the queue. Optional filter by severity. Use for 'what incidents are open', 'any critical incidents'.",
        "parameters": {"type": "object", "properties": {"severity": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {
        "name": "get_asset_detail", "description": "Full detail for ONE asset by name or IP: device type, zone, protocols spoken, role, peers, traffic, first/last seen, managed/authorized status.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "get_asset", "description": "Look up an asset by name or role, with criticality and whether it is an authorized OT speaker.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "list_rules", "description": "List detection rules (built-in + user), enabled state and ATT&CK mapping.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "get_latest_state", "description": "The most recent process state the product already collected (last telemetry snapshot — not a live device read).",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
]


# --- tool implementations (all read-only) -----------------------------------

def _query_events(domain=None, rule=None):
    conn = store.connect(); store.init(conn)
    evs = store.get_events(conn); conn.close()
    if domain:
        evs = [e for e in evs if e["domain"].lower() == domain.lower()]
    if rule:
        evs = [e for e in evs if rule.lower() in e["rule"].lower()]
    return [{"id": e["id"], "domain": e["domain"], "rule": e["rule"],
             "severity": e["severity"], "techniques": [t["id"] for t in e["techniques"]],
             "src": e["src"], "dst": e["dst"], "summary": e["summary"]} for e in evs]


def _query_assets(domain=None, criticality=None, unmanaged=None):
    d = asset_discovery.discover()
    out = d["assets"]
    if domain:
        out = [a for a in out if (a.get("domain") or "").lower() == domain.lower()]
    if criticality:
        out = [a for a in out if a.get("criticality") == criticality]
    if unmanaged is not None:
        out = [a for a in out if a.get("unmanaged") == bool(unmanaged)]
    keys = ("id", "ip", "domain", "device_type", "criticality", "managed", "unmanaged", "protocols", "role", "peers", "bytes")
    return {"summary": d["summary"], "assets": [{k: a.get(k) for k in keys} for a in out[:50]]}


def _query_flows(src=None, dst=None, proto=None, anomalous=None):
    convos = zeek_stats.overview().get("conversations", [])

    def match(c):
        if src and src.lower() not in f"{c.get('src')} {c.get('src_ip')}".lower():
            return False
        if dst and dst.lower() not in f"{c.get('dst')} {c.get('dst_ip')}".lower():
            return False
        if proto and proto.lower() != (c.get("service") or "").lower():
            return False
        if anomalous is not None and bool(c.get("anomalous")) != bool(anomalous):
            return False
        return True
    keys = ("src", "dst", "port", "service", "conns", "bytes", "anomalous", "states")
    return [{k: c.get(k) for k in keys} for c in convos if match(c)][:50]


def _query_incidents(severity=None):
    conn = store.connect(); store.init(conn)
    incs = store.get_incidents(conn); conn.close()
    if severity:
        incs = [i for i in incs if i.get("severity") == severity]
    return [{"id": i["id"], "severity": i["severity"], "cross_domain": i["cross_domain"],
             "domains": i["domains"], "techniques": [t["id"] for t in i["techniques"]],
             "summary": i["summary"]} for i in incs]


def _get_asset_detail(name):
    q = (name or "").lower().strip()
    for a in asset_discovery.discover()["assets"]:
        if q and (q == (a.get("ip") or "").lower() or q in (a.get("id") or "").lower()
                  or q in (a.get("device_type") or "").lower()):
            return a
    return {"error": f"no asset matching '{name}'"}


def _get_latest_state(latest_state):
    """Return the last process snapshot the PRODUCT already collected (the
    backend's cached OPC poll), not a fresh device read. Read-plane only."""
    if not latest_state:
        return {"note": "no process snapshot collected yet"}
    snap = {k: (round(v, 2) if isinstance(v, float) else v)
            for k, v in latest_state.items() if k != "status"}
    snap["source"] = "last telemetry snapshot collected by the product (not a live device read)"
    return snap


async def _run_tool(name: str, args: dict, latest_state=None):
    try:
        if name == "query_events":
            return _query_events(args.get("domain"), args.get("rule"))
        if name == "query_assets":
            return _query_assets(args.get("domain"), args.get("criticality"), args.get("unmanaged"))
        if name == "query_flows":
            return _query_flows(args.get("src"), args.get("dst"), args.get("proto"), args.get("anomalous"))
        if name == "query_incidents":
            return _query_incidents(args.get("severity"))
        if name == "get_asset_detail":
            return _get_asset_detail(args.get("name", ""))
        if name == "get_asset":
            return assets.get_asset(args.get("name", "")) or {"error": "asset not found"}
        if name == "list_rules":
            return [{"id": r["id"], "name": r["name"], "enabled": r["enabled"],
                     "attack": r.get("attack", []), "builtin": r.get("builtin")} for r in rules_store.list_rules()]
        if name == "get_latest_state":
            return _get_latest_state(latest_state)
    except Exception as e:
        return {"error": repr(e)}
    return {"error": f"unknown tool {name}"}


# --- model plumbing ---------------------------------------------------------

def _post(payload: dict, timeout: float = 120) -> dict:
    req = urllib.request.Request(f"{config.OLLAMA_HOST}/api/chat",
                                 data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _corpus_snapshot() -> str:
    """A compact whole-environment context (assets + top conversations) built from the
    same read-only query sources, so 'ask your network' questions are answerable even
    if the model doesn't issue a tool call. In cloud mode this text is pseudonymized by
    the egress boundary like all other grounding."""
    try:
        disc = asset_discovery.discover()
        z = zeek_stats.overview()
    except Exception:
        return ""
    s = disc.get("summary", {})
    out = ["", "ENVIRONMENT — passive asset discovery (full inventory):",
           f"totals: {s.get('total', 0)} assets · {s.get('ot', 0)} OT · {s.get('it', 0)} IT · "
           f"{s.get('external', 0)} external · {s.get('unmanaged', 0)} unmanaged/rogue · {s.get('active', 0)} active"]
    for a in disc.get("assets", [])[:20]:
        flag = "  [UNMANAGED/ROGUE]" if a.get("unmanaged") else ""
        out.append(f"- {a.get('id')} ({a.get('ip')}) · {a.get('domain')} · {a.get('device_type')} · "
                   f"crit={a.get('criticality')} · speaks {','.join(a.get('protocols') or []) or '-'}{flag}")
    convos = z.get("conversations", [])
    if convos:
        out.append("TOP CONVERSATIONS (Zeek):")
        for c in convos[:12]:
            an = "  ANOMALOUS" if c.get("anomalous") else ""
            out.append(f"- {c.get('src')} -> {c.get('dst')}:{c.get('port')} ({c.get('service')}) "
                       f"{c.get('conns')}c {c.get('bytes')}B{an}")
    return "\n".join(out)


def _ground(bundle, latest_state=None) -> str:
    """Concrete, readable grounding: the correlated incident, its detection events
    (with evidence), recent flagged Zeek log lines, AND a whole-environment corpus
    snapshot (assets + conversations). This is the material the assistant reasons from
    (plus the read-only tools for targeted drill-down)."""
    def _snapshot() -> str:
        if not latest_state:
            return ""
        vals = {k: (round(v, 2) if isinstance(v, float) else v)
                for k, v in latest_state.items() if k not in ("status", "burst_bar")}
        return ("\n\nLAST PROCESS SNAPSHOT (collected by the product, not a live device read):\n"
                + json.dumps(vals, default=str))

    if not bundle or not bundle.get("incident"):
        return ("NO ACTIVE INCIDENT. The plant is at baseline and the sensor has "
                "flagged nothing for an incident — but you can still answer questions "
                "about the environment from the inventory + conversations below."
                + _snapshot() + _corpus_snapshot())
    inc = bundle["incident"]
    out = [
        f"INCIDENT {inc['id']}  severity={inc['severity']}  pivot={inc['pivot']}  "
        f"domains={inc.get('domains')}  cross_domain={inc.get('cross_domain')}",
        f"summary: {inc.get('summary')}",
    ]
    ctx = bundle.get("asset_context") or []
    if ctx:
        out.append("")
        out.append("ASSETS IN THIS INCIDENT (from the deployment inventory):")
        for a in ctx:
            out.append(f"- {a['name']} · role={a.get('role')} · domain={a.get('domain')} · "
                       f"criticality={a.get('criticality')} · authorized_ot={a.get('authorized_ot')}"
                       + (f"\n    process: {a['notes']}" if a.get("notes") else ""))
    out += [
        "",
        "DETECTION EVENTS (real Zeek detections, correlated):",
    ]
    for e in bundle.get("events", []):
        tids = ",".join(t["id"] for t in e.get("techniques", []))
        out.append(f"- {e['id']} [{e['severity']}] {e['domain']} {tids}  "
                   f"{e['src']} -> {e['dst']}\n    what: {e['summary']}\n    "
                   f"evidence: {json.dumps(egress.scrub(e.get('evidence', {})), default=str)}")
    flagged = [r for r in telemetry.recent(per_log=12) if r.get("flagged")][-12:]
    if flagged:
        out.append("")
        out.append("RECENT FLAGGED LOG LINES (raw Zeek, sensor at the ews):")
        for r in flagged:
            out.append(f"- {r['log_type']} {r.get('src')} -> {r.get('dst')}  "
                       f"{json.dumps(egress.scrub(r.get('parsed_fields', {})), default=str)}")
    return "\n".join(out) + _snapshot() + _corpus_snapshot()


def _system_prompt(bundle, latest_state=None, plain=False) -> str:
    return egress.INJECTION_NOTICE + "\n\n" + _system_prompt_body(bundle, latest_state, plain)


def _system_prompt_body(bundle, latest_state=None, plain=False) -> str:
    if plain:
        return (
            "You are a security advisor briefing a NON-TECHNICAL manager about an "
            "industrial (OT) security situation. Explain in plain English a smart person "
            "with no security background can follow. Hard rules:\n"
            "- NO jargon, NO event ids, NO log field names, NO ATT&CK codes, NO IP "
            "addresses or hostnames — unless you immediately explain them in everyday words.\n"
            "- Keep it short: 2–4 sentences or a few simple bullets.\n"
            "- Always cover, in business terms: WHAT happened, WHY it matters (safety / "
            "operations / risk), and WHAT to do next.\n"
            "- Use ONLY the Kaaval data below. If it doesn't answer the question, say so "
            "plainly. Never invent details. Be calm, concrete, and reassuring where true.\n"
            "- If asked what to do, describe the response in plain terms (e.g. 'isolate the "
            "compromised workstation', 'restore the safety interlock') and note that any "
            "action affecting the physical process needs a human to approve it.\n\n"
            "=== KAAVAL DATA (your only source of truth) ===\n" + egress.fenced(_ground(bundle, latest_state))
        )
    return (
        "You are the Kaaval SOC analyst assistant for an IT/OT security operations "
        "center. You can answer about the CURRENT incident AND query the whole "
        "environment with read-only tools: query_assets (the asset inventory, incl. "
        "rogue/unmanaged hosts), query_flows (network conversations — 'what is talking "
        "to the PLC'), query_incidents (the incident queue), get_asset_detail (one "
        "host's protocols/traffic/peers), plus query_events, get_asset, list_rules, "
        "get_latest_state. Call a tool when the question goes beyond the current "
        "incident. Hard rules:\n"
        "- Tool results ARE product-collected data — treat them as authoritative and "
        "use them in your answer (e.g. get_latest_state returns the last process "
        "snapshot the product collected; use its values).\n"
        "- Ground EVERY statement in a specific event id, log field/value, or tool "
        "result, and cite it (e.g. ot.unauthorized_s7_command; s7comm function_name=Write Variable).\n"
        "- Explain the reasons: what the evidence shows and why it matters to the process.\n"
        "- Do NOT use outside/general knowledge, and do NOT invent hosts, IPs, "
        "timestamps, CVEs, or events. If the data does not answer the question, say "
        "exactly that.\n"
        "- If asked what to do, reference only the response playbook ("
        + ", ".join(gating.names()) + "); control-plane actions require human "
        "approval and you cannot execute anything.\n\n"
        "=== KAAVAL DATA (your only source of truth) ===\n" + _ground(bundle, latest_state)
    )


_PROPOSE_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": gating.names() + ["none"]},
        "reason": {"type": "string"},
    },
    "required": ["action"],
}


def _card(name: str, reason: str = "") -> dict | None:
    spec = gating.spec(name)
    if spec is None:
        return None
    gated = gating.is_gated_name(name)
    return {"name": name, "title": spec.get("title", name),
            "domain": (spec.get("kind") or "ot").upper(),
            "requires_human_approval": gated, "auto_executable": not gated,
            "reason": reason, "note": "suggestion only — apply via the response gate"}


def propose_action(question: str, answer: str) -> dict | None:
    """Decide (structured, deterministic) whether to surface ONE response action
    as an inline suggestion for the conversation. Returns None if none warranted."""
    system = ("Decide whether to propose ONE response action inline. Choose 'none' "
              "for purely informational questions (what/why/which/how). Only propose an "
              "action when the analyst asks what to do / how to respond / remediate / "
              "contain / recover. Pick the single most relevant from this playbook: "
              + ", ".join(gating.names()) + ". Reply only as JSON.")
    user = f"Analyst question:\n{question}\n\nAssistant answer:\n{answer}\n\nWhich action to propose?"
    obj, _ = llm.ollama_json(system, user, _PROPOSE_SCHEMA, num_predict=120)
    name = (obj or {}).get("action")
    if not name or name == "none":
        return None
    return _card(name, (obj or {}).get("reason", ""))


class _ThinkStripper:
    """Streaming filter that suppresses <think>…</think> spans across token
    boundaries (qwen3 leaks a reasoning block despite think:false). Emits only
    the final answer. If a think block never closes, flush() returns it as a
    fallback so the answer is never silently empty."""

    OPEN, CLOSE = "<think>", "</think>"

    def __init__(self):
        self.buf = ""
        self.in_think = False
        self.suppressed = ""

    @staticmethod
    def _partial_keep(s: str, tag: str) -> int:
        # trailing chars of s that could be the start of `tag` (hold them back)
        for k in range(min(len(tag) - 1, len(s)), 0, -1):
            if s.endswith(tag[:k]):
                return k
        return 0

    def feed(self, tok: str) -> str:
        self.buf += tok
        out = ""
        progress = True
        while progress:
            progress = False
            if not self.in_think:
                i = self.buf.find(self.OPEN)
                if i != -1:
                    out += self.buf[:i]
                    self.buf = self.buf[i + len(self.OPEN):]
                    self.in_think = True
                    progress = True
                else:
                    keep = self._partial_keep(self.buf, self.OPEN)
                    out += self.buf[:len(self.buf) - keep]
                    self.buf = self.buf[len(self.buf) - keep:]
            else:
                j = self.buf.find(self.CLOSE)
                if j != -1:
                    self.buf = self.buf[j + len(self.CLOSE):]
                    self.in_think = False
                    self.suppressed = ""           # closed cleanly -> discard
                    progress = True
                else:
                    keep = self._partial_keep(self.buf, self.CLOSE)
                    self.suppressed += self.buf[:len(self.buf) - keep]
                    self.buf = self.buf[len(self.buf) - keep:]
        return out

    def flush(self) -> str:
        if self.in_think:                          # never closed -> fallback
            return self.suppressed + self.buf
        return self.buf


# --- public: async generator of SSE events ----------------------------------

async def chat_sse(message: str, incident_id: str | None = None, history: list | None = None,
                   latest_state: dict | None = None, plain: bool = True):
    import asyncio

    def sse(kind, data):
        return f"event: {kind}\ndata: {json.dumps(data)}\n\n"

    # Plain-language answers for a non-technical audience by default; "Analyst" mode
    # (plain=False) gives the technical, event-id/ATT&CK-cited style.
    final_instr = ("Now answer the question for a NON-TECHNICAL manager: plain English, "
                   "short, no codes/ids/field names. Say what happened, why it matters, and "
                   "what to do. Use ONLY the data above; if it's not there, say so.") if plain else (
                   "Now answer using ONLY the Kaaval data above. Cite the specific event ids and "
                   "log fields/values that support each point. If the data doesn't cover it, say so.")

    bundle = latest_incident_bundle()
    messages = [{"role": "system", "content": _system_prompt(bundle, latest_state, plain)}]
    # Prior turns (multi-turn follow-ups) keep the model grounded in context.
    for m in (history or []):
        if m.get("role") in ("user", "assistant") and m.get("content"):
            messages.append({"role": m["role"], "content": m["content"]})
    messages.append({"role": "user", "content": message})

    # Read-only tool loop (orchestrated on the local model) — gather corpus data for
    # BOTH modes. Tool results join the message history (local) and are folded into the
    # cloud grounding; either way they pass through the egress pseudonymizer before any
    # cloud transmission. No tool can mutate state, reach an action, or open a device.
    tool_results = []
    # The read-only tool loop is orchestrated on the LOCAL model only. In cloud mode
    # we skip it entirely so cloud chat has ZERO local-Ollama dependency: the whole-
    # environment corpus (assets + conversations + incident events) is already folded
    # into the grounding/system prompt by _ground()/_corpus_snapshot(), and cloud
    # tool-calling semantics vary by provider. So cloud mode needs no Ollama running.
    if llm.mode() != "cloud":
        try:
            for _ in range(MAX_TOOL_ROUNDS):
                resp = await asyncio.to_thread(_post, {
                    "model": llm.get_config()["local_model"], "messages": messages, "tools": TOOLS,
                    "stream": False, "think": False, "keep_alive": config.KEEP_ALIVE,
                    "options": {"temperature": config.AGENT_TEMPERATURE}})
                msg = resp.get("message", {})
                calls = msg.get("tool_calls") or []
                if not calls:
                    messages.append({"role": "assistant", "content": msg.get("content", "")})
                    break
                messages.append(msg)
                for call in calls:
                    fn = call.get("function", {})
                    name = fn.get("name", "")
                    args = fn.get("arguments") or {}
                    if isinstance(args, str):
                        try: args = json.loads(args)
                        except json.JSONDecodeError: args = {}
                    result = await _run_tool(name, args, latest_state)
                    tool_results.append({"tool": name, "args": args, "result": result})
                    yield sse("tool", {"name": name, "args": args})
                    messages.append({"role": "tool", "content": json.dumps(result, default=str)})
        except Exception as e:
            yield sse("tool", {"error": f"tool loop failed: {e!r}"})

    # Cloud mode: fold the read-only tool output into the grounding and stream the final
    # answer through the egress boundary, which pseudonymizes system + messages + the
    # folded tool data (asset identities masked) before the call leaves the box.
    if llm.mode() == "cloud":
        full = ""
        retrieved = ("\n\nRETRIEVED via read-only tools (product data):\n"
                     + egress.fenced(json.dumps(tool_results, default=str))) if tool_results else ""
        sys_cloud = messages[0]["content"] + retrieved
        amsgs = [{"role": m["role"], "content": m["content"]} for m in (history or [])
                 if m.get("role") in ("user", "assistant") and m.get("content")]
        amsgs.append({"role": "user", "content": message})
        amsgs.append({"role": "user", "content": final_instr})
        p, model, key = llm._cloud_creds()
        try:
            async for tok in egress.cloud_stream(p, model, key, sys_cloud, amsgs,
                                                  incident_id=incident_id, principal="operator", purpose="chat"):
                full += tok
                yield sse("token", {"t": tok})
        except Exception as e:
            yield sse("token", {"t": f"[answer unavailable: {e!r}]"})
        action = await asyncio.to_thread(propose_action, message, full)
        if action:
            yield sse("actions", {"proposed": [action]})
        yield sse("done", {"ok": True})
        return

    # Local mode: stream the final grounded answer (uses `messages`, incl. tool results)
    full = ""
    try:
        # think:True so qwen3 keeps its reasoning in the separate `thinking`
        # field; we stream only `content` (the answer), which is clean.
        payload = {"model": llm.get_config()["local_model"],
                   "messages": messages + [{"role": "user", "content": final_instr}],
                   "stream": True, "think": True, "keep_alive": config.KEEP_ALIVE,
                   "options": {"temperature": config.AGENT_TEMPERATURE}}
        q: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_running_loop()

        def producer():
            req = urllib.request.Request(f"{config.OLLAMA_HOST}/api/chat",
                                         data=json.dumps(payload).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=180) as r:
                for line in r:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    m = chunk.get("message") or {}
                    if m.get("thinking"):
                        loop.call_soon_threadsafe(q.put_nowait, ("think", m["thinking"]))
                    if m.get("content"):
                        loop.call_soon_threadsafe(q.put_nowait, ("token", m["content"]))
                    if chunk.get("done"):
                        loop.call_soon_threadsafe(q.put_nowait, None)
                        return
            loop.call_soon_threadsafe(q.put_nowait, None)

        task = asyncio.create_task(asyncio.to_thread(producer))
        stripper = _ThinkStripper()
        while True:
            item = await q.get()
            if item is None:
                break
            kind, text = item
            if kind == "think":
                yield sse("think", {"t": text})    # reasoning trace (UI shows faintly)
                continue
            full += text
            out = stripper.feed(text)              # belt-and-suspenders tag strip
            if out:
                yield sse("token", {"t": out})
        tail = stripper.flush()
        if tail:
            yield sse("token", {"t": tail})
        await task
    except Exception as e:
        yield sse("token", {"t": f"[answer unavailable: {e!r}]"})

    action = await asyncio.to_thread(propose_action, message, full)
    if action:
        yield sse("actions", {"proposed": [action]})
    yield sse("done", {"ok": True})
