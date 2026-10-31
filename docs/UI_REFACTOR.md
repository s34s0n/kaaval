# Kaaval UI Refactor — two surfaces, industry-grade SOC

Paste this into Claude Code. It replaces the Phase 6 single dashboard and adds features. Work through the R-steps in order, stop after each, run its test, show me the observable, and wait for approval. Use plan mode before each step.

## Do not touch
The working backend stays as is: Zeek tailing, IT/OT detection, correlation, the agents (Ollama), `gating.py`, and the real iptables + OPC UA response actions. This refactor is additive on the backend (new read, chat, and rules APIs) and a full rebuild of the frontend. Never move safety logic into the model or the UI. Gating stays authoritative in code.

## The two surfaces
Split the frontend into two distinct apps/routes that share one backend and one live WebSocket event bus.

1. **Range Console** (the environment). Shows the live process, launches attacks, and allows manual control. This is the demo world, not the product. It may look industrial/utilitarian and visually different from the product.
2. **Kaaval** (the product). The agentic SOC. Must look industry-grade. This is the hero screen. Product-name constant: `Kaaval`.

They run as separate routes (e.g. `/range` and `/`) so each can be put on its own screen or window during a demo.

---

## SOC design system (this is the fix for "looks generic")
Build a real SecOps console: dense, dark, trustworthy, information-rich. Reference the density and hierarchy of professional security tooling, not a marketing dashboard.

Tokens:
- Background near-black with a faint indigo tint (around #0b0d14). Panels one step lighter (#11141d). Hairline borders (#1f2430). No pure black, no white cards.
- One brand/interactive accent: amber (#f5a524). Use it only for interactive and brand elements.
- Semantic severity scale, used only for meaning, never decoration: critical #ff4d4f, high #f5a524, medium #e6c84b, low #4aa3ff, info #8b93a7.
- Status dots: green ok, amber degraded, red breached.

Type:
- UI font: IBM Plex Sans. Telemetry, IDs, timestamps, IPs, hex, log lines: JetBrains Mono.
- Base 13px, tight line-height. Tables compact, 30px rows.

Layout:
- Fixed left icon+label nav: Incidents, Telemetry, Detections, Assets, Settings.
- Top status bar: environment status, autonomy ENABLED/DISABLED toggle, model status (warm/loaded), clock.
- Main area is a three-column incident workspace: left incident queue, center incident detail, right analyst chat (collapsible).

Motion: minimal and meaningful only (new alert slides in, severity pulse on critical). No gratuitous animation.

Do NOT do any of these: large rounded hero cards, centered single-column layouts, big empty padding, pastel or purple gradients, emoji, "AI assistant" sparkle clichés, oversized headings. If it looks like a generic template, it is wrong.

---

## SOC views (wire each to real backend data)

**Incident workspace (default view).**
- Incident header: severity tag, status, time-to-detect, time-to-contain, affected assets, the ews named as the pivot.
- Cross-domain kill-chain timeline: IT stages and OT stages on one timeline showing the boundary crossing, each node tagged with its ATT&CK for ICS technique id/name/tactic. This cross-IT/OT correlation is the product's differentiator, so make it the visual centerpiece.
- Correlated events list: the real detection events, each linking to the raw log line that produced it.
- Agent assessment: Triage, Investigation, Response, streamed token by token as they generate (no more staring at a spinner).
- Response actions: every recommended action rendered as a row with risk, reversibility, ATT&CK context, and an Apply button. Reversible IT actions apply on click. Control-plane/OT actions show the physical consequence and require explicit approval; the click is the human approval the gate demands. Applied actions write to the audit log and update the Range process view.

**Telemetry (the live logs, "print the logs").**
- Live tail over WebSocket of the actual Zeek JSON logs in `./logs/`: conn, ssh, ssl, dns, plus opcua_binary and s7comm, and any others present.
- Monospace table, columns per log type (ts, uid, src→dst, proto, and protocol fields like s7comm function/area/db and opcua service). Row expand shows the raw JSON.
- Filter box, per-log-type tabs, severity coloring on flagged lines, a follow-tail toggle. Must handle volume (virtualize).

**Detections (capabilities + rules, "show what Zeek and ICSNPP offer" + "add rules manually").**
- Capabilities panel: list every loaded analyzer/parser, native (conn, dns, http, ssl, ssh, rdp, smb, kerberos as available) and ICSNPP (opcua-binary, s7comm), and for each the log(s) it produces and the key fields. This is also the field palette for rule building.
- Coverage panel: a matrix of enabled rules mapped to ATT&CK for ICS techniques, so you can show detection coverage.
- Rules list: id, name, enabled toggle, source log, condition, severity, mapped ATT&CK, action-on-fire.
- Add/Edit rule via a slide-over: pick a log type, pick field(s) from the capabilities palette, operator, value, severity, ATT&CK id, action. Save persists to the rules store and hot-reloads the engine. A manually added rule must fire live without restart.
- "Draft from description": optional button that asks the local model to propose a rule JSON from a sentence, which you review before saving.

**Assets.**
- IT/OT inventory with criticality and authorized roles (which hosts may speak S7comm/OPC UA). Editable, because this context is what makes "ews speaking S7comm is unauthorized" true.

**Analyst chat (the interactive intelligence, docked right).**
- Grounded in the current incident bundle plus read-only tools over the platform: query_events, get_asset, list_rules, get_process_state. Streaming output.
- Must cite which events/assets it based an answer on. No ungrounded claims.
- Can propose an action inline with an Apply button (conversational remediation), routed through the same gating as the action rows.
- A few suggested starter questions.

---

## Range Console spec (Surface 1)
- Process schematic: tank, pump, valve, discharge-pressure gauge, interlock indicator, with live values streamed over WebSocket. Clear green-to-red states. Pressure climbing toward the 12-bar burst must be obvious.
- Attack panel: a Launch full-chain button and per-stage step buttons (SSH T0822, C2 T0869, scan T0846, OPC UA browse T0888, S7 write T0855/T0836/T0831), each labelled with its ATT&CK id.
- Manual control, two clearly separated paths:
  - Malicious (unauthorized): direct register writes from the ews path, set pump %, toggle interlock, push setpoint. This is what an attacker does and what Kaaval must catch.
  - Legitimate (authorized): operator setpoint change through the gateway. Kaaval must NOT alert on this. The contrast (same value, benign via HMI, malicious via ews) is a deliberate demo moment.
- Reset to clean baseline.

---

## Backend additions (additive, keep the rest)
- WebSocket/endpoint streaming raw Zeek log lines with {log_type, parsed_fields, raw, flagged}.
- GET /capabilities: loaded parsers, their log types and key fields (static map keyed by what logs exist).
- Rules CRUD (GET/POST/PUT/DELETE) persisting to a rules store (JSON or SQLite); IT and OT detection read from it; hot-reload on change.
- POST /chat: message + incident_id, streams model tokens, runs a read-only tool-calling loop, returns proposed actions as structured suggestions.
- Manual control endpoints for the Range: malicious direct write (via the ews path so the sensor sees it), legitimate setpoint via the gateway, and per-stage attack triggers.

---

## Build order with validation gates
R1 — Backend read/chat/rules APIs only, no UI. Test: a WS shows live log lines; /capabilities returns the parser/field map; rules CRUD works and a rule added via API fires live; /chat streams a grounded answer. Show me the curl/ws output.
R2 — SOC design system + app shell (nav, top bar, tokens, fonts), static, no data. Show me a screenshot to check it against this spec before wiring data.
R3 — SOC views on real data: incident workspace (kill-chain, events, streamed agents), Telemetry live tail, Detections (capabilities + coverage + rules add/toggle), Assets. Show: full incident renders, logs tail, a hand-added rule fires.
R4 — Analyst chat: grounded, tools, streaming, inline Apply. Show: a follow-up answered with cited events, and a proposed action applied.
R5 — Range Console: process schematic, attack panel, dual-path manual control, distinct look. Show: full chain and per-stage runs, a malicious manual write that alerts, a legitimate setpoint change that does not.
R6 — Streaming everywhere, polish, reliability (this is Phase 7): warm-on-boot, one-click reset across both surfaces, wifi-off run, failure handling, five clean runs, spoken demo script.

Start with R1. Confirm the plan back in two lines, then build R1 and stop for my review.
