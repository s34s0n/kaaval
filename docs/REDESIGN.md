# Kaaval Redesign — generic engine + deployment profile

Paste this into Claude Code. Work the D-steps in order, plan-mode first, stop after each, run its test, show me the observable, wait for approval. The water-pump demo must keep working at every step.

## What the audit found, and what to keep
The pipeline shape is correct and must not be touched:
- Detection is genuinely log-derived (Zeek/ICSNPP), not attacker-API-driven. Keep this.
- The LLM runs strictly after detection (P2 compliant). Keep this.
- Actions execute in deterministic code; gating is authoritative in `gating.py`; apply/approve re-enforce it server-side (P4 compliant). Keep this.
- The kill chain is already built from detected events. Keep this.

The problems to fix:
- P3 VIOLATED: the chat tool `get_process_state` reads the gateway/PLC over OPC UA directly. The LLM must never touch a device.
- P6 VIOLATED and P1 PARTIAL: detection rules, ATT&CK ids, correlation narrative, agent prompts, the gating playbook, the OPC node map, and the asset seed are all hardcoded to the water pump; OT "unauthorized" comes from the capture-topology invariant and `derive_ews_ip`, not from data.
- P1: time-to-detect uses the launch-click timestamp.
- P5 PARTIAL: verification reads device/host state directly instead of confirming detection no longer fires.

## Two principles to hold throughout
1. Read plane vs control plane. The LLM (agents and chat) reads only data the product already collected (Zeek/ICSNPP outputs, incidents, asset inventory, rules). It has no tool or import that reads or writes any device, gateway, PLC, range, or simulation. It proposes; deterministic code executes.
2. Replace foreknowledge of the attack with knowledge of the environment. Do not make detection context-free. Delete the hardcoded knowledge of the 5 scripted stages, and instead derive authorization and context from a declared asset inventory. The environment is described in config; the attack is not.

## Core mechanism: deployment profile + generic engine
Extract everything scenario-specific into a single deployment profile (one config file, e.g. `profiles/pumpstation.yaml`), loaded at startup. The pump becomes profile #1. The engine reads the profile and is otherwise generic.

The profile contains:
- assets: list of {id, ips, role, criticality, process_context (free-text: what it controls and what is at risk)}.
- authorization: per protocol, the allowed client assets and allowed operations, e.g. `s7comm: { allowed_clients: [gateway, hmi], allow_write: false }`, `opcua: { allowed_clients: [backend], ... }`.
- actions: the response catalog, each {id, kind (it|ot), description, attributes: {control_plane, reversible, affects_process}, executor params}. This is the only place device targets (OPC nodes, iptables specs) live, and it is used only by the executor, never exposed to the LLM.

Detection authorization becomes data-driven: an observed write on a protocol from a client not in that protocol's `allowed_clients` is unauthorized. No `derive_ews_ip`, no "sensor only sees ews" invariant. (Note: a declared authorization policy is the environment baseline for now; learned/statistical baselining is a later roadmap item, not part of this work.)

## Build order with validation gates

D1 — Cut the LLM to device path (P3). Remove `get_process_state` and the `opc` import from `chat.py`. If the analyst needs current state, expose only what telemetry already captured (latest values from the product's store), never a live device read. Test: grep shows no device/opc import in `chat.py`; the chat still answers grounded questions. Lowest risk, do first.

D2 — Deployment profile + inventory-driven authorization (P1/P6 core). Add the profile loader and move the pump specifics into `profiles/pumpstation.yaml`. Drive OT and IT authorization from the inventory instead of `derive_ews_ip` and the capture invariant. Test: unauthorized S7/OPC writes are flagged because the source is not an allowed client, not because of the ews IP; authorized gateway/HMI traffic does not alert; authorizing a new host in the profile changes what is flagged. This proves authorization is data-driven.

D3 — Rules as config (P1/P6). Migrate the five hardcoded `detect_it`/`detect_ot` functions into entries in the existing `rules_store`, expressed as generic field-based conditions with severity and ATT&CK technique as rule metadata, evaluated by the existing `rules_engine`. Remove the hardcoded id/technique/summary branches. Test: the same incident is still detected, now via config rules; disabling a rule stops that detection; adding a generic rule (for example, inbound RDP from a non-allowlisted source) fires on a new probe with no code change.

D4 — Generic analyst and correlation (P6). Remove pump/interlock language from the `agents.py` prompts and `correlate._PHRASE`. Feed the affected assets' `criticality` and `process_context` from the profile so the LLM reasons from data; build the narrative from the fired rules' metadata. Test: triage and investigation read sensibly using inventory context with no hardcoded pump wording; editing an asset's `process_context` in the profile changes the analysis.

D5 — Pluggable response and attribute-based gating (P6/P4). Move the action catalog and OPC node map into the profile. Make `gating.py` decide from each action's attributes (control_plane, reversible, affects_process), with unknown or unattributed actions failing safe to gated. Keep gating authoritative in code. Test: pump actions still work from the profile; an action with no attributes is gated; gating references attributes, not the five hardcoded action names.

D6 — Detection-anchored metrics and verification (P1/P5). Compute time-to-detect from the incident's first detected event timestamp, not the launch click. After a fix is applied, run verification by collecting a FRESH window of Zeek telemetry gathered after the remediation timestamp and confirming the triggering condition no longer fires; do not re-scan the historical logs, which still contain the past attack. Keep the direct-effect check as a fast secondary signal, but the authoritative "resolved" comes from detection going quiet on fresh telemetry. Test: TTD no longer uses the launch click; after Approve, the tool gathers fresh telemetry and reports resolved only when no new unauthorized activity is seen; if the attacker keeps writing, it reports not resolved.

## Priority if time is tight
D1, D2, and D6 are the must-haves: they make the LLM boundary clean, authorization data-driven, and metrics and verification honest, which is what defends "this is a real product." D3, D4, and D5 complete the genericity and are worth doing but can follow. Do not skip D1 or D2.

Start with D1. Confirm the plan back in two lines, then build D1 and stop for my review.
