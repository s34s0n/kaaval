# Kaaval — engineering context

Full context so a model (or engineer) can understand Kaaval without the original build
session. For how to build/run/fix, see [../CLAUDE.md](../CLAUDE.md). For the visual
walkthrough, see [GUIDE.md](GUIDE.md).

## What it is, and why it's a product (not a scripted demo)
Kaaval is a local, offline-capable **agentic IT/OT SOC**. The engine has **no
foreknowledge of the attack**: everything plant-specific lives in a deployment profile
(`profiles/*.yaml`) and everything detected comes from real open-source sensor logs
(Zeek + ICSNPP). Swap the profile + the simulated plant and the same engine defends a
different ICS with zero application-code change (pump is profile #1; a reactor profile
ships too).

## Core product principles
1. **OT-safety gating (the central logic).** Any action that changes OT control state, is
   irreversible, or could affect the physical process is `requires_human_approval`. The
   decision is made **in code** from the action's attributes (`control_plane` /
   `reversible` / `affects_process`) — never by the LLM. Unknown/unattributed ⇒ gated
   (fail-safe). Only low-risk **reversible IT** actions may auto-run, and only under an
   explicit admin autonomy policy. The gate is enforced server-side at the `/apply` and
   `/approve` endpoints, re-checked in the executor layer (defense in depth), and approval
   requires the `approver` role (separation of duties). Executor **adapters** decide *how*
   an approved action runs (lab docker-exec+OPC UA, or a real firewall/NAC REST contract
   that fails closed when unconfigured) — never *whether*.
2. **Asymmetric trust boundaries (two outbound paths, deliberately different).**
   - **Cloud LLM egress (`egress.py`)** leaves the premises, so it is **pseudonymized**
     (per-incident IP/asset tokens, denylist scrub, structural fencing of untrusted
     telemetry, immutable `egress_log`). NVD CVE lookups route here too and send only a CPE
     string. Real identity never crosses this boundary.
   - **SIEM/CEF feed (`siem.py` + `cef.py`)** is an **internal** destination on the
     customer's own premises, so it legitimately carries **real** asset identity (that's the
     point — correlation against their logs). It is off unless an admin enables it, one-way
     out (client socket only), and imports no `actions`/`gating`/`egress`. It is **never**
     pseudonymized and **never** routed off-prem.
   Rule of thumb: *off-premises ⇒ pseudonymize; on-premises customer destination ⇒ real
   identity is the point.*
3. **The LLM never touches a device or an action.** Agents and chat read only
   product-collected data (Zeek logs, incidents, inventory, rules, the last polled process
   snapshot). No tool reaches a PLC/gateway/simulator, and the action set is code-derived.

## The 7 build phases (all complete)
0. Scaffold + model warm. 1. Simulator (PLC physics over S7comm + OPC UA gateway).
2. Sensor (Zeek + ICSNPP sidecar in the ews namespace). 3. Attacker (full ATT&CK-tagged
chain over HTTP). 4. Detection + correlation (IT + OT → one incident). 5. Agents (Triage →
Investigation → Response, strict JSON, + gating). 6. Dashboard (process view, kill-chain,
agent pipeline, human gate, scoreboard, attacker console). 7. Reliability (warm model,
one-click reset, offline run, failure handling).

## Productization features F1–F8 (status: all shipped)
- **F1 — Auth/RBAC + corpus NL query.** Mandatory bearer-token auth, roles
  viewer<operator<approver<admin, fail-closed; grounded corpus-wide analyst chat.
- **F2 — Compliance.** Evidence-derived compliance status (never LLM) against CEA/NCIIPC,
  IEC 62443-3-3, NIST SP 800-82 r3; branded DOCX/PDF export.
- **F3 — CVE enrichment.** CPE→CVE via local OUI/CPE resolution + offline NVD snapshot;
  cloud mode sends only a CPE string through the egress boundary.
- **F4 — Purdue topology.** Zone/level inference from discovered assets + Zeek flows.
- **F5 — Response playbooks (SOAR-lite).** Profile-bound YAML that *proposes* ordered
  actions; every step still routes through the gate. Imports no executor.
- **F6 — SIEM/CEF forwarding.** See principle #2.
- **F7 — Casework.** Per-incident case workflow + signed-off report (workflow only; no gate path).
- **F8 — Executor adapters.** See principle #1.

## LLM provider design + the trust-boundary caveat
`llm.py` dispatches to three providers, selected by env (`KAAVAL_LLM_PROVIDER/MODE/MODEL`):
- `openrouter` (default, OpenAI-compatible cloud), `anthropic` (Messages API) — both
  **off-prem**, routed through `egress.py` (pseudonymized + audited).
- `local` (Ollama native `/api/chat`, `format`-schema grammar) — in-process, never leaves
  the box.
`mode` (local|cloud) is the single on-prem/off-prem switch; an unknown/empty provider or
mode fails safe to local. A missing key degrades safely (agents emit "degraded" cards).

**classify() caveat for future work:** today the fail-safe holds because "local" means
loopback Ollama. If/when an `openai_compatible` provider is added that can carry an
arbitrary `base_url`, the on-prem/off-prem decision **must key on the URL** (loopback or an
explicit private allowlist ⇒ on-prem; anything else, or unknown ⇒ **off-prem = masked +
audited**), not on a provider label. Otherwise a "local"-labelled remote URL could bypass
pseudonymization and the egress log. This is the single most important invariant to
preserve when extending the provider layer.

## Test map (`backend/tests/test_kaaval.py`, 95 tests, offline)
Which tests guard which invariant:
- **OT actions gated server-side:** `test_is_gated_attribute_matrix`,
  `test_ot_gated_it_auto_both_profiles`, `test_no_gated_action_is_auto_executable`,
  `test_adapter_cannot_run_ungated_or_unapproved_action`.
- **Unknown ⇒ gated (fail-safe):** `test_gating_fail_safe`,
  `test_playbook_unknown_action_fails_closed`, `test_cve_unknown_is_not_assessed_never_safe`.
- **Separation of duties:** `test_rbac_separation_of_duties`, `test_rbac_required_roles`,
  `test_rbac_token_store`.
- **Off-prem LLM always pseudonymized + key never leaks:**
  `test_egress_pseudonymize_roundtrip`, `test_egress_scrub_denylist`,
  `test_egress_fencing_marks_untrusted`, `test_corpus_tool_output_pseudonymized_for_cloud`,
  `test_secret_never_in_status_disk_error_or_audit`,
  `test_openrouter_egress_is_always_pseudonymized`.
- **SIEM never off-prem / never pseudonymized:**
  `test_siem_carries_real_identity_not_pseudonymized`,
  `test_siem_is_one_way_no_execution_path`, `test_siem_off_by_default_and_fails_gracefully`.
- **Chat needs no local Ollama in cloud mode:** `test_chat_cloud_mode_needs_no_local_ollama`.

## Portability audit — findings & fixes
A pre-publish audit drove the packaging work. Fixed: `requirements.txt` missing
`PyYAML`/`python-docx`/`reportlab`; F3–F8 modules untracked but load-bearing; no LICENSE /
lab warning; app tier not Dockerized (added backend + nginx frontend images, same-origin
proxy); LAN-exposed ports (now `127.0.0.1`); LLM not pluggable for cloud-by-default (now
OpenRouter default, env-driven); chat required Ollama in cloud mode (now skipped);
containerized-backend wiring (attacker URL/OPC endpoint/compose project via env, docker
socket mount, reset via `restart`); demo users (flag-gated, fail-safe); `.gitattributes`
(LF), exec bits, `*.pcap` ignore. Runtime bugs found & fixed during porting: empty-env
provider override, `make test` venv assumption, `make reset` token, backend docker-binary
arch. Verified: 95 tests pass; backend+frontend build for linux/amd64; amd64 sensor loads
both ICSNPP plugins; clean-clone builds; full live run forms a gated cross-domain incident;
console/network audit clean.

## Deferred work / roadmap
- **`openai_compatible` local provider** (vLLM / LM Studio / llama.cpp) with the URL-based
  `classify()` above.
- **CI** (GitHub Actions: offline pytest + frontend build; buildx multi-arch to GHCR).
- **Prebuilt sensor image on GHCR** to remove the first-build Zeek compile.
- Harden the analyst-chat reasoning strip for models that emit untagged reasoning.
- Optional true two-person control (identity-based, not just role-based, SoD).

No secrets, client names, or personal information are recorded here.
