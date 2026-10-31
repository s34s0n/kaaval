# Screenshot capture guide

The PNGs in this folder are **real captures** of the running app (1440×900, headless
Chrome). To refresh any of them, re-capture the same screen and overwrite the file
in place (keep the exact filename). No API keys or tokens should be visible in any shot.

Start the stack first: `make up` then `make demo` (log in at `http://localhost:8080/`).
Use `?token=kaaval-operator` for operator views and `?token=kaaval-approver` for the
approver view. For non-degraded agent output, use a working LLM (local Ollama, or set
an OpenRouter key).

| File | Screen | How to get there |
|---|---|---|
| `hero.png` | Incident workspace (hero) | During an incident, open Incidents → the incident; frame the kill-chain + agent assessment. |
| `login.png` | Login | Open `http://localhost:8080/` logged out. |
| `soc-home.png` | SOC home (baseline) | After `make reset`, SOC Overview with no active incident. |
| `range-normal.png` | Range normal | `http://localhost:8080/range` before the attack (green schematic). |
| `range-attack.png` | Range attack mid-run | On the Range, click Launch full chain; capture during the run. |
| `incident-workspace.png` | Incident workspace | Incidents → the incident: timeline + ATT&CK mapping. |
| `agents-triage.png` | Triage card | Incident workspace → Triage agent card. |
| `agents-investigation.png` | Investigation card | Incident workspace → Investigation card (IT→OT narrative). |
| `agents-response.png` | Response card | Incident workspace → Response card (graded actions). |
| `gate-awaiting.png` | Gated action (operator) | Logged in as `kaaval-operator`; show the gated OT action held for approval. |
| `gate-approver.png` | Approver view | Logged in as `kaaval-approver`; show the Approve control. |
| `plant-recovered.png` | Plant recovered | After approving the OT actions, Range schematic back to green. |
| `telemetry.png` | Telemetry | SOC → Raw telemetry tail. |
| `detections-coverage.png` | Detections / coverage | SOC → Detection → ATT&CK coverage. |
| `assets.png` | Assets | SOC → Asset discovery. |
| `purdue.png` | Purdue topology | SOC → Network → Purdue model. |
| `chat.png` | Analyst chat | Open the analyst chat; ask "which host is the pivot and what should we do?" |
| `case-report.png` | Case report / compliance | Incident → case report, or SOC → Compliance export. |
| `settings-llm.png` | Settings — LLM | SOC → Settings → LLM provider/model. |

Tip: `make reset` returns a clean baseline for the "before" shots; `make demo`
launches the attack for the "during/after" shots.
