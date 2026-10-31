# Kaaval — Demo Guide (step-by-step, all features)

Kaaval (by Traboda) is a local, offline-capable **agentic IT/OT SOC**. It defends a
simulated Siemens water-pumping station. A real attack starts in IT, pivots across the
IT/OT boundary, and manipulates the physical process. A real Zeek sensor detects every
stage; three AI agents triage, correlate the IT intrusion and the OT manipulation into
**one** incident, map it to MITRE ATT&CK for ICS, and recommend a response. **Every OT
control action is held behind a server-side human approval gate.**

This guide runs the whole product end-to-end. Total time: ~20-30 min for everything,
~8 min for the "hero loop" alone.

---

## 0. Setup & sign-in (2 min)

**What's running** (confirm before you start):
- Docker stack: `plc`, `gateway`, `ews`, `sensor`, `attacker`, `c2` — `docker ps`
- Backend (FastAPI + WebSocket) on `:8000`, Frontend (Vite) on `:5173`
- Ollama serving `qwen3:30b-a3b` on `:11434` (local LLM, fully offline)

**Roles** (separation of duties — the heart of the safety story):

| Token | User | Role | Can do |
|---|---|---|---|
| `tok-operator` | olivia | operator | work cases, apply reversible IT containment |
| `tok-approver` | andre | approver | **approve gated OT control actions**, close cases |
| `tok-admin` | ava | admin | settings, autonomy, attack/range, SIEM/LLM config |

**Sign in (magic link):** open `http://localhost:5173/?token=tok-admin`
(or use the **Sign in** button top-right and paste a token).

**Reset to a clean baseline** (do this before every run):
- UI: **Reset** button (top bar, admin only), or
- API: `curl -X POST -H "Authorization: Bearer tok-admin" http://localhost:8000/api/reset`

Reset reseeds the PLC (setpoint 50, interlock armed), flushes IT containment, clears the
Zeek logs, recreates the sensor, and clears the incident queue. The immutable approval
audit log is intentionally **kept**. Takes ~10s.

> **Say:** "Everything you'll see runs on this Mac, offline — the model is local. No plant
> data leaves the box unless an admin explicitly turns on a cloud model, and even then it
> goes through one sanitizing boundary. I'll show that."

---

## 1. THE HERO LOOP — attack → detect → correlate → agents → human gate → recover (8 min)

This is the core story. Run it first; everything else drills into what it produces.

### 1.1 Show the clean plant (Overview)
Go to **Overview**. Point out the live process view: discharge pressure in band, interlock
armed, pump setpoint at 50. This is the physical plant, read live over OPC UA.

> **Say:** "This is a water pumping station. The pressure and the safety interlock are real
> values read from the PLC every 250ms."

### 1.2 Show the honest inventory (Asset discovery)
Go to **Asset discovery**. You see only the *declared* plant assets: `plc`, `gateway`,
`ews`, `soc_backend`. **No attacker, no C2** — they aren't pre-seeded. Discovery only
reports what it observes.

> **Say:** "Passive discovery — built from the wire, Dragos-style. Notice there's no
> 'attacker' here. We don't cheat by pre-labeling the bad guy."

### 1.3 Launch the attack
Open the **Range Console** (`http://localhost:5173/range`) → **Run full attack chain**
(or `curl -X POST -H "Authorization: Bearer tok-admin" http://localhost:8000/api/attack/run`).

The attacker runs an ATT&CK-tagged chain: SSH foothold on the `ews` → network scan →
C2 beacon → unauthorized OPC UA/S7comm into the OT control path → manipulates the process.

### 1.4 Watch detection light up (live)
- **Raw telemetry** — Zeek log lines stream in (ssh, ssl, dns, conn, opcua, s7comm), with
  flagged lines colored.
- **Detection → Rules** — the IT and OT rules that fired.
- **Overview** — the discharge pressure goes **out of band** / interlock disabled as the
  manipulation lands.

> **Say:** "The sensor is real Zeek with the ICSNPP OT plugins. It detected the IT intrusion
> *and* the OT manipulation independently."

### 1.5 The ONE correlated incident (Incidents)
Go to **Incidents**. There is **exactly one** incident — it spans IT **and** OT
(`cross-domain`). Open it. Walk through, top to bottom:

- **Kill chain** — the detected stages in order, with the **ews pivot** marked at the IT→OT
  crossing. The adversary host reads as **"external adversary host"** / **"C2 endpoint"** —
  a *conclusion* drawn from behavior, not a pre-seeded label.
- **Correlated events** — every fired rule with its ATT&CK technique.
- **AI agent pipeline** — three agents run on the local model, streaming in:
  - **Triage** — severity, priority, what process is at risk, confidence.
  - **Investigation** — the cross-domain narrative + the IT↔OT link + the ATT&CK-ICS chain.
  - **Response** — recommends graded actions, ordered IT-containment-before-OT-recovery.
- **Rogue devices involved** — `172.30.0.14`, `172.30.0.13` recorded as a **durable**
  incident attribute (the transient rogue alert fires once and ages out; this persists).

> **Say:** "One attack, one incident — the IT foothold and the OT manipulation fused into a
> single case, mapped to ATT&CK for ICS, by three agents running offline."

### 1.6 The human gate — separation of duties (the money shot)
In **Response actions · human gate**: IT containment actions are blue ("auto/apply"); OT
recovery actions (`rearm_interlock`, `restore_setpoint`) are **red ("gated")**.

1. **Sign in as the operator** (`?token=tok-operator`, or Sign in → `tok-operator`).
   Try to approve a gated OT action → the button reads **"Approve · requires approver"** and
   is **disabled**. (Via API it's an HTTP **403**.)
2. **Sign in as the approver** (`tok-approver`). The OT action now shows **"Approve &
   execute"**. Click it → a confirmation ceremony shows the *verified* approver (andre) that
   will be recorded. Confirm.
3. The OT action runs (real OPC UA write through the gateway), the interlock re-arms, and the
   **Overview** pressure returns **in band**.

> **Say:** "An operator can investigate and contain on the IT side, but cannot touch OT
> control. Only an approver can, and only by stepping through this gate — which is enforced
> on the server, fails safe, and is recorded against the verified identity. The LLM never
> fires an action; it only *recommends*. The action set is code-derived, not model-chosen."

### 1.7 The audit trail
Below the actions: **Decision log** — one immutable record per approval: who approved what,
when, the gating reason, and the result. This is the chain of custody.

---

## 2. The incident's deeper features (10 min)

All of these hang off the same incident you just made.

### 2.1 F4 — Purdue model topology (Network → Purdue model)
The single topology view. Zones (OT/IT/external) come from the **same source detection and
authz use** — one source of truth. The attacker now appears as an **unmanaged** node
(absent before the attack), and the **IT→OT pivot is a red animated edge** dropping from the
IT band into the OT control band. Findings list flags the unauthorized crossing.

> **Say:** "A red line here is a real authorization finding, not a cosmetic line — it's the
> same `is_authorized_client` check the detection engine uses. The map shows the kill-chain
> pivot path visually: external → IT → through the gateway DMZ → OT."

### 2.2 F3 — CVE enrichment (Asset discovery → Vulnerability exposure)
Scroll down on **Asset discovery**. The Siemens PLC resolves locally to a CPE
(`cpe:2.3:o:siemens:s7-1200_firmware:4.2`) → **3 real CVEs** (incl. CVE-2022-38465, CVSS 9.3).
The gateway is Siemens-by-OUI but firmware unknown → **"not assessed"** (honest, not "safe").

> **Say:** "Asset→CPE resolves *locally*. Only the CPE string ever goes to NVD — never an IP,
> hostname, or how many of these we run. CVE data is informational; it never triggers an
> action."

### 2.3 F5 — Response playbooks (Incident → Response playbook · proposal)
On the incident, the **Response playbook** panel suggests an ordered playbook (the LLM may
*recommend* which one — a suggestion). Step through it: investigation steps + proposed
actions. The OT steps still route through the **exact same gate** — each is an individual
approver decision, recorded individually.

> **Say:** "A playbook is a pre-written *proposal*, not automation. It orders and pre-fills;
> it never pre-authorizes. An unknown action in a playbook fails closed."

### 2.4 F7 — Case management (Incident → Case management)
At the bottom of the incident. Built for a **non-expert operator**:
- **Assign** the case (operator), **add a note**, **move state** (with a logged reason).
- **Close** it (approver only — disposition dropdown) / **Reopen**.
- **Case timeline** — chain of custody: who did what, when, why (incl. the system-recorded
  "rogue device involved" entries).
- **Incident report** — **Generate draft (AI)** → a plain-language report for a
  non-technical reader (facts from the store, prose from the LLM) → edit it → **Sign off**
  (approver) → download branded **PDF / DOCX**.

> **Say:** "This is chain-of-custody for incident response — a government reviewer can read
> exactly who did what. The report is a draft until a person signs off."

### 2.5 F1 — Analyst chat (the side panel in the incident)
Open the **chat** panel. Ask plain-language questions grounded in *real* data:
- "What happened in this incident?"
- "How many assets do we have, and how many are OT?"
- "Which host is unmanaged?"

It answers from the actual incident events, Zeek logs, and asset inventory — read-only tools,
no hallucination. In cloud mode its output is pseudonymized through the egress boundary.

---

## 3. Reporting & integration features (6 min)

### 3.1 F2 — Compliance reporting (Compliance)
Pick a framework: **IEC 62443-3-3**, **NIST SP 800-82 Rev 3**, or **CEA + NCIIPC (India)**.
Each control shows **MET / GAP / NOT-ASSESSED**, and **clicking a control reveals the exact
evidence record** it's traced to (an asset, an approval, an audit entry, a timestamp).
Download **PDF / DOCX**.

> **Say:** "The status is computed from recorded evidence — never the model's opinion.
> Absence of data renders as 'not assessed', never 'met'. Over-claiming is what loses a
> government auditor; every claim here traces to a record."

### 3.2 F6 — SIEM / syslog CEF export (Settings → SIEM forwarding)
Configure a SIEM target (host/port, **UDP/TCP/TLS**). **Preview CEF** for the current
incident, or **Send test heartbeat**. The CEF carries **real** asset identity (it's the
customer's own on-prem SIEM) with the incident id, ATT&CK techniques, src/dst, and the
approval reference.

> **Say:** "Two outbound paths, deliberately different: the cloud LLM is pseudonymized
> because it *leaves* the premises; the SIEM gets real IPs because it's *their* SOC and
> needs to correlate. It's one-way out, off by default, and TLS-capable for a gov SOC."

### 3.3 F8 — Executor adapters (Settings → Executor adapters)
Shows the active **IT** and **OT** adapters, honestly labeled: **`lab`** (docker-exec
reference) vs **`firewall_rest`** (real-integration shape against a documented REST contract).
Selecting an adapter changes only *how* an approved action runs — never *whether*. The gate
stays in front; the adapter is reached only after approval and fails closed on anything
un-gated/un-approved.

### 3.4 Local vs cloud LLM + the egress boundary (Settings → AI Model)
Show the provider picker: **local Ollama** (offline, default) or **cloud (Anthropic /
OpenRouter)**. Switching to cloud routes *every* LLM call through one sanitizing,
pseudonymizing, audited boundary — IPs/asset names become tokens (`PLC_1`, `HOST_1`) before
egress and are restored locally in the render.

> **Say:** "cloud-now and local-later differ by a single config value. We run cloud now
> because the local model isn't strong enough yet; the air-gapped target is the same product,
> minus one toggle."

---

## 4. The "legitimate vs malicious" contrast (optional, 2 min)
On the **Range Console**: run a **legitimate** operator setpoint change (operator → gateway
over OPC UA). Kaaval raises **no alert** — it's an authorized path through the gateway. Then
run the **malicious** direct write from the `ews`. Kaaval alerts immediately.

> **Say:** "Same physical effect, opposite verdict. Authorization is profile-driven — the
> `ews` speaking S7comm directly to the PLC is anomalous *by definition*, the gateway doing
> it is not."

---

## 5. Reset & wrap (1 min)
Hit **Reset**. Clean baseline restored. You can re-run the whole loop immediately.

### The three things to leave them with
1. **One incident across IT and OT** — real detection, agentic correlation, ATT&CK-ICS.
2. **The gate** — OT control is server-side human-approved, fail-safe, role-separated,
   audited; the LLM never fires an action.
3. **Trust boundaries** — offline by default; cloud egress pseudonymized; SIEM gets real
   identity on-prem; compliance is evidence-derived, never model opinion.

---

## Quick reference — API equivalents (for a headless / scripted demo)

```bash
ADMIN='-H "Authorization: Bearer tok-admin"'
# reset, attack
curl -X POST -H "Authorization: Bearer tok-admin" http://localhost:8000/api/reset
curl -X POST -H "Authorization: Bearer tok-admin" http://localhost:8000/api/attack/run
# the incident
curl -H "Authorization: Bearer tok-admin" http://localhost:8000/api/incidents
# gate: operator blocked (403), approver approves
curl -X POST -H "Authorization: Bearer tok-operator" "http://localhost:8000/api/actions/rearm_interlock/approve?incident_id=<INC>"   # 403
curl -X POST -H "Authorization: Bearer tok-approver" "http://localhost:8000/api/actions/rearm_interlock/approve?incident_id=<INC>"   # OK
# features
curl -H "Authorization: Bearer tok-admin" http://localhost:8000/api/topology
curl -H "Authorization: Bearer tok-admin" http://localhost:8000/api/enrichment
curl -H "Authorization: Bearer tok-admin" "http://localhost:8000/api/playbooks/suggest?incident=<INC>"
curl -H "Authorization: Bearer tok-admin" "http://localhost:8000/api/compliance/report?framework=iec_62443_3_3"
curl -H "Authorization: Bearer tok-admin" "http://localhost:8000/api/siem/preview?incident=<INC>"
curl -H "Authorization: Bearer tok-admin" http://localhost:8000/api/executors
```

## Troubleshooting
- **Incident slow to appear / agents not running:** detection polls every 2s; agents run
  after the incident is stable ~6s. Give it ~20-30s after launching the attack.
- **OT recovery button says "requires approver":** you're signed in as operator — switch to
  `tok-approver`. That's the demo working as intended.
- **Manual OT write "blackholed":** IT containment is active (the ews is isolated) — that's
  correct; Reset to restore the path.
- **Model slow/cold:** `bash scripts/warm_model.sh` to pre-warm Ollama before the demo.
