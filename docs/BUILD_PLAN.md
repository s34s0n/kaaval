# Agentic IT/OT-SOC — Local Pitch Demo: Architecture and Build Prompt

Target machine: Apple M1 Max, 64 GB. Runs fully offline on one laptop. Built with Claude Code, phase by phase, validated after each phase.

---

## Part 1 — Architecture

### What we are building
A working product that defends a Siemens-controlled critical-infrastructure plant. A real attack starts in IT, crosses the IT/OT boundary, and manipulates the physical process. A real sensor detects every stage, and three AI agents triage it, correlate the IT intrusion and the OT manipulation into one incident, map it to MITRE ATT&CK for ICS, and recommend a response. Reversible IT containment runs automatically. Any action that touches the physical control plane is blocked until a human approves it. The audience watches the plant start to fail and then recover on screen.

The product is the agentic layer plus the dashboard. The sensing and the model server are open source and replaceable later.

### Why this stands out
- It is a true IT/OT convergence demo, not an OT-only one. The attack begins with IT protocols and pivots into OT, which is how real critical-infrastructure intrusions work.
- The OT protocols are OPC UA (the modern Industry 4.0 convergence protocol, the trending angle) and S7comm (the Siemens PLC protocol from the Stuxnet lineage, instant gravitas). No Modbus.
- The differentiator is cross-domain correlation: the agent links the IT intrusion to the OT impact across the boundary into a single incident. Most OT tools see only OT and most IT SOCs see only IT.

### Decisions (locked, no alternatives)
- **Model server:** Ollama, native on the Mac (Metal GPU), not in Docker.
- **Model:** `qwen3:30b-a3b` (MoE, fast on Apple Silicon, strong reasoning), kept warm. If that tag is unavailable, use the current Qwen3 ~30B instruct tag and note it.
- **IT protocols (Zeek native, no plugins):** SSH and RDP for remote access, TLS and DNS for C2 beaconing, connection logs for scanning and lateral movement.
- **OT protocols (Zeek + ICSNPP plugins):** OPC UA Binary (`icsnpp-opcua-binary`) for the IT/OT gateway, S7comm (`icsnpp-s7comm`) for the PLC.
- **Process simulator:** Python. The PLC is `python-snap7` running an S7comm server plus the physics loop. The gateway is `asyncua` running an OPC UA server that mirrors the PLC tags. Models a water pumping station with a discharge-pressure safety interlock.
- **Sensor:** Zeek with `icsnpp-opcua-binary` and `icsnpp-s7comm`, JSON logging, running as a sidecar that shares the engineering-workstation network namespace.
- **Storage:** SQLite inside the backend. No OpenSearch or Wazuh in the demo.
- **Backend / product:** Python FastAPI, WebSocket to the frontend. Talks OPC UA (`asyncua`, pure Python, no native dependency on the Mac) to the gateway for reading process state and issuing approved writes. Holds IT and OT detection, cross-domain correlation, the agent pipeline, the OT-safety gate, response actions, and the audit log.
- **Attacker:** Python red-team service with an HTTP API that runs the whole chain (SSH/RDP access, TLS/DNS beacon, scan, OPC UA browse, S7comm rogue write), each stage tagged with its ATT&CK technique.
- **Frontend:** React + Vite + Tailwind + Framer Motion. Dark, branded, one product-name constant.
- **Orchestration:** Docker Compose for the plant, gateway, IT hosts, attacker, and sensor. Backend, frontend, and Ollama run natively.

### Demo scenario (the one we build and validate against)
1. Baseline: plant normal. The gateway polls the PLC over S7comm and exposes tags over OPC UA. Discharge pressure is in band, the safety interlock is armed.
2. Initial access: attacker logs into the engineering workstation (EWS) over SSH or RDP from an unrecognized external host, off-hours. [IT] ATT&CK ICS T0822 External Remote Services.
3. C2: the EWS beacons to an external host over TLS and DNS on a fixed interval. [IT]
4. Discovery: the EWS scans the OT subnet. [IT] T0846 Remote System Discovery.
5. Boundary recon: the EWS connects to the OPC UA gateway and browses the address space to find control tags. [OPC UA]
6. Pivot and impact: the EWS opens a direct S7comm session to the PLC (the EWS is not an authorized S7 client), disables the safety interlock, and forces the pump setpoint to maximum. [S7comm] T0855 Unauthorized Command Message, T0836 Modify Parameter, T0831 Manipulation of Control.
7. Discharge pressure climbs toward burst; the process view goes red.
8. Detection: Zeek logs the SSH/RDP login, the TLS/DNS beacon, the scan, the OPC UA browse, and the unauthorized S7comm writes, all from the EWS.
9. Agents run live: Triage (severity from process criticality) -> Investigation (correlate the IT intrusion and the OT manipulation into one cross-boundary incident, identify the EWS as the pivot, map ATT&CK ICS) -> Response (graded actions).
10. Auto action: isolate the EWS from the OT segment (reversible, low risk). Gated action: re-arm the interlock and restore the safe setpoint (touches the control plane, held for human approval).
11. Human approves. The backend isolates the EWS and restores the setpoint through the gateway over OPC UA, the legitimate path. Pressure recovers on screen.
12. Scoreboard: techniques detected across IT and OT, time from attack to detection, time to containment.

### Data flow and capture topology (get this right or capture breaks)
- Compose network holds: `plc`, `gateway`, `ews` (engineering workstation, the pivot box), `c2` (external beacon endpoint), `attacker`, `sensor`.
- Every malicious flow either terminates at or originates from the EWS. So the `sensor` (Zeek) runs with `network_mode: "service:ews"`, sharing the EWS network namespace, and sees the entire IT-to-OT kill chain from one capture point. This is the reliable pattern on macOS Docker, where the host cannot sniff the bridge.
- Zeek writes JSON logs to a host-mounted `./logs` directory. The native backend tails the IT logs (`ssh.log`, `ssl.log`, `dns.log`, `conn.log`, plus `rdp` where present) and the OT logs (`opcua*` and `s7comm*`).
- Legitimate OT access is the gateway and the authorized HMI path only. The EWS speaking S7comm directly to the PLC is therefore anomalous by definition, which makes the OT detection crisp.
- The backend is the authorized operator: it reads process state from the gateway over OPC UA at ~4 Hz for the animation, and issues approved control writes through the gateway.

### Repo structure
```
otsoc-demo/
  docker-compose.yml
  sim/
    plc.py            # python-snap7 S7 server + physics (pump station)
    gateway.py        # asyncua OPC UA server mirroring PLC tags (IT/OT boundary)
    Dockerfile
  it/
    ews/Dockerfile    # engineering workstation: sshd + client tooling (the pivot box)
    c2/Dockerfile     # fake external C2 endpoint for beaconing
  sensor/
    Dockerfile        # zeek + icsnpp-opcua-binary + icsnpp-s7comm, JSON logs
    local.zeek
  attacker/
    attacks.py        # ssh/rdp access, tls/dns beacon, scan, opcua browse, s7 rogue write
    api.py
    Dockerfile
  backend/
    app/{main,detect_it,detect_ot,correlate,agents,gating,actions,store}.py
    requirements.txt  # fastapi, uvicorn, websockets, asyncua, ollama client
  frontend/
    src/...           # React + Vite + Tailwind + Framer Motion
  scripts/
    warm_model.sh, reset_demo.sh, run_all.sh
  README.md           # exact run order + the spoken demo script
```

### Build order with validation gates
Each phase stops at its definition of done and produces the listed observable. Hand that back for validation before the next phase starts.

- **Phase 0 — Scaffold + model.** Repo created, Ollama installed, model pulled and warm. Test: a script sends a prompt and prints the reply with tokens/sec. Validate: responds, latency acceptable.
- **Phase 1 — Simulator.** PLC physics over S7comm plus the OPC UA gateway mirroring tags. Test: a reader prints discharge pressure and interlock state over OPC UA for 60s, all in band, plus the documented tag and register map. Validate: physics sane, gateway mirrors correctly.
- **Phase 2 — Sensor.** Zeek + ICSNPP plugins as a sidecar in the EWS namespace, JSON logs. Test: from the EWS, generate IT traffic (an SSH login, a TLS connection, a port scan) and OT traffic (an OPC UA browse, an S7 read), and show entries in `ssh.log`, `ssl.log`, `conn.log`, the OPC UA log, and the S7comm log. Validate: one sidecar captures both IT and OT flows. (Highest-risk phase, front-loaded.)
- **Phase 3 — Attacker.** The full chain via HTTP, ATT&CK-tagged. Test: running the chain drives the plant unsafe AND every stage appears in the correct Zeek log, all sourced from the EWS. Validate: real cause-and-effect, every stage independently detectable.
- **Phase 4 — Detection + correlation.** IT rules (remote-access anomaly, beaconing, scanning) and OT rules (unauthorized OPC UA browse, unauthorized direct S7 write) produce events; events correlate into one incident spanning IT and OT. Test: the chain yields the expected IT and OT events and exactly one correlated incident; baseline yields none. Validate: detections correct, no false positives, correlation links IT to OT.
- **Phase 5 — Agent pipeline.** Triage, Investigation, Response on Ollama, strict JSON, plus the gating policy. Investigation must correlate across IT and OT. Test: feeding the incident yields sensible triage, a cross-boundary attack narrative, ATT&CK ICS mapping, and graded actions with control actions correctly gated. Validate: reasoning quality, gating correctness, JSON never breaks the UI.
- **Phase 6 — Dashboard.** Animated process view, IT/OT kill-chain view showing the boundary crossing, alert stream, agent pipeline, human gate wired to real actions, scoreboard, attacker console. Test: full loop in the browser, approval triggers on-screen recovery. Validate: visuals, the recovery moment, end-to-end timing.
- **Phase 7 — Reliability.** Warm-model script, one-click reset, offline run, failure handling, README demo script. Test: five clean full runs, working reset, a run with wifi off. Validate: demo-ready.

---

## Part 2 — Prompt to paste into Claude Code

Copy everything in the block below into Claude Code as the opening instruction.

```
You are building a local, offline agentic SOC demo for IT/OT critical-infrastructure security. It runs entirely on an Apple M1 Max with 64 GB RAM. This is a pitch demo: it must be reliable, look like a finished product, and run with no internet.

GOAL
Defend a Siemens-controlled water pumping station. A real attack starts in IT, pivots across the IT/OT boundary, and manipulates the physical process. A real sensor detects every stage. Three AI agents triage, correlate the IT intrusion and the OT manipulation into ONE incident, map to MITRE ATT&CK for ICS, and recommend a response. Reversible IT containment runs automatically; any action touching the physical control plane is blocked until a human approves it. The dashboard shows the plant failing and then recovering.

LOCKED STACK (do not substitute without telling me first)
- Model server: Ollama, native on the Mac (Metal GPU), not in Docker.
- Model: qwen3:30b-a3b, kept warm. If unavailable, use the current Qwen3 ~30B instruct tag and tell me which.
- IT protocols, detected by Zeek natively (no plugins): SSH, RDP, TLS, DNS, connection logs.
- OT protocols, detected by Zeek + ICSNPP plugins: OPC UA Binary (icsnpp-opcua-binary) and S7comm (icsnpp-s7comm).
- Simulator: PLC is python-snap7 running an S7 server plus the physics loop; gateway is asyncua running an OPC UA server mirroring the PLC tags.
- Sensor: Zeek with icsnpp-opcua-binary and icsnpp-s7comm, JSON logging.
- Storage: SQLite in the backend.
- Backend: Python FastAPI with a WebSocket to the frontend; talks OPC UA via asyncua to the gateway (no native deps on the Mac).
- Attacker: Python red-team service with an HTTP API; each attack stage tagged with its ATT&CK technique.
- Frontend: React + Vite + Tailwind + Framer Motion; one product-name constant.
- Orchestration: Docker Compose for plc, gateway, ews, c2, attacker, sensor. Backend, frontend, and Ollama run natively.

CAPTURE TOPOLOGY (critical)
- Compose network: plc, gateway, ews (engineering workstation, the pivot box), c2 (external beacon endpoint), attacker, sensor.
- Every malicious flow originates from or terminates at the ews. The sensor (Zeek) uses network_mode: "service:ews" so it shares the ews namespace and captures the whole IT-to-OT chain from one point. Do not try to sniff the docker bridge from the macOS host; it does not work.
- Zeek writes JSON logs to a host-mounted ./logs directory; the native backend tails the IT logs (ssh, ssl, dns, conn) and the OT logs (opcua, s7comm).
- Authorized OT access is the gateway and the authorized HMI only. The ews speaking S7comm directly to the plc is anomalous by definition.
- The backend reads process state from the gateway over OPC UA at ~4 Hz for the animation and issues approved control writes through the gateway.

DEMO SCENARIO TO IMPLEMENT
1. Baseline: gateway polls plc over S7comm, exposes tags over OPC UA; discharge pressure in band, safety interlock armed.
2. Initial access: attacker logs into the ews over SSH or RDP from an unknown external host (ATT&CK ICS T0822).
3. C2: ews beacons to c2 over TLS and DNS on a fixed interval.
4. Discovery: ews scans the OT subnet (T0846).
5. Boundary recon: ews browses the OPC UA gateway address space.
6. Pivot and impact: ews opens a direct S7comm session to the plc, disables the interlock, forces the pump setpoint to max (T0855, T0836, T0831).
7. Pressure climbs toward burst; the process view goes red.
8. Zeek logs every stage from the ews.
9. Agents: Triage -> Investigation (correlate IT + OT into one cross-boundary incident, identify the ews pivot, map ATT&CK ICS) -> Response (graded actions).
10. Auto: isolate the ews from the OT segment. Gated: re-arm the interlock and restore the setpoint, held for human approval.
11. On approval, isolate the ews and restore the setpoint through the gateway over OPC UA; the plant recovers on screen.
12. Scoreboard: techniques across IT and OT, time-to-detect, time-to-contain.

OT-SAFETY GATING RULE (core product logic)
Any action that changes OT control state, is irreversible, or could affect the physical process must be marked requires_human_approval and must not execute until a human approves. Only low-risk reversible IT-side actions may run automatically. The Response agent must state in plain language why each gated action is gated.

HARD CONSTRAINTS
- Fully offline. No external API calls in the running product. The model is local via Ollama.
- The detection path must be real: the sensor detects actual attack traffic across both IT and OT. The UI must never fabricate an alert.
- Agent outputs are strict JSON, parsed defensively; a malformed model response must never crash the UI.
- Keep the model warm; the first on-stage response must not cold-start.
- Provide a one-click reset that returns the plant and the dashboard to a clean pre-attack state.

BUILD PROCESS
Build in the seven phases below. Stop at the end of each phase, run its test, and show me the observable output. Do not start the next phase until I confirm. Do not skip ahead or stub the detection path.

Phase 0 — Scaffold the repo; install/verify Ollama; pull and warm the model. Show: a script that prompts the model and prints the reply with tokens/sec.
Phase 1 — Build the PLC physics over S7comm and the OPC UA gateway mirroring tags. Show: a reader printing discharge pressure and interlock state over OPC UA for 60s, all in band, plus the documented tag/register map.
Phase 2 — Build the Zeek sensor with icsnpp-opcua-binary and icsnpp-s7comm as a sidecar in the ews namespace. Show: from the ews, IT traffic (ssh, a TLS connection, a scan) and OT traffic (opcua browse, s7 read) all appearing in the right JSON logs.
Phase 3 — Build the attacker service running the full chain, ATT&CK-tagged. Show: the chain drives the plant unsafe AND every stage appears in the correct Zeek log, sourced from the ews.
Phase 4 — Build IT and OT detection rules and cross-domain correlation into one incident. Show: the chain produces the expected IT and OT events and exactly one correlated incident; baseline produces none.
Phase 5 — Build the agent pipeline (Triage, Investigation, Response) on Ollama with strict JSON and the gating policy; Investigation correlates across IT and OT. Show: feeding the incident yields sensible triage, a cross-boundary narrative, ATT&CK ICS mapping, and correctly gated actions.
Phase 6 — Build the dashboard: animated process view, IT/OT kill-chain view, alert stream, agent pipeline, human gate wired to real actions, scoreboard, attacker console. Show: the full loop in the browser with approval triggering on-screen recovery.
Phase 7 — Reliability: warm-model script, one-click reset, offline run, failure handling, and a README with the exact run order and spoken demo script. Show: five clean full runs, working reset, and a run with wifi off.

Start with Phase 0. Confirm the plan back to me in two lines, then build Phase 0 and stop for my review.
```

---

## Validation cadence (how we work)
Claude Code builds one phase, then stops and shows the observable. You paste me that output (logs, a screenshot, or the relevant code). I check it against the phase's definition of done, flag anything wrong, and tell you to proceed or fix. Phase 2 (one Zeek sidecar capturing both IT and OT) and Phase 5 (the agents, cross-domain correlation, and gating) are the two most likely to need a second pass, so bring those to me first.
