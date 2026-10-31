# CLAUDE.md — build, run, and fix Kaaval

You are a fresh Claude Code instance on someone's machine. Your job: get Kaaval
**built, running, and verified**, and fix any errors along the way. Read this whole
file first. For deeper engineering context see [docs/CONTEXT.md](docs/CONTEXT.md).

## What Kaaval is (5 lines)
Kaaval is a local, self-contained **agentic IT/OT SOC** that defends a *simulated*
Siemens water-pumping station. A scripted attack starts in IT, pivots at the
engineering workstation (`ews`), and manipulates the PLC over S7comm. A real
**Zeek + ICSNPP** sensor detects every stage; three LLM agents correlate it into one
cross-domain incident, map MITRE ATT&CK for ICS, and recommend graded actions.
Reversible IT containment can auto-run; OT control actions are **held for human approval**.

## Architecture
Docker Compose stack (project name is pinned to `kaaval` via `name:` in
`docker-compose.yml`). Services, all host ports bound to **127.0.0.1**:

| Service | Role | Host port |
|---|---|---|
| `plc` | S7comm PLC server + physics (python-snap7) | 1102→102 |
| `gateway` | OPC UA gateway mirroring PLC tags (asyncua) | 4840 |
| `ews` | engineering workstation = the IT/OT pivot (sshd, iptables) | 2222→22 |
| `c2` | external TLS/DNS beacon target | — |
| `attacker` | red-team HTTP API, ATT&CK-tagged kill chain | 8090 |
| `sensor` | **Zeek + ICSNPP**, runs **in the `ews` network namespace** (`network_mode: "service:ews"`) so one capture point sees the whole IT→OT chain; writes JSON logs to `./logs` | — |
| `backend` | FastAPI: detection, correlation, agents, gating, executors; reads `./logs`, talks OPC UA to `gateway`, drives the lab plant via the **mounted docker socket** | 8000 |
| `frontend` | Vite build served by nginx; same-origin reverse proxy of `/api` + `/ws` to `backend` | 8080→80 |
| `ollama` | optional local LLM (profile `local` only) | 11434 |

**Startup order** (enforced by healthchecks + `depends_on`): `plc → gateway → ews →
sensor → backend → frontend`; `attacker` waits for plc/gateway/ews/c2 healthy.
**Data flow:** attacker → ews (IT) → PLC/gateway (OT) → sensor captures in the ews
namespace → Zeek JSON in `./logs` → backend tails logs → detection/correlation →
one incident → agents (local or cloud LLM) → code-derived actions → human gate →
approved OT writes go back out over OPC UA to the gateway.

## Repo map
- `docker-compose.yml`, `Makefile`, `setup.sh`/`setup.ps1`, `.env.example` — run surface.
- `backend/app/` — the product. Key modules: `main.py` (API + loops), `detect.py`/
  `correlate.py`/`rules_engine.py` (detection), `agents.py`+`llm.py`+`egress.py` (agents +
  the single pseudonymizing cloud egress), `gating.py` (OT-safety gate), `actions.py`+
  `executors/` (execute AFTER the gate), `auth.py` (RBAC/SoD), `siem.py`+`cef.py` (on-prem
  SIEM feed), `profile.py` (per-plant config), `chat.py` (grounded analyst chat),
  enrichment (`nvd.py`/`cpe.py`/`oui.py`), `compliance*.py`, `casework.py`, `topology.py`.
- `backend/tests/test_kaaval.py` — offline test suite (95 tests; runs in the container).
- `frontend/src/soc/` (SOC console) and `frontend/src/range/` (Range Console).
- `sim/` — PLC physics + OPC UA gateway. `it/ews`, `it/c2`, `attacker/` — IT + red team.
- `sensor/` — Zeek image + `local.zeek` (zkg installs the two ICSNPP plugins).
- `profiles/*.yaml` — deployment profiles (pump = default, reactor). `backend/app/data/` —
  shipped offline snapshots (OUI/CPE/NVD). `backend/app/frameworks|playbooks/` — config.

## Commands (and expected durations)
```bash
make doctor   # pre-flight checks (OS/arch, Docker, memory, ports, .env) — seconds
make up       # build + start everything. FIRST build 5–15 min (Zeek+ICSNPP compile), then ~20–60 s
make demo     # launch the IT→OT attack chain
make test     # run the 95-test suite inside the backend container (no venv needed)
make reset    # return to a clean pre-attack baseline (plant, logs, containment, incidents)
make down     # stop + remove the stack
make logs     # tail backend + sensor logs
```

## Env / .env
Copy the template and set a key: `cp .env.example .env`.
- `KAAVAL_LLM_PROVIDER` = `openrouter` (default) | `anthropic` | `local`.
- `OPENROUTER_API_KEY` — required for the default provider (https://openrouter.ai/keys).
  Costs a few cents/run; `:free` models cost nothing. **Without a key the stack still runs
  and incidents still form & gate — only the agent narratives degrade.**
- `KAAVAL_LLM_MODEL` — any model slug for the active provider (blank = built-in default).
- **Local Ollama (offline, no key):** set `KAAVAL_LLM_PROVIDER=local`. On macOS run Ollama
  on the host (`ollama pull qwen3:30b-a3b`); the default `OLLAMA_HOST` points at the host. On
  Linux use `make local` (bundled container) with `OLLAMA_HOST=http://ollama:11434`.
- Demo users are seeded by `KAAVAL_SEED_DEMO_USERS=1` (set in compose): tokens
  `kaaval-admin` / `kaaval-approver` / `kaaval-operator`. Lab only.

## Platform notes
- **macOS** (Apple Silicon or Intel): works. Apple Silicon is best for a local model (Metal).
- **Linux** amd64/arm64: works. For a local GPU model use the `local` profile with the NVIDIA
  runtime, or point `OLLAMA_HOST` at a host Ollama.
- **Windows:** requires **Docker Desktop + WSL2**. **Clone inside WSL** (or ensure LF line
  endings — `.gitattributes` enforces `*.sh` = LF) and run `make`/scripts from a WSL shell.
- All images are multi-arch (python:3.12-slim, zeek/zeek:8.1.1, node, nginx); the backend
  image downloads the arch-correct docker CLI via `TARGETARCH`.

## Known issues & fixes
Bugs already fixed in this repo (don't reintroduce):
- **Empty env var overriding the provider:** compose passes an unset `${VAR:-}` as an empty
  string; `config.py` resolves provider/mode with `or` so empty falls back to the default.
- **`make test` venv assumption:** the target runs inside the backend container when it's up,
  else a local `.venv`.
- **`make reset` auth:** reset is admin-gated; `make reset`/`reset_demo.sh` send the admin token.
- **Backend image docker binary arch:** the Dockerfile uses `ARG TARGETARCH` to fetch the
  x86_64/aarch64 docker static binary — keep that.
- **CRLF on Windows:** `.gitattributes` forces `*.sh` to LF; clone inside WSL.

Likely issues on a new machine and how to fix:
- **Port already in use** (8080/8000/8090/4840/1102/2222): stop the conflicting process, or
  change the left-hand `127.0.0.1:PORT` in `docker-compose.yml` (keep the `127.0.0.1:` prefix).
  `make doctor` flags busy ports.
- **Docker memory too low:** raise Docker Desktop memory to ≥8 GB (Settings → Resources);
  more for a local 30B model. `make doctor` warns under 8 GB.
- **buildx missing:** install/enable Docker buildx (bundled with modern Docker Desktop / the
  `docker-buildx` package on Linux).
- **Docker socket permission (Linux):** the backend mounts `/var/run/docker.sock`; add your
  user to the `docker` group (`sudo usermod -aG docker $USER`, re-login) or run with sufficient
  privilege. The lab executor needs the socket.
- **Zeek plugin compile fails:** usually a transient apt/network hiccup during the first build.
  Re-run `docker compose build sensor`. The build needs internet.
- **Agents show "degraded":** no/invalid LLM key, or local Ollama unreachable. Add a key or fix
  `OLLAMA_HOST`. This is safe behavior, not a crash — do not "fix" it by weakening anything.

## How to verify success
1. `make doctor` → all pass (warnings OK).
2. `make up` → `curl -s http://localhost:8000/api/health` shows `gateway: up` and the stack is
   healthy (`docker compose -p kaaval ps` all healthy).
3. `make test` → **95 passed**.
4. `make demo`, then within ~30–60 s a **single correlated IT+OT incident** appears
   (`curl -s http://localhost:8000/api/incident`): `cross_domain: true`, severity `critical`,
   with OT actions `requires_human_approval: true` and IT actions auto-eligible.
5. Approval flow:
   - operator cannot approve: `curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer kaaval-operator' -X POST http://localhost:8000/api/actions/rearm_interlock/approve` → **403**.
   - approver can: same with `kaaval-approver` → **200**, and the OT write executes.
   - plant recovers: `curl -s http://localhost:8000/api/state` → discharge pressure falls back
     into band and `interlock_enabled: true`, `status: ok`.
6. `make reset` → `/api/incident` returns no incident; plant in band.

## NON-NEGOTIABLE INVARIANTS — never break these while fixing anything
If a change would touch any of these, **STOP and ask the human**. Never disable or weaken a
test to make a build pass.
1. OT-changing actions are **always** `requires_human_approval`, enforced **server-side**.
2. Unknown / unattributed actions are **gated** (fail-safe), never auto-run.
3. **Separation of duties:** approving a gated OT action requires the `approver` role; an
   un-authenticated mutation is 401, an under-privileged one is 403.
4. The **LLM never selects or triggers an action** — the action set is code-derived.
5. **Off-prem LLM traffic is always pseudonymized and logged** (via `egress.py`). On-prem =
   loopback or an explicit allowlist only; unknown ⇒ treated as off-prem.
6. The **SIEM/CEF feed is never routed off-prem** and never pseudonymized (it carries real
   identity to the customer's own SIEM); it imports no `actions`/`gating`/`egress`.
7. All published host ports stay bound to **127.0.0.1**.

## Working rules
- **Never commit `.env`, API keys, tokens, or local settings.** They are gitignored — keep it so.
- **Prefer fixing configuration over code.** Most run failures are env/ports/memory/socket, not bugs.
- **Explain every change you make** and why, and keep changes minimal and reversible.
- Run `make test` after any change to backend code; all 95 must pass.
