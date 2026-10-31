---
description: Set up, build, start, and verify Kaaval end to end (with diagnosis + fixes on failure)
---

You are setting up Kaaval on this machine for the first time. Read `CLAUDE.md`
(especially **Known issues & fixes** and the **NON-NEGOTIABLE INVARIANTS**) before you
start. Work through these steps in order. After each step, confirm it succeeded before
moving on. On any failure: read the logs, diagnose, consult the known-issues in
`CLAUDE.md`, apply the smallest fix (prefer config over code), retry, and tell the user
exactly what you changed and why. Never weaken a test or an invariant to make something pass.

1. **Pre-flight.** Run `make doctor`. Resolve every `FAIL` (and ideally the `WARN`s) before
   continuing — low Docker memory, busy ports, missing buildx, docker socket permissions,
   and CRLF line endings are the common ones; `make doctor` prints fix hints.

2. **Configure.** If `.env` does not exist, create it from `.env.example`. The default LLM
   provider is **OpenRouter, a paid cloud service**: tell the user they must **create their
   own API key at https://openrouter.ai/keys** and that **each agent run costs money** (a few
   cents; `:free` models are free). Ask for the key and set `OPENROUTER_API_KEY` in `.env`.
   If the user has no key or wants to avoid cloud cost, instead set `KAAVAL_LLM_PROVIDER=local`
   and follow the local-Ollama notes in `CLAUDE.md`. Never print the key back or commit `.env`.

3. **Build + start.** Run `make up`. Warn the user the **first build takes ~5–15 min** (Zeek +
   ICSNPP compile). Wait until `docker compose -p kaaval ps` shows every service healthy and
   `curl -s http://localhost:8000/api/health` reports `gateway: up`.

4. **Test.** Run `make test`. All **95 tests must pass**. If any fail, stop and diagnose — do
   not disable tests.

5. **Demo + verify.** Run `make demo`. Within ~30–60 s confirm, via
   `curl -s http://localhost:8000/api/incident`, a single **correlated IT+OT incident**:
   `cross_domain: true`, severity `critical`, OT actions `requires_human_approval: true`,
   IT actions auto-eligible. Then verify the gate:
   - operator approve → **403**:
     `curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer kaaval-operator' -X POST http://localhost:8000/api/actions/rearm_interlock/approve`
   - approver approve → **200** (executes the OT write):
     `curl -s -H 'Authorization: Bearer kaaval-approver' -X POST http://localhost:8000/api/actions/rearm_interlock/approve`
     and `.../restore_setpoint/approve`
   - plant recovers: `curl -s http://localhost:8000/api/state` → discharge pressure back in
     band, `interlock_enabled: true`, `status: ok`.

6. **Report.** Print:
   - the URLs — **SOC** `http://localhost:8080/`, **Range Console** `http://localhost:8080/range`;
   - the demo logins (lab-only): `kaaval-operator`, `kaaval-approver`, `kaaval-admin`
     (e.g. `http://localhost:8080/?token=kaaval-operator`);
   - that `make demo` relaunches the attack, `make reset` returns a clean baseline, and
     `make down` stops everything;
   - a short summary of anything you changed to get it working.
