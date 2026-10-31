# Security Policy

## ⚠️ This is offensive lab software — run it isolated

Kaaval ships, on purpose, two things that are dangerous on a shared network:

1. **A deliberately vulnerable engineering workstation** (`it/ews`) — it runs an
   SSH server with a weak, well-known password (`engineer:engineer`) and password
   authentication enabled. It exists to be compromised.
2. **A live red-team attacker service** (`attacker/`) — it drives a real IT→OT kill
   chain (credential use, pivot, direct S7comm writes to the simulated PLC) over an
   HTTP API, tagged with MITRE ATT&CK for ICS.

**Run Kaaval only on an isolated, single-host lab environment that you control.**

- Do **not** deploy it on a production, corporate, or shared network.
- Do **not** expose it to the internet or to any OT/ICS network carrying real
  equipment. The attacker and PLC must never be able to reach real devices.
- All published host ports bind to `127.0.0.1` by default. Keep it that way.
- The seeded demo credentials (`kaaval-admin` / `kaaval-approver` / `kaaval-operator`)
  and the `engineer:engineer` login are for the demo only. Never reuse them, and
  never enable `KAAVAL_SEED_DEMO_USERS` or `KAAVAL_DEV` outside the lab.

The simulated plant and all network traffic are synthetic. No real industrial
equipment is involved or should ever be connected.

## Reporting a vulnerability

If you find a security issue in the Kaaval product code (the agentic layer, the
gating/approval logic, the egress boundary, auth/RBAC), please report it privately
to the maintainers rather than opening a public issue:

- Email: **security@traboda.com**

Please include a description, affected files, and reproduction steps. We will
acknowledge receipt and coordinate a fix. Do not include working exploits against
third parties or any real customer data.

## Scope note

Findings about the intentionally-vulnerable lab components (the `engineer:engineer`
workstation, the attacker service, the unauthenticated simulated PLC) are **out of
scope** — those are features of the range, not bugs. Reports about the defensive
product's trust boundaries (gating, approval, pseudonymized egress, SIEM isolation)
are very much in scope.
