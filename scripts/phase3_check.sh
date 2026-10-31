#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Phase 3 observable — confirm the attack chain produced real impact AND that
# every stage landed in the right Zeek log, sourced from the ews.
set -uo pipefail
cd "$(dirname "$0")/.."

exec .venv/bin/python - "$@" <<'PY'
import asyncio, glob, json, os, sys

LOGDIR = "./logs"
GREEN, RED, RESET = "\033[1;32m", "\033[1;31m", "\033[0m"

def load(name):
    rows = []
    for path in sorted(glob.glob(os.path.join(LOGDIR, name))):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try: rows.append(json.loads(line))
                    except json.JSONDecodeError: pass
    return rows

def pf(ok, label, detail):
    tag = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"{tag} {label:<22} {detail}")
    return ok

# --- physical impact, read over OPC UA -------------------------------------
from asyncua import Client, ua
NS = "http://traboda.com/kaaval/pumpstation"

async def read_plant():
    async with Client("opc.tcp://127.0.0.1:4840/kaaval/") as c:
        idx = await c.get_namespace_index(NS)
        p = await c.get_node(ua.NodeId("PumpStation.DischargePressure", idx)).read_value()
        il = await c.get_node(ua.NodeId("PumpStation.InterlockEnabled", idx)).read_value()
        sp = await c.get_node(ua.NodeId("PumpStation.PumpSetpoint", idx)).read_value()
        return p, il, sp

print("Kaaval Phase 3 — impact + detection check\n")
try:
    pressure, interlock, setpoint = asyncio.run(read_plant())
except Exception as e:
    print(f"{RED}ERROR{RESET} cannot read plant over OPC UA: {e}"); sys.exit(2)

ok = True
ok &= pf(not interlock, "IMPACT interlock", f"interlock_enabled={interlock} (expect False/disabled)")
ok &= pf(setpoint >= 99, "IMPACT setpoint", f"pump_setpoint={setpoint:.0f}% (expect 100)")
ok &= pf(pressure > 6.0, "IMPACT pressure", f"discharge_pressure={pressure:.2f} bar (out of band, climbing to burst)")
print()

# --- detection evidence in the Zeek logs, sourced from the ews -------------
ssl = load("ssl.log")
ews_ip = ssl[0]["id.orig_h"] if ssl else None   # ews originates the TLS beacon
print(f"(ews identified as {ews_ip} from ssl.log)\n" if ews_ip else "(no ssl.log yet)\n")

def from_ews(rows, key="id.orig_h"):
    return [r for r in rows if ews_ip and r.get(key) == ews_ip]

ssh = load("ssh.log")
ok &= pf(any(r.get("id.resp_p") == 22 for r in ssh), "T0822 ssh.log",
         f"{len(ssh)} row(s), login to ews:22")
ok &= pf(bool(from_ews(ssl)), "T0869 ssl.log", f"{len(ssl)} TLS row(s) ews->c2:443")
dns = load("dns.log")
ok &= pf(any("kaaval-c2" in str(r.get("query","")) for r in dns), "T0869 dns.log",
         f"{len(dns)} DNS row(s), beacon query present")
conn = load("conn.log")
scan = [r for r in from_ews(conn) if r.get("id.resp_p") in (22,102,443,4840)]
ok &= pf(len(scan) >= 4, "T0846 conn.log", f"{len(scan)} scan conn(s) from ews to OT ports")
opcua = load("opcua_binary.log")
ok &= pf(bool(from_ews(opcua)), "T0888 opcua_binary", f"{len(opcua)} OPC UA row(s) ews->gateway")
s7 = load("s7comm.log")
s7_ews = from_ews(s7)
# A write shows up as a job/function referencing write; print the function fields seen.
funcs = sorted({str(r.get("function") or r.get("function_name") or r.get("item_function") or r.get("rosctr") or "?") for r in s7_ews})
has_write = any("write" in f.lower() for f in funcs)
ok &= pf(bool(s7_ews), "T0855 s7comm.log", f"{len(s7_ews)} S7 row(s) ews->plc; functions={funcs}")
pf(has_write, "T0836/T0831 s7 write", "write job present" if has_write else "no explicit 'write' function field (see functions above)")

print()
print(f"{GREEN}PHASE 3 PASS{RESET}" if ok else f"{RED}PHASE 3 INCOMPLETE{RESET}")
sys.exit(0 if ok else 1)
PY
