# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""ArcSight CEF formatting for the SIEM feed — pure, no I/O.

TRUST BOUNDARY (deliberate, see CLAUDE.md): the SIEM is an INTERNAL destination on
the customer's own premises, configured by their admin. Its whole purpose is to
correlate against THEIR other logs, so it legitimately carries REAL asset identity
(real IPs/hostnames). This is the OPPOSITE of the cloud-LLM egress boundary
(egress.py), which pseudonymizes because it leaves the premises. The SIEM path must
NOT route through the pseudonymizer — doing so would break SIEM correlation. That
asymmetry is intentional.

CEF line:  CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext k1=v1 k2=v2
Header fields escape '\\' and '|'; extension VALUES escape '\\', '=' and newlines.
Severity is an integer 0-10.
"""

from __future__ import annotations

import re
import time
from collections import OrderedDict

from . import adversary, profile

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _ip_for_name(name: str) -> str | None:
    for a in profile.assets():
        if a.get("id") == name and a.get("ips"):
            return a["ips"][0]
    return None


def _endpoint(val):
    """An event endpoint may be 'ip', 'ip:port', 'name', or 'name:port'. Return
    (ip, hostname, port) so CEF gets a real IP in src/dst, the name in shost/dhost,
    and the port in spt/dpt — not a hostname jammed into the IP field."""
    if not val:
        return None, None, None
    host, _, port = str(val).partition(":")
    port = port or None
    if _IP_RE.match(host):
        return host, profile.name_for_ip(host), port
    return _ip_for_name(host), host, port

CEF_VERSION = 0
VENDOR = "Traboda"
PRODUCT = "Kaaval"
PRODUCT_VERSION = "1.0"

# our severity label -> CEF 0-10
_CEF_SEV = {"info": 0, "low": 3, "medium": 5, "high": 8, "critical": 10}


def cef_severity(sev) -> int:
    if isinstance(sev, (int, float)):
        return max(0, min(10, int(sev)))
    return _CEF_SEV.get((sev or "").lower(), 5)


def _esc_header(s) -> str:
    return str(s).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", "")


def _esc_ext(s) -> str:
    return str(s).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")


def _extension(d: "OrderedDict") -> str:
    return " ".join(f"{k}={_esc_ext(v)}" for k, v in d.items() if v is not None and v != "")


def build(signature_id: str, name: str, severity, extension: "OrderedDict") -> str:
    header = "|".join([
        f"CEF:{CEF_VERSION}", _esc_header(VENDOR), _esc_header(PRODUCT), _esc_header(PRODUCT_VERSION),
        _esc_header(signature_id), _esc_header(name), str(cef_severity(severity)),
    ])
    return f"{header}|{_extension(extension)}"


# --- domain mappings --------------------------------------------------------

def _rt_ms(ts) -> int | None:
    return int(ts * 1000) if ts else None


def incident_to_cef(inc: dict, events: list[dict] | None = None) -> str:
    """Map a correlated incident to a CEF alert carrying REAL asset identity so the
    customer's SIEM can correlate it against their other logs."""
    events = events or []
    techs = [t.get("id") if isinstance(t, dict) else t for t in (inc.get("techniques") or [])]
    flow = next((e for e in events if e.get("domain") == "OT"), events[0] if events else {})
    src_ip, src_host, src_pt = _endpoint(flow.get("src"))
    dst_ip, dst_host, dst_pt = _endpoint(flow.get("dst"))
    # Behavioral adversary label (narrative layer) for the hostname fields; src/dst
    # keep the REAL IP for SIEM correlation.
    _labels = adversary.label_hosts(events)
    src_host = _labels.get(str(flow.get("src") or "").split(":")[0]) or src_host
    dst_host = _labels.get(str(flow.get("dst") or "").split(":")[0]) or dst_host
    cross = bool(inc.get("cross_domain"))
    name = "IT-to-OT intrusion" if cross else "OT/ICS security incident"
    sig = "kaaval:" + (techs[0] if techs else (inc.get("pivot") or "incident"))

    ext = OrderedDict()
    ext["externalId"] = inc.get("id")            # SIEM correlation key back to Kaaval
    ext["rt"] = _rt_ms(inc.get("last_seen") or inc.get("created"))
    ext["src"] = src_ip; ext["shost"] = src_host; ext["spt"] = src_pt
    ext["dst"] = dst_ip; ext["dhost"] = dst_host; ext["dpt"] = dst_pt
    ext["proto"] = (flow.get("evidence") or {}).get("service") or flow.get("proto")
    ext["cat"] = "IT/OT Intrusion" if cross else "ICS Alert"
    ext["cs1Label"] = "mitreTechniques"; ext["cs1"] = ",".join(t for t in techs if t)
    ext["cs2Label"] = "domains"; ext["cs2"] = ",".join(inc.get("domains") or [])
    ext["cs3Label"] = "crossDomain"; ext["cs3"] = str(cross).lower()
    ext["msg"] = inc.get("summary")
    return build(sig, name, inc.get("severity"), ext)


def approval_to_cef(ap: dict) -> str:
    """Map an immutable approval/decision record to a CEF audit event, so the SIEM
    holds the response audit trail (who approved which gated OT action, and where)."""
    ext = OrderedDict()
    ext["externalId"] = ap.get("incident_id")
    ext["rt"] = _rt_ms(ap.get("ts"))
    ext["act"] = ap.get("decision")              # approved / applied
    ext["duser"] = ap.get("approver")            # the VERIFIED principal
    ext["cs1Label"] = "action"; ext["cs1"] = ap.get("action")
    ext["cs2Label"] = "gated"; ext["cs2"] = str(bool(ap.get("gated"))).lower()
    ext["outcome"] = "success" if ap.get("result_ok") else "failure"
    ext["msg"] = ap.get("gating_reason") or ap.get("rationale")
    name = f"OT control action {ap.get('decision', 'decision')}"
    return build("kaaval:approval", name, "high", ext)


def heartbeat_cef() -> str:
    ext = OrderedDict()
    ext["msg"] = "Kaaval SIEM connectivity test"
    return build("kaaval:heartbeat", "Kaaval SIEM test", "low", ext)


# --- syslog framing (RFC 3164-style) ----------------------------------------

def _syslog_sev(cef_sev: int) -> int:
    # CEF 0-10 -> syslog severity 0-7 (lower = more severe)
    if cef_sev >= 9: return 2     # critical
    if cef_sev >= 7: return 3     # error
    if cef_sev >= 4: return 4     # warning
    if cef_sev >= 1: return 5     # notice
    return 6                      # informational


def syslog_line(cef: str, *, host: str = "kaaval", facility: int = 16,
                cef_sev: int = 5, ts: float | None = None) -> str:
    pri = facility * 8 + _syslog_sev(cef_sev)
    stamp = time.strftime("%b %d %H:%M:%S", time.localtime(ts or time.time()))
    return f"<{pri}>{stamp} {host} {cef}"


# --- parser (for validation / round-trip tests) -----------------------------

def _split_unescaped(s: str, sep: str, maxsplit: int) -> list[str]:
    out, buf, i, n = [], [], 0, 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            buf.append(s[i:i + 2]); i += 2; continue
        if c == sep and n < maxsplit:
            out.append("".join(buf)); buf = []; n += 1; i += 1; continue
        buf.append(c); i += 1
    out.append("".join(buf))
    return out


def parse(line: str) -> dict:
    """Parse a (possibly syslog-framed) CEF line. Raises ValueError if malformed —
    used by tests to assert the output is real, parseable CEF."""
    idx = line.find("CEF:")
    if idx < 0:
        raise ValueError("no CEF: prefix")
    body = line[idx:]
    parts = _split_unescaped(body, "|", 7)
    if len(parts) < 8:
        raise ValueError(f"expected 8 CEF fields, got {len(parts)}")
    ver, vendor, product, dversion, sig, name, sev = parts[:7]
    if not ver.startswith("CEF:"):
        raise ValueError("bad CEF version token")
    if not sev.isdigit() or not (0 <= int(sev) <= 10):
        raise ValueError(f"severity not 0-10: {sev!r}")
    ext = _parse_ext(parts[7])
    return {"version": ver, "vendor": vendor, "product": product, "deviceVersion": dversion,
            "signatureId": sig, "name": name, "severity": int(sev), "extension": ext}


def _parse_ext(s: str) -> dict:
    import re
    out = {}
    keys = list(re.finditer(r"(?:^|\s)([A-Za-z][A-Za-z0-9]*)=", s))
    for i, m in enumerate(keys):
        k = m.group(1)
        v0 = m.end()
        v1 = keys[i + 1].start() if i + 1 < len(keys) else len(s)
        val = s[v0:v1]
        out[k] = val.replace("\\n", "\n").replace("\\=", "=").replace("\\\\", "\\")
    return out
