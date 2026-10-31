# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Per-incident report (F7) — LLM-drafted prose over store-derived facts, branded
DOCX/PDF via the F2 pipeline, human-edited and signed off before it is final.

Discipline (same as F2): the FACTS/timeline/evidence come from the store and are
authoritative; the LLM only drafts plain-language prose for a non-technical reader.
In cloud mode the prose generation routes through the egress boundary (llm.ollama_json
-> egress.cloud_json, pseudonymized out / de-pseudonymized back) like every other LLM
call. The report stays a DRAFT until a person signs off (casework.signoff_report).
"""

from __future__ import annotations

import io
import json
import time

from . import compliance_render as brand, llm, store

_NARR_SCHEMA = {"type": "object", "properties": {
    "what_happened": {"type": "string"}, "impact": {"type": "string"}, "response": {"type": "string"}},
    "required": ["what_happened"]}


# --- facts (authoritative, from the store) ----------------------------------

def build_facts(case_detail: dict) -> dict:
    inc = case_detail.get("incident") or {}
    iid = case_detail.get("id") or inc.get("id")
    events = case_detail.get("events") or []
    actions = case_detail.get("actions") or []
    agents = case_detail.get("agents") or {}
    metrics = case_detail.get("metrics") or {}
    conn = store.connect(); store.init(conn)
    approvals = store.get_approvals(conn, iid)
    conn.close()

    timeline = []
    if metrics.get("time_to_detect_s") is not None or inc.get("first_seen"):
        timeline.append({"ts": inc.get("first_seen"), "label": "Detected",
                         "detail": f"{len(events)} correlated events across {', '.join(inc.get('domains') or [])}"})
    if agents.get("triage"):
        timeline.append({"ts": None, "label": "Triaged", "detail": (agents['triage'] or {}).get('summary', '')[:200]})
    for a in actions:
        if a.get("status") in ("executed", "approved", "applied"):
            timeline.append({"ts": None, "label": f"Action {a['status']}",
                             "detail": f"{a.get('title') or a.get('name')} ({a.get('domain')})"})
    for ap in approvals:
        timeline.append({"ts": ap.get("ts"), "label": "Human approval",
                         "detail": f"{ap.get('action')} approved by {ap.get('approver')} "
                                   f"({'ok' if ap.get('result_ok') else 'failed'})"})
    if metrics.get("resolved"):
        timeline.append({"ts": None, "label": "Resolved", "detail": "detection quiet on fresh telemetry"})

    return {
        "incident_id": iid,
        "summary": inc.get("summary"),
        "severity": inc.get("severity"),
        "cross_domain": bool(inc.get("cross_domain")),
        "domains": inc.get("domains") or [],
        "techniques": [t.get("id") if isinstance(t, dict) else t for t in (inc.get("techniques") or [])],
        "metrics": {k: metrics.get(k) for k in ("time_to_detect_s", "time_to_contain_s", "it_events", "ot_events")},
        "timeline": timeline,
        "actions": [{"name": a.get("name"), "title": a.get("title"), "domain": a.get("domain"),
                     "status": a.get("status"), "gated": bool(a.get("requires_human_approval"))} for a in actions],
        "approvals": [{"action": ap.get("action"), "approver": ap.get("approver"),
                       "ts": ap.get("ts"), "ok": ap.get("result_ok")} for ap in approvals],
        "evidence": [{"rule": e.get("rule"), "domain": e.get("domain"), "summary": (e.get("summary") or "")[:160],
                      "techniques": [t.get("id") if isinstance(t, dict) else t for t in (e.get("techniques") or [])]}
                     for e in events[:12]],
    }


# --- narrative (LLM prose; egress-routed in cloud; never sets facts) --------

def _fallback(facts: dict) -> dict:
    dom = " and ".join(facts.get("domains") or []) or "the monitored network"
    return {
        "what_happened": f"A {facts.get('severity') or ''} security incident was detected on {dom}. "
                         + (facts.get("summary") or ""),
        "impact": ("This incident crossed the IT/OT boundary and reached the control network."
                   if facts.get("cross_domain") else "Activity was observed within a single zone."),
        "response": f"{len([a for a in facts.get('actions', []) if a['status'] in ('executed', 'approved', 'applied')])} "
                    f"response action(s) were taken; {len(facts.get('approvals', []))} required human approval.",
        "source": "deterministic-fallback",
    }


def draft_narrative(facts: dict) -> dict:
    system = (
        "You draft a plain-language INCIDENT REPORT for a NON-TECHNICAL government reader "
        "(not a security expert). Use ONLY the facts provided — do not invent events, asset "
        "names, numbers, or outcomes. Avoid jargon; explain acronyms. Three short sections: "
        "what_happened (what occurred, in order), impact (why it matters, plainly), response "
        "(what was done and by whom). Return JSON {what_happened, impact, response}."
    )
    try:
        obj, meta = llm.ollama_json(system, json.dumps(facts), _NARR_SCHEMA, num_predict=700,
                                    incident_id=facts.get("incident_id"), principal="case-report",
                                    purpose="case-report")
    except Exception:  # noqa: BLE001
        obj, meta = None, {}
    if obj and isinstance(obj.get("what_happened"), str) and obj["what_happened"].strip():
        return {"what_happened": obj.get("what_happened", ""), "impact": obj.get("impact", ""),
                "response": obj.get("response", ""), "source": f"llm:{meta.get('provider', '?')}"}
    return _fallback(facts)


def to_markdown(facts: dict, narrative: dict) -> str:
    L = [f"# Incident Report — {facts.get('incident_id')}", ""]
    L += [f"**Severity:** {facts.get('severity') or '—'}  ·  **Zones:** {', '.join(facts.get('domains') or []) or '—'}"
          f"  ·  **ATT&CK:** {', '.join(facts.get('techniques') or []) or '—'}", ""]
    L += ["## What happened", narrative.get("what_happened", ""), ""]
    L += ["## Impact", narrative.get("impact", ""), ""]
    L += ["## Response", narrative.get("response", ""), ""]
    L += ["## Timeline"]
    for t in facts.get("timeline", []):
        L.append(f"- **{t['label']}** — {t['detail']}")
    L += ["", "## Response actions & approvals"]
    for a in facts.get("actions", []):
        L.append(f"- {a.get('title') or a.get('name')} ({a.get('domain')}) — {a.get('status')}"
                 + (" · gated (human-approved)" if a.get("gated") else ""))
    L += ["", "_Facts, timeline and evidence are derived from the incident store. The narrative is AI-assisted "
          "and edited by an analyst; it is a draft until signed off._"]
    return "\n".join(L)


# --- branded render (reuses the F2 brand) -----------------------------------

def _md_paragraphs(md: str):
    for raw in (md or "").split("\n"):
        line = raw.rstrip()
        if line.startswith("# "):
            yield ("h0", line[2:])
        elif line.startswith("## "):
            yield ("h1", line[3:])
        elif line.startswith("- "):
            yield ("li", line[2:])
        elif line.strip():
            yield ("p", line)


def to_docx(markdown: str, meta: dict) -> bytes:
    from docx import Document
    from docx.shared import Pt, RGBColor

    doc = Document()
    head = doc.add_paragraph()
    r = head.add_run("KAAVAL"); r.bold = True; r.font.size = Pt(22); r.font.color.rgb = RGBColor(*brand.TEAL)
    s = head.add_run("   IT/OT Security Operations  ·  Traboda"); s.font.size = Pt(10); s.font.color.rgb = RGBColor(*brand.INK)
    status = (meta or {}).get("report_status")
    tag = doc.add_paragraph().add_run("FINAL — signed off by " + str(meta.get("report_by"))
                                      if status == "final" else "DRAFT — not yet signed off")
    tag.bold = True; tag.font.size = Pt(9)
    tag.font.color.rgb = RGBColor(0x15, 0x80, 0x3D) if status == "final" else RGBColor(0xB4, 0x23, 0x18)
    for kind, text in _md_paragraphs(markdown):
        if kind == "h0":
            doc.add_heading(text, level=0)
        elif kind == "h1":
            doc.add_heading(text, level=1)
        elif kind == "li":
            doc.add_paragraph(text, style="List Bullet")
        else:
            doc.add_paragraph(text)
    buf = io.BytesIO(); doc.save(buf); return buf.getvalue()


def to_pdf(markdown: str, meta: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9.5, leading=13)
    story = [Paragraph('<font color="#14B8A6" size="22"><b>KAAVAL</b></font>'
                       '<font size="10" color="#0F1C2E">&nbsp;&nbsp;IT/OT Security Operations · Traboda</font>',
                       ParagraphStyle("brand", parent=body, fontSize=22, leading=24))]
    status = (meta or {}).get("report_status")
    tag = ("FINAL — signed off by %s" % meta.get("report_by")) if status == "final" else "DRAFT — not yet signed off"
    story.append(Paragraph(f'<b>{tag}</b>', ParagraphStyle("tag", parent=body,
                 textColor=colors.HexColor("#15803D" if status == "final" else "#B42318"))))
    story.append(Spacer(1, 4 * mm))
    bullets = []
    def flush_bullets():
        if bullets:
            story.append(ListFlowable([ListItem(Paragraph(b, body)) for b in bullets], bulletType="bullet"))
            bullets.clear()
    for kind, text in _md_paragraphs(markdown):
        if kind == "li":
            bullets.append(text); continue
        flush_bullets()
        if kind == "h0":
            story.append(Paragraph(f"<b>{text}</b>", ParagraphStyle("h0", parent=body, fontSize=15, leading=19, spaceBefore=6)))
        elif kind == "h1":
            story.append(Paragraph(f"<b>{text}</b>", ParagraphStyle("h1", parent=body, fontSize=12, leading=16, spaceBefore=6, textColor=colors.HexColor("#0F1C2E"))))
        else:
            story.append(Paragraph(text, body))
    flush_bullets()
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm,
                      topMargin=14 * mm, bottomMargin=14 * mm,
                      title=f"Kaaval Incident Report — {(meta or {}).get('incident_id', '')}").build(story)
    return buf.getvalue()
