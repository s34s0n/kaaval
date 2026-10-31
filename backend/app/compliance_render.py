# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Branded DOCX + PDF rendering for compliance reports. Pure-Python (python-docx,
reportlab) — offline-safe. Renders LOCAL deterministic report data (de-pseudonymized);
only the executive-summary prose may have touched the cloud (via the egress boundary)."""

from __future__ import annotations

import io
import time

# Kaaval brand
TEAL = (0x14, 0xB8, 0xA6)
INK = (0x0F, 0x1C, 0x2E)
STATUS_RGB = {"MET": (0x15, 0x80, 0x3D), "GAP": (0xB4, 0x23, 0x18), "NOT_ASSESSED": (0x6B, 0x72, 0x80)}
STATUS_LABEL = {"MET": "MET", "GAP": "GAP", "NOT_ASSESSED": "NOT ASSESSED"}
DISCLAIMER = (
    "Control statuses in this report are computed deterministically from recorded evidence — network "
    "detections, the immutable approval and egress audit logs, and the passive asset inventory. The "
    "executive summary prose may be AI-assisted but does not determine any control status. 'Not assessed' "
    "marks controls that are not observable from network/SOC telemetry and require separate review; it is "
    "not a pass."
)


def _ts(ts):
    if not ts:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(float(ts)))
    except (ValueError, OverflowError, OSError):
        return ""


def _gen_str(report):
    g = report.get("generated")
    return _ts(g) if g else time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())


def _evidence_lines(control):
    out = []
    for e in control.get("evidence", []):
        line = f"• [{e['type']}] {e['ref']}: {e['detail']}"
        if e.get("ts"):
            line += f"  ({_ts(e['ts'])})"
        out.append(line)
    return out or ["—"]


# ----------------------------------------------------------------------------- DOCX

def to_docx(report: dict, narrative_text: str) -> bytes:
    from docx import Document
    from docx.shared import Pt, RGBColor

    doc = Document()
    fw = report["framework"]

    head = doc.add_paragraph()
    r = head.add_run("KAAVAL")
    r.bold = True; r.font.size = Pt(22); r.font.color.rgb = RGBColor(*TEAL)
    sub = head.add_run("   IT/OT Security Operations  ·  Traboda")
    sub.font.size = Pt(10); sub.font.color.rgb = RGBColor(*INK)

    doc.add_heading("Compliance Assessment Report", level=0)
    p = doc.add_paragraph()
    p.add_run(f"{fw.get('name')} — {fw.get('full_name', '')}").bold = True
    meta = doc.add_paragraph()
    meta.add_run(f"Framework version: {fw.get('version')}    ·    Authority: {fw.get('authority')}\n")
    meta.add_run(f"Site / deployment: {report['site']}\n")
    meta.add_run(f"Generated: {_gen_str(report)}")

    s = report["summary"]
    doc.add_heading("Posture", level=1)
    pp = doc.add_paragraph()
    for key in ("MET", "GAP", "NOT_ASSESSED"):
        run = pp.add_run(f"{s.get(key, 0)} {STATUS_LABEL[key]}    ")
        run.bold = True; run.font.color.rgb = RGBColor(*STATUS_RGB[key])
    pp.add_run(f"   ({s.get('total', 0)} controls assessed)")

    doc.add_heading("Executive summary", level=1)
    doc.add_paragraph(narrative_text)

    doc.add_heading("Control assessment (evidence-traced)", level=1)
    table = doc.add_table(rows=1, cols=4)
    try:
        table.style = "Light Grid Accent 1"
    except KeyError:
        pass
    hdr = table.rows[0].cells
    for i, t in enumerate(("Control", "Status", "Basis", "Evidence")):
        run = hdr[i].paragraphs[0].add_run(t); run.bold = True
    for c in report["controls"]:
        row = table.add_row().cells
        cp = row[0].paragraphs[0]
        cr = cp.add_run(c["id"]); cr.bold = True
        cp.add_run(f"\n{c['title']}\n"); fam = cp.add_run(c.get("family", "")); fam.font.size = Pt(8)
        sr = row[1].paragraphs[0].add_run(STATUS_LABEL.get(c["status"], c["status"]))
        sr.bold = True; sr.font.color.rgb = RGBColor(*STATUS_RGB.get(c["status"], INK))
        row[2].text = c["rationale"]
        ev_para = row[3].paragraphs[0]
        for j, ln in enumerate(_evidence_lines(c)):
            run = (ev_para if j == 0 else row[3].add_paragraph()).add_run(ln)
            run.font.size = Pt(8)

    doc.add_paragraph()
    d = doc.add_paragraph().add_run(DISCLAIMER)
    d.italic = True; d.font.size = Pt(8); d.font.color.rgb = RGBColor(*STATUS_RGB["NOT_ASSESSED"])

    buf = io.BytesIO(); doc.save(buf); return buf.getvalue()


# ------------------------------------------------------------------------------ PDF

def to_pdf(report: dict, narrative_text: str) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    teal = colors.Color(*[c / 255 for c in TEAL])
    ink = colors.Color(*[c / 255 for c in INK])
    fw = report["framework"]
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=8.5, leading=11)
    cell = ParagraphStyle("cell", parent=body, fontSize=7.5, leading=9.5)
    small = ParagraphStyle("small", parent=body, fontSize=7, leading=9, textColor=colors.grey)

    def status_para(st):
        c = colors.Color(*[v / 255 for v in STATUS_RGB.get(st, INK)])
        return Paragraph(f'<b>{STATUS_LABEL.get(st, st)}</b>', ParagraphStyle("st", parent=cell, textColor=c))

    story = []
    story.append(Paragraph('<font color="#14B8A6" size="22"><b>KAAVAL</b></font>'
                           '<font size="10" color="#0F1C2E">&nbsp;&nbsp;IT/OT Security Operations · Traboda</font>',
                           ParagraphStyle("brand", parent=body, fontSize=22, leading=24)))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Compliance Assessment Report", ParagraphStyle("title", parent=ss["Title"], textColor=ink, fontSize=20)))
    story.append(Paragraph(f"<b>{fw.get('name')}</b> — {fw.get('full_name', '')}", body))
    story.append(Paragraph(f"Framework version: {fw.get('version')} · Authority: {fw.get('authority')}", small))
    story.append(Paragraph(f"Site / deployment: {report['site']} · Generated: {_gen_str(report)}", small))
    story.append(Spacer(1, 4 * mm))

    s = report["summary"]
    posture = "  ".join(
        f'<font color="rgb({STATUS_RGB[k][0]},{STATUS_RGB[k][1]},{STATUS_RGB[k][2]})"><b>{s.get(k, 0)} {STATUS_LABEL[k]}</b></font>'
        for k in ("MET", "GAP", "NOT_ASSESSED"))
    story.append(Paragraph(f"Posture: {posture} &nbsp; ({s.get('total', 0)} controls)", body))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("<b>Executive summary</b>", body))
    story.append(Paragraph(narrative_text, body))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("<b>Control assessment (evidence-traced)</b>", body))
    story.append(Spacer(1, 2 * mm))

    data = [[Paragraph("<b>Control</b>", cell), Paragraph("<b>Status</b>", cell),
             Paragraph("<b>Basis</b>", cell), Paragraph("<b>Evidence</b>", cell)]]
    for c in report["controls"]:
        ctrl = Paragraph(f"<b>{c['id']}</b><br/>{c['title']}<br/><font size=6 color='grey'>{c.get('family', '')}</font>", cell)
        ev = Paragraph("<br/>".join(_evidence_lines(c)).replace("•", "&bull;"), cell)
        data.append([ctrl, status_para(c["status"]), Paragraph(c["rationale"], cell), ev])

    tbl = Table(data, colWidths=[33 * mm, 20 * mm, 52 * mm, 67 * mm], repeatRows=1)
    style = [("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.8, 0.83, 0.86)),
             ("BACKGROUND", (0, 0), (-1, 0), teal),
             ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.96, 0.98, 0.98)]),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    tbl.setStyle(TableStyle(style))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(DISCLAIMER, small))

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=12 * mm, rightMargin=12 * mm,
                      topMargin=12 * mm, bottomMargin=12 * mm,
                      title=f"Kaaval Compliance — {fw.get('name')}").build(story)
    return buf.getvalue()
