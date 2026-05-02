"""
Export Module — PDF & CSV
===========================
Generates professional PDF reports and CSV exports from scan results.
Uses ReportLab for PDF (no browser required).
"""

import csv
import io
from datetime import datetime
from typing import Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.colors import HexColor


# ── Colour Palette ────────────────────────────────────────────────────────────
CLR_BG        = HexColor("#0a0e1a")
CLR_PANEL     = HexColor("#111827")
CLR_BORDER    = HexColor("#1f2937")
CLR_TEXT      = HexColor("#f9fafb")
CLR_TEXT2     = HexColor("#9ca3af")
CLR_BLUE      = HexColor("#3b82f6")
CLR_RED       = HexColor("#ef4444")
CLR_ORANGE    = HexColor("#f97316")
CLR_YELLOW    = HexColor("#eab308")
CLR_GREEN     = HexColor("#22c55e")
CLR_WHITE     = HexColor("#ffffff")
CLR_DARK      = HexColor("#0d1117")
CLR_ACCENT    = HexColor("#1e3a5f")

SEV_COLORS = {
    "CRITICAL": (HexColor("#7f1d1d"), HexColor("#fca5a5")),
    "HIGH":     (HexColor("#7c2d12"), HexColor("#fdba74")),
    "MEDIUM":   (HexColor("#713f12"), HexColor("#fde68a")),
    "LOW":      (HexColor("#14532d"), HexColor("#86efac")),
    "INFO":     (HexColor("#1e3a5f"), HexColor("#93c5fd")),
}

GRADE_COLORS = {
    "A": HexColor("#22c55e"),
    "B": HexColor("#84cc16"),
    "C": HexColor("#eab308"),
    "D": HexColor("#f97316"),
    "F": HexColor("#ef4444"),
}


def _grade(risk: Dict) -> str:
    rating = risk.get("rating", "CRITICAL")
    return {"SECURE": "A", "LOW": "B", "MEDIUM": "C", "HIGH": "D", "CRITICAL": "F"}.get(rating, "F")


def _sev_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(sev, 5)


# ── Styles ─────────────────────────────────────────────────────────────────────

def _build_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["title"] = ParagraphStyle(
        "title", fontName="Helvetica-Bold", fontSize=22, textColor=CLR_WHITE,
        leading=28, spaceAfter=4
    )
    styles["subtitle"] = ParagraphStyle(
        "subtitle", fontName="Helvetica", fontSize=10, textColor=CLR_TEXT2,
        leading=14, spaceAfter=2
    )
    styles["section"] = ParagraphStyle(
        "section", fontName="Helvetica-Bold", fontSize=11, textColor=CLR_BLUE,
        leading=16, spaceBefore=14, spaceAfter=6,
        borderPadding=(0, 0, 4, 0),
    )
    styles["body"] = ParagraphStyle(
        "body", fontName="Helvetica", fontSize=9, textColor=HexColor("#374151"),
        leading=14, spaceAfter=4
    )
    styles["body_white"] = ParagraphStyle(
        "body_white", fontName="Helvetica", fontSize=9, textColor=CLR_WHITE,
        leading=14, spaceAfter=4
    )
    styles["mono"] = ParagraphStyle(
        "mono", fontName="Courier", fontSize=8, textColor=HexColor("#4b5563"),
        leading=12, spaceAfter=2
    )
    styles["label"] = ParagraphStyle(
        "label", fontName="Helvetica-Bold", fontSize=7, textColor=CLR_TEXT2,
        leading=10, spaceBefore=2
    )
    styles["vuln_title"] = ParagraphStyle(
        "vuln_title", fontName="Helvetica-Bold", fontSize=9,
        textColor=HexColor("#111827"), leading=13
    )
    styles["vuln_body"] = ParagraphStyle(
        "vuln_body", fontName="Helvetica", fontSize=8,
        textColor=HexColor("#374151"), leading=12, spaceAfter=3
    )
    styles["fix_step"] = ParagraphStyle(
        "fix_step", fontName="Courier", fontSize=7.5,
        textColor=HexColor("#1d4ed8"), leading=11, leftIndent=8, spaceAfter=1
    )
    styles["footer"] = ParagraphStyle(
        "footer", fontName="Helvetica", fontSize=7, textColor=CLR_TEXT2,
        leading=10, alignment=TA_CENTER
    )
    return styles


# ── Header/Footer callbacks ────────────────────────────────────────────────────

class _PageDecorator:
    def __init__(self, target: str, timestamp: str):
        self.target = target
        self.timestamp = timestamp

    def __call__(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # Header bar
        canvas.setFillColor(CLR_DARK)
        canvas.rect(0, h - 38, w, 38, fill=1, stroke=0)
        canvas.setFillColor(CLR_BLUE)
        canvas.rect(0, h - 38, 4, 38, fill=1, stroke=0)

        canvas.setFont("Helvetica-Bold", 11)
        canvas.setFillColor(CLR_WHITE)
        canvas.drawString(18, h - 24, "VulnScanner")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(CLR_TEXT2)
        canvas.drawString(18, h - 34, "Security Assessment Report")

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(CLR_TEXT2)
        canvas.drawRightString(w - 18, h - 22, self.target)
        canvas.drawRightString(w - 18, h - 33, self.timestamp)

        # Footer bar
        canvas.setFillColor(CLR_DARK)
        canvas.rect(0, 0, w, 28, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(CLR_TEXT2)
        canvas.drawString(18, 10, "For authorised security testing only  |  abdallahshaban0  |  VulnScanner v1.0")
        canvas.drawRightString(w - 18, 10, f"Page {doc.page}")

        canvas.restoreState()


# ── PDF Generator ──────────────────────────────────────────────────────────────

def generate_pdf(scan_data: Dict, output_path: str) -> str:
    """Generate a professional PDF report from scan data."""
    S = _build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        topMargin=1.4 * cm,
        bottomMargin=1.4 * cm,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        title=f"VulnScanner Report — {scan_data.get('target', '')}",
        author="abdallahshaban0 / VulnScanner",
    )

    target    = scan_data.get("target", "Unknown")
    timestamp = scan_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    risk      = scan_data.get("risk_score", {})
    vulns     = sorted(scan_data.get("all_vulnerabilities", []), key=lambda v: _sev_order(v.get("severity", "INFO")))
    ports     = scan_data.get("ports", [])
    dns       = scan_data.get("dns", {})
    http      = scan_data.get("http", {})
    duration  = scan_data.get("duration", "N/A")
    modules   = ", ".join(scan_data.get("modules_run", []))

    grade       = _grade(risk)
    grade_color = GRADE_COLORS.get(grade, CLR_RED)
    score       = risk.get("score", 0)
    rating      = risk.get("rating", "UNKNOWN")
    counts      = risk.get("counts", {})

    story = []
    page_dec = _PageDecorator(target, timestamp)

    # ── Cover block ────────────────────────────────────────────────────────────
    # Dark header table
    header_data = [[
        Paragraph(f"<b>{target}</b>", ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=16, textColor=CLR_WHITE, leading=20)),
        Paragraph(f"<b>{grade}</b>", ParagraphStyle("g", fontName="Helvetica-Bold", fontSize=40, textColor=grade_color, leading=44, alignment=TA_RIGHT)),
    ]]
    header_table = Table(header_data, colWidths=[11 * cm, 5.4 * cm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CLR_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING",   (0, 0), (0, -1), 14),
        ("RIGHTPADDING",  (-1, 0), (-1, -1), 14),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8))

    # Meta row
    meta_items = [
        ("Timestamp", timestamp),
        ("IP Address", scan_data.get("resolved_ip", "N/A")),
        ("Duration",  duration),
        ("Modules",   modules or "N/A"),
    ]
    meta_data  = [[Paragraph(f"<b>{k}</b>", S["label"]), Paragraph(v, S["mono"])] for k, v in meta_items]
    meta_table = Table(meta_data, colWidths=[3 * cm, 13.4 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#f9fafb")),
        ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#e5e7eb")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # ── Risk score bar ─────────────────────────────────────────────────────────
    story.append(Paragraph("RISK ASSESSMENT", S["section"]))

    score_data = [
        [
            Paragraph(f"<b>Score: {score}/100</b>", S["body"]),
            Paragraph(f"<b>Rating: {rating}</b>", S["body"]),
            Paragraph(f"Critical: <b>{counts.get('CRITICAL', 0)}</b>", S["body"]),
            Paragraph(f"High: <b>{counts.get('HIGH', 0)}</b>", S["body"]),
            Paragraph(f"Medium: <b>{counts.get('MEDIUM', 0)}</b>", S["body"]),
            Paragraph(f"Low: <b>{counts.get('LOW', 0)}</b>", S["body"]),
        ]
    ]
    score_table = Table(score_data, colWidths=[3.2*cm]*5 + [2.4*cm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, 0), CLR_ACCENT),
        ("BACKGROUND", (2, 0), (2, 0), HexColor("#7f1d1d")),
        ("BACKGROUND", (3, 0), (3, 0), HexColor("#7c2d12")),
        ("BACKGROUND", (4, 0), (4, 0), HexColor("#713f12")),
        ("BACKGROUND", (5, 0), (5, 0), HexColor("#14532d")),
        ("TEXTCOLOR",  (0, 0), (-1, -1), CLR_WHITE),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 14))

    # ── HTTP Summary ───────────────────────────────────────────────────────────
    if http.get("reachable"):
        story.append(Paragraph("WEB SERVER SUMMARY", S["section"]))
        ssl      = http.get("ssl", {})
        ssl_ok   = not ssl.get("issues")
        ssl_str  = ssl.get("protocol", "N/A") + ("  ✓" if ssl_ok else "  ✗ Issues found")
        srv_info = http.get("server_info", {})
        server   = list(srv_info.values())[0] if srv_info else "Not disclosed"

        http_data = [
            ["HTTP Status",    str(http.get("status_code", "N/A"))],
            ["Final URL",      str(http.get("final_url", "N/A"))[:70]],
            ["SSL/TLS",        ssl_str],
            ["Server Header",  server],
            ["Cookies",        str(len(http.get("cookies", []))) + " detected"],
            ["Sensitive Files", str(len(http.get("sensitive_files", []))) + " exposed"],
        ]
        ht = Table(http_data, colWidths=[4 * cm, 12.4 * cm])
        ht.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), HexColor("#f1f5f9")),
            ("BACKGROUND",    (1, 0), (1, -1), CLR_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#e2e8f0")),
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(ht)
        story.append(Spacer(1, 12))

    # ── Vulnerabilities ────────────────────────────────────────────────────────
    story.append(Paragraph(f"VULNERABILITY FINDINGS ({len(vulns)} total)", S["section"]))

    for vuln in vulns:
        sev   = vuln.get("severity", "INFO")
        bg, fg = SEV_COLORS.get(sev, (CLR_ACCENT, CLR_WHITE))
        vtype = vuln.get("type", "Finding").replace("_", " ")
        detail = vuln.get("detail", "") or vuln.get("description", "")
        summary = vuln.get("summary", "")
        impact  = vuln.get("impact", "")
        steps   = vuln.get("fix_steps", [])
        owasp   = vuln.get("owasp", "")
        port_str = f"  (Port {vuln['port']})" if vuln.get("port") else ""

        block = []

        # Title row
        title_data = [[
            Paragraph(sev, ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=7, textColor=fg, leading=10)),
            Paragraph(f"<b>{vtype}{port_str}</b>", ParagraphStyle("vt", fontName="Helvetica-Bold", fontSize=9, textColor=HexColor("#111827"), leading=12)),
        ]]
        title_t = Table(title_data, colWidths=[1.6 * cm, 14.8 * cm])
        title_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), bg),
            ("BACKGROUND", (1, 0), (1, 0), HexColor("#f8fafc")),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (0, 0), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, HexColor("#e2e8f0")),
        ]))
        block.append(title_t)

        # Body
        body_rows = []
        if detail:
            body_rows.append(["Detail", detail[:200]])
        if summary:
            body_rows.append(["Summary", summary])
        if impact:
            body_rows.append(["Impact", impact])
        if owasp:
            body_rows.append(["OWASP", owasp])

        if body_rows:
            body_t = Table(
                [[Paragraph(k, ParagraphStyle("bk", fontName="Helvetica-Bold", fontSize=7.5, textColor=HexColor("#6b7280"))),
                  Paragraph(v, S["vuln_body"])] for k, v in body_rows],
                colWidths=[1.6 * cm, 14.8 * cm]
            )
            body_t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), CLR_WHITE),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, HexColor("#f1f5f9")),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            block.append(body_t)

        # Fix steps
        if steps:
            steps_content = []
            steps_content.append(Paragraph(
                "Remediation Steps:",
                ParagraphStyle("rh", fontName="Helvetica-Bold", fontSize=7.5, textColor=HexColor("#1d4ed8"), leading=12)
            ))
            for i, step in enumerate(steps[:6], 1):
                steps_content.append(Paragraph(
                    f"{i}. {step}",
                    ParagraphStyle("rs", fontName="Helvetica", fontSize=7.5, textColor=HexColor("#374151"), leading=11, leftIndent=4, spaceAfter=1)
                ))

            steps_data = [[steps_content]]
            steps_t = Table(steps_data, colWidths=[16.4 * cm])
            steps_t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), HexColor("#eff6ff")),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, HexColor("#bfdbfe")),
            ]))
            block.append(steps_t)

        block.append(Spacer(1, 8))
        story.append(KeepTogether(block))

    # ── Open Ports ─────────────────────────────────────────────────────────────
    if ports:
        story.append(PageBreak())
        story.append(Paragraph(f"OPEN PORTS ({len(ports)} found)", S["section"]))
        port_hdr = [["Port", "Service", "Risk", "Banner"]]
        port_rows = [[
            str(p.get("port", "")),
            p.get("service", "unknown"),
            p.get("risk", "LOW"),
            (p.get("banner") or "—")[:55],
        ] for p in ports]

        pt = Table(port_hdr + port_rows, colWidths=[2*cm, 3.5*cm, 2.5*cm, 8.4*cm])
        pt.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), CLR_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), CLR_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [CLR_WHITE, HexColor("#f8fafc")]),
            ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#e2e8f0")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(pt)

    # ── DNS ────────────────────────────────────────────────────────────────────
    records  = dns.get("dns_records", {})
    subdomains = dns.get("subdomains", [])
    if records or subdomains:
        story.append(Spacer(1, 14))
        story.append(Paragraph("DNS RECONNAISSANCE", S["section"]))
        if records:
            dns_rows = [["Type", "Value"]]
            for rtype, vals in records.items():
                for v in vals:
                    dns_rows.append([rtype, str(v)[:80]])
            dt = Table(dns_rows, colWidths=[2.5*cm, 13.9*cm])
            dt.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), CLR_ACCENT),
                ("TEXTCOLOR",     (0, 0), (-1, 0), CLR_WHITE),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [CLR_WHITE, HexColor("#f8fafc")]),
                ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#e2e8f0")),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ]))
            story.append(dt)

        if subdomains:
            story.append(Spacer(1, 8))
            story.append(Paragraph(f"Subdomains Discovered ({len(subdomains)})", S["body"]))
            sub_rows = [["Subdomain", "IP Addresses"]]
            for s in subdomains[:30]:
                sub_rows.append([s.get("subdomain", ""), ", ".join(s.get("ips", []))])
            st = Table(sub_rows, colWidths=[8.2*cm, 8.2*cm])
            st.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), CLR_ACCENT),
                ("TEXTCOLOR",     (0, 0), (-1, 0), CLR_WHITE),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [CLR_WHITE, HexColor("#f8fafc")]),
                ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#e2e8f0")),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ]))
            story.append(st)

    # ── Disclaimer ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e2e8f0")))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "This report was generated by VulnScanner for authorised security assessment purposes only. "
        "Scanning systems without explicit written permission is illegal under the Computer Fraud and Abuse Act (CFAA), "
        "Computer Misuse Act (CMA), and equivalent laws. VulnScanner v1.0 — abdallahshaban0 — 2026",
        S["footer"]
    ))

    doc.build(story, onFirstPage=page_dec, onLaterPages=page_dec)
    return output_path


# ── CSV Generator ──────────────────────────────────────────────────────────────

def generate_csv(scan_data: Dict) -> str:
    """Generate CSV content from scan data. Returns CSV string."""
    output = io.StringIO()

    # Section 1: Scan metadata
    meta_writer = csv.writer(output)
    meta_writer.writerow(["=== SCAN METADATA ==="])
    meta_writer.writerow(["Target",    scan_data.get("target", "")])
    meta_writer.writerow(["IP",        scan_data.get("resolved_ip", "")])
    meta_writer.writerow(["Timestamp", scan_data.get("timestamp", "")])
    meta_writer.writerow(["Duration",  scan_data.get("duration", "")])
    meta_writer.writerow(["Modules",   ", ".join(scan_data.get("modules_run", []))])
    risk = scan_data.get("risk_score", {})
    meta_writer.writerow(["Risk Score", str(risk.get("score", 0))])
    meta_writer.writerow(["Risk Rating", risk.get("rating", "")])
    counts = risk.get("counts", {})
    meta_writer.writerow(["Critical Findings", str(counts.get("CRITICAL", 0))])
    meta_writer.writerow(["High Findings",     str(counts.get("HIGH", 0))])
    meta_writer.writerow(["Medium Findings",   str(counts.get("MEDIUM", 0))])
    meta_writer.writerow(["Low Findings",      str(counts.get("LOW", 0))])
    meta_writer.writerow([])

    # Section 2: Vulnerabilities
    meta_writer.writerow(["=== VULNERABILITIES ==="])
    vuln_writer = csv.DictWriter(output, fieldnames=[
        "Severity", "Type", "Port", "Detail", "Summary",
        "Impact", "Fix Step 1", "Fix Step 2", "Fix Step 3",
        "OWASP", "CWE", "References"
    ])
    vuln_writer.writeheader()

    vulns = sorted(
        scan_data.get("all_vulnerabilities", []),
        key=lambda v: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(v.get("severity","INFO"),4)
    )
    for v in vulns:
        steps = v.get("fix_steps", [])
        vuln_writer.writerow({
            "Severity":    v.get("severity", ""),
            "Type":        v.get("type", "").replace("_", " "),
            "Port":        str(v.get("port", "")),
            "Detail":      v.get("detail", ""),
            "Summary":     v.get("summary", ""),
            "Impact":      v.get("impact", ""),
            "Fix Step 1":  steps[0] if len(steps) > 0 else "",
            "Fix Step 2":  steps[1] if len(steps) > 1 else "",
            "Fix Step 3":  steps[2] if len(steps) > 2 else "",
            "OWASP":       v.get("owasp", ""),
            "CWE":         v.get("cwe", ""),
            "References":  "; ".join(v.get("references", [])),
        })
    output.write("\n")

    # Section 3: Open Ports
    meta_writer.writerow(["=== OPEN PORTS ==="])
    port_writer = csv.DictWriter(output, fieldnames=["Port", "Service", "Risk", "Banner"])
    port_writer.writeheader()
    for p in scan_data.get("ports", []):
        port_writer.writerow({
            "Port":    str(p.get("port", "")),
            "Service": p.get("service", ""),
            "Risk":    p.get("risk", ""),
            "Banner":  (p.get("banner") or "")[:100],
        })
    output.write("\n")

    # Section 4: DNS Records
    dns = scan_data.get("dns", {})
    records = dns.get("dns_records", {})
    if records:
        meta_writer.writerow(["=== DNS RECORDS ==="])
        dns_writer = csv.DictWriter(output, fieldnames=["Type", "Value"])
        dns_writer.writeheader()
        for rtype, vals in records.items():
            for v in vals:
                dns_writer.writerow({"Type": rtype, "Value": str(v)})
        output.write("\n")

    # Section 5: Subdomains
    subdomains = dns.get("subdomains", [])
    if subdomains:
        meta_writer.writerow(["=== SUBDOMAINS ==="])
        sub_writer = csv.DictWriter(output, fieldnames=["Subdomain", "IP Addresses"])
        sub_writer.writeheader()
        for s in subdomains:
            sub_writer.writerow({
                "Subdomain":   s.get("subdomain", ""),
                "IP Addresses": ", ".join(s.get("ips", [])),
            })

    return output.getvalue()
