import os, re
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable, PageBreak,
                                     KeepTogether)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

# ── Colours ───────────────────────────────────────────────────────────────────
WHITE  = colors.white
DARK   = colors.HexColor("#1A1A1A")
GRAY1  = colors.HexColor("#F8F9FA")
GRAY2  = colors.HexColor("#E9ECEF")
GRAY3  = colors.HexColor("#DEE2E6")
GRAY4  = colors.HexColor("#6C757D")
COVER  = colors.HexColor("#0D1117")
RED    = colors.HexColor("#DC3545")
ORANGE = colors.HexColor("#E65C00")
AMBER  = colors.HexColor("#D4980A")
GREEN  = colors.HexColor("#1A7A3C")
BLUE   = colors.HexColor("#0D5C9E")
PURPLE = colors.HexColor("#6A3DBB")

# ── Uniform spacing constants ─────────────────────────────────────────────────
STEP_PAD_V  = 9   # vertical padding in ALL table rows (detail, HOW TO FIX, AI)
STEP_PAD_H  = 8   # horizontal padding in ALL table rows
SECTION_GAP = 10  # gap between detail table and HOW TO FIX
SECTION_GAP2= 10  # gap between HOW TO FIX and AI ANALYSIS
CARD_GAP    = 16  # gap between vulnerability cards

SEV_COL = {"Critical": RED, "High": ORANGE, "Medium": AMBER, "Low": GREEN}
SEV_BG  = {
    "Critical": colors.HexColor("#FFF0F0"),
    "High":     colors.HexColor("#FFF5EE"),
    "Medium":   colors.HexColor("#FFFBEB"),
    "Low":      colors.HexColor("#F0FFF5"),
}
SEV_BORDER = {
    "Critical": colors.HexColor("#F5C6CB"),
    "High":     colors.HexColor("#FAD6BD"),
    "Medium":   colors.HexColor("#FFEEBA"),
    "Low":      colors.HexColor("#C3E6CB"),
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def _safe(text, maxlen=200):
    if not text: return ""
    t = str(text)
    if len(t) > maxlen: t = t[:maxlen] + "..."
    return (t.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))

def _clean(text):
    if not text: return ""
    return "".join(c for c in str(text) if c.isprintable() or c in "\n\t")

def _url_short(url, maxlen=75):
    if not url: return ""
    u = str(url)
    if len(u) > maxlen: u = u[:maxlen] + "..."
    return _safe(u)

def _hr(color=GRAY3, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness,
                      color=color, spaceAfter=0, spaceBefore=0)

def _gap(pts=8):
    return Spacer(1, pts)

def _styles():
    return {
        "title":   ParagraphStyle("TI", fontSize=26, textColor=WHITE,
                                  fontName="Helvetica-Bold", leading=30),
        "subtitle":ParagraphStyle("SU", fontSize=10,
                                  textColor=colors.HexColor("#AAAAAA"),
                                  fontName="Helvetica", leading=14),
        "h1":      ParagraphStyle("H1", fontSize=14, textColor=DARK,
                                  fontName="Helvetica-Bold",
                                  spaceBefore=14, spaceAfter=6),
        "h2":      ParagraphStyle("H2", fontSize=11, textColor=BLUE,
                                  fontName="Helvetica-Bold",
                                  spaceBefore=10, spaceAfter=4),
        "body":    ParagraphStyle("BO", fontSize=8.5, textColor=DARK,
                                  fontName="Helvetica", leading=13),
        "body_sm": ParagraphStyle("BS", fontSize=8, textColor=GRAY4,
                                  fontName="Helvetica", leading=12),
        "mono":    ParagraphStyle("MO", fontSize=7.5, textColor=BLUE,
                                  fontName="Courier", leading=11, wordWrap="CJK"),
        "label":   ParagraphStyle("LA", fontSize=7, textColor=GRAY4,
                                  fontName="Helvetica-Bold",
                                  leading=10, spaceAfter=1),
        "white":   ParagraphStyle("WH", fontSize=9, textColor=WHITE,
                                  fontName="Helvetica", leading=13),
    }

def _sev_badge(sev):
    col = SEV_COL.get(sev, GRAY4)
    t = Table([[Paragraph(sev, ParagraphStyle("SB", fontSize=7,
                fontName="Helvetica-Bold", textColor=WHITE,
                alignment=TA_CENTER))]], colWidths=[18*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), col),
        ("PADDING",    (0,0),(-1,-1), 3),
    ]))
    return t

# ── Main generator ────────────────────────────────────────────────────────────
def generate_pdf(scan, vulns, recon, crawl_stats, ai_summary, output_path):
    if not REPORTLAB_OK:
        return False, "reportlab not installed. Run: pip install reportlab"

    out_dir = os.path.dirname(output_path)
    if out_dir: os.makedirs(out_dir, exist_ok=True)

    W   = A4[0] - 36*mm
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=18*mm, bottomMargin=18*mm)
    ST = _styles()
    E  = []

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in vulns:
        s = v.get("severity", "Low")
        if s in counts: counts[s] += 1

    # ══════════════════════════════ COVER ════════════════════════════════════
    cover = Table([[
        Paragraph("VULNX", ST["title"]),
        Paragraph(f"#{scan.get('id','')}", ST["subtitle"]),
    ]], colWidths=[W*0.8, W*0.2])
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), COVER),
        ("PADDING",    (0,0),(-1,-1), 18),
        ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
        ("ALIGN",      (1,0),(1,0), "RIGHT"),
    ]))
    E.append(cover)

    strip = Table([[Paragraph("Web Application Security Assessment Report", ST["white"])]],
                  colWidths=[W])
    strip.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), RED),
        ("PADDING",    (0,0),(-1,-1), 8),
    ]))
    E.append(strip)
    E.append(_gap(12))

    # Meta table
    meta = Table([
        [Paragraph("Target",  ST["label"]), Paragraph(_url_short(scan.get("target",""), 90), ST["mono"]),
         Paragraph("Scan ID", ST["label"]), Paragraph(f"#{scan.get('id','')}", ST["body"])],
        [Paragraph("Date",    ST["label"]), Paragraph(_safe(scan.get("created_at","")), ST["body"]),
         Paragraph("Status",  ST["label"]), Paragraph(_safe(scan.get("status","")).title(), ST["body"])],
        [Paragraph("Total",   ST["label"]), Paragraph(str(len(vulns)) + " vulnerabilities", ST["body"]),
         Paragraph("Risk",    ST["label"]), Paragraph(
             "CRITICAL" if counts["Critical"] > 0 else
             "HIGH"     if counts["High"]     > 0 else "MEDIUM", ST["body"])],
    ], colWidths=[20*mm, W/2-20*mm, 20*mm, W/2-20*mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(0,-1), GRAY2),
        ("BACKGROUND", (2,0),(2,-1), GRAY2),
        ("BACKGROUND", (1,0),(-1,-1), WHITE),
        ("GRID",       (0,0),(-1,-1), 0.4, GRAY3),
        ("PADDING",    (0,0),(-1,-1), 7),
        ("VALIGN",     (0,0),(-1,-1), "TOP"),
        ("TEXTCOLOR",  (0,0),(-1,-1), DARK),
    ]))
    E.append(meta)
    E.append(_gap(12))

    # Severity counts box — explicit row heights so large digits don't clip
    sev_label_style = ParagraphStyle("SL", fontSize=7, fontName="Helvetica-Bold",
                                     textColor=WHITE, alignment=TA_CENTER)
    sev_num_styles  = [
        ParagraphStyle("SN", fontSize=26, fontName="Helvetica-Bold",
                        textColor=c, alignment=TA_CENTER)
        for c in [RED, ORANGE, AMBER, GREEN]
    ]
    sev_data = [
        [Paragraph(lbl, sev_label_style) for lbl in ["CRITICAL","HIGH","MEDIUM","LOW"]],
        [Paragraph(str(counts[k]), sev_num_styles[i])
         for i, k in enumerate(["Critical","High","Medium","Low"])],
    ]
    sev_t = Table(sev_data, colWidths=[W/4]*4, rowHeights=[12*mm, 18*mm])
    sev_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(0,0), colors.HexColor("#B71C1C")),
        ("BACKGROUND",    (1,0),(1,0), colors.HexColor("#BF360C")),
        ("BACKGROUND",    (2,0),(2,0), colors.HexColor("#F57F17")),
        ("BACKGROUND",    (3,0),(3,0), colors.HexColor("#1B5E20")),
        ("BACKGROUND",    (0,1),(-1,1), WHITE),
        ("GRID",          (0,0),(-1,-1), 0.5, GRAY3),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
        ("TOPPADDING",    (0,0),(-1,0), 3),
        ("BOTTOMPADDING", (0,0),(-1,0), 3),
        ("TOPPADDING",    (0,1),(-1,1), 2),
        ("BOTTOMPADDING", (0,1),(-1,1), 2),
    ]))
    E.append(sev_t)
    E.append(_gap(18))

    # ══════════════════════════ EXECUTIVE SUMMARY ════════════════════════════
    if ai_summary:
        E.append(Paragraph("Executive Summary", ST["h1"]))
        E.append(_hr(RED, 1.5))
        E.append(_gap(6))
        for para in ai_summary.split("\n\n"):
            para = para.strip()
            if para:
                E.append(Paragraph(_safe(para, 1000), ST["body"]))
                E.append(_gap(5))
        E.append(_gap(10))

    # ══════════════════════════ VULNERABILITY FINDINGS ═══════════════════════
    E.append(Paragraph("Vulnerability Findings", ST["h1"]))
    E.append(_hr(RED, 1.5))
    E.append(_gap(8))

    if not vulns:
        E.append(Paragraph("No vulnerabilities detected.", ST["body_sm"]))
    else:
        for i, v in enumerate(vulns, 1):
            sev    = v.get("severity", "Low")
            col    = SEV_COL.get(sev, GRAY4)
            bg     = SEV_BG.get(sev, WHITE)
            border = SEV_BORDER.get(sev, GRAY3)
            ai     = v.get("ai_analysis") or {}

            # ── 1. Vuln title header bar ──────────────────────────────────────
            hdr = Table([[
                Paragraph(f"{i}.  {_safe(v.get('vuln_type','Unknown'), 60)}", ST["h2"]),
                _sev_badge(sev),
            ]], colWidths=[W-22*mm, 22*mm])
            hdr.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(0,0), bg),
                ("BACKGROUND", (1,0),(1,0), col),
                ("GRID",       (0,0),(-1,-1), 0.4, border),
                ("PADDING",    (0,0),(-1,-1), 8),
                ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
                ("LINEBELOW",  (0,0),(-1,-1), 1.5, col),
            ]))

            # ── 2. Detail table (URL / Parameter / Severity / Description) ────
            detail_rows = [
                [Paragraph("URL",         ST["label"]),
                 Paragraph(_url_short(v.get("url",""), 90), ST["mono"])],
                [Paragraph("Parameter",   ST["label"]),
                 Paragraph(_safe(v.get("parameter",""), 60), ST["body"])],
                [Paragraph("Severity",    ST["label"]),
                 Paragraph(sev, ParagraphStyle("sv", fontSize=8,
                            fontName="Helvetica-Bold", textColor=col))],
                [Paragraph("Description", ST["label"]),
                 Paragraph(_safe(v.get("description",""), 400), ST["body"])],
            ]
            if v.get("payload") and v.get("payload") != "N/A":
                detail_rows.insert(3,
                    [Paragraph("Payload", ST["label"]),
                     Paragraph(_safe(v.get("payload",""), 100),
                               ParagraphStyle("pl", fontSize=7.5,
                                             fontName="Courier",
                                             textColor=PURPLE, leading=11))])
            detail = Table(detail_rows, colWidths=[22*mm, W-22*mm])
            detail.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(0,-1), GRAY1),
                ("BACKGROUND",    (1,0),(1,-1), WHITE),
                ("GRID",          (0,0),(-1,-1), 0.3, GRAY3),
                ("TOPPADDING",    (0,0),(-1,-1), STEP_PAD_V),
                ("BOTTOMPADDING", (0,0),(-1,-1), STEP_PAD_V),
                ("LEFTPADDING",   (0,0),(-1,-1), STEP_PAD_H),
                ("RIGHTPADDING",  (0,0),(-1,-1), STEP_PAD_H),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ("TEXTCOLOR",     (0,0),(-1,-1), DARK),
                ("LINEAFTER",     (0,0),(0,-1),  1.5, col),
            ]))

            # ── 3. HOW TO FIX ─────────────────────────────────────────────────
            fix_steps = ai.get("fix_steps") or []
            if not fix_steps:
                rec_text = v.get("recommendation", "")
                parts = re.split(r'\d+\.\s+', rec_text)
                fix_steps = [p.strip().rstrip(".").strip() for p in parts if p.strip()]
                if not fix_steps and rec_text:
                    fix_steps = [rec_text]

            how_hdr = Table([[
                Paragraph("HOW TO FIX",
                          ParagraphStyle("hf", fontSize=7, fontName="Helvetica-Bold",
                                        textColor=WHITE))
            ]], colWidths=[W])
            how_hdr.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,-1), GREEN),
                ("PADDING",    (0,0),(-1,-1), 6),
            ]))

            step_rows = []
            for j, step in enumerate(fix_steps[:5], 1):
                step_clean = step.strip().lstrip("0123456789.").strip()
                if step_clean:
                    step_rows.append([
                        Paragraph(str(j),
                                  ParagraphStyle("rn", fontSize=7,
                                                fontName="Helvetica-Bold",
                                                textColor=WHITE,
                                                alignment=TA_CENTER)),
                        Paragraph(_safe(step_clean, 250), ST["body"]),
                    ])

            how_body = None
            if step_rows:
                how_body = Table(step_rows, colWidths=[8*mm, W-8*mm])
                how_body.setStyle(TableStyle([
                    ("BACKGROUND",     (0,0),(0,-1), GREEN),
                    ("ROWBACKGROUNDS", (1,0),(1,-1),
                     [colors.HexColor("#F0FFF5"), colors.HexColor("#E8FFE8")]),
                    ("GRID",           (0,0),(-1,-1), 0.3, colors.HexColor("#C3E6CB")),
                    ("TOPPADDING",     (0,0),(-1,-1), STEP_PAD_V),
                    ("BOTTOMPADDING",  (0,0),(-1,-1), STEP_PAD_V),
                    ("LEFTPADDING",    (0,0),(-1,-1), STEP_PAD_H),
                    ("RIGHTPADDING",   (0,0),(-1,-1), STEP_PAD_H),
                    ("VALIGN",         (0,0),(-1,-1), "MIDDLE"),
                    ("ALIGN",          (0,0),(0,-1), "CENTER"),
                ]))

            # ── 4. AI ANALYSIS ────────────────────────────────────────────────
            ai_hdr  = None
            ai_body = None
            if ai.get("risk_explanation") or ai.get("attack_scenario"):
                ai_hdr = Table([[
                    Paragraph("AI ANALYSIS",
                              ParagraphStyle("ah", fontSize=7, fontName="Helvetica-Bold",
                                            textColor=WHITE))
                ]], colWidths=[W])
                ai_hdr.setStyle(TableStyle([
                    ("BACKGROUND", (0,0),(-1,-1), BLUE),
                    ("PADDING",    (0,0),(-1,-1), 6),
                ]))

                ai_rows = []
                if ai.get("risk_explanation"):
                    ai_rows.append([
                        Paragraph("Risk", ST["label"]),
                        Paragraph(_safe(ai["risk_explanation"], 300),
                                  ParagraphStyle("ar", fontSize=8, textColor=DARK,
                                                fontName="Helvetica", leading=13)),
                    ])
                if ai.get("attack_scenario"):
                    ai_rows.append([
                        Paragraph("Attack", ST["label"]),
                        Paragraph(_safe(ai["attack_scenario"], 250),
                                  ParagraphStyle("aa", fontSize=8,
                                                textColor=colors.HexColor("#8B0000"),
                                                fontName="Helvetica-Oblique", leading=13)),
                    ])
                if ai.get("cwe") or ai.get("cvss_estimate"):
                    meta_txt = []
                    if ai.get("cwe"):           meta_txt.append(f"Reference: {ai['cwe']}")
                    if ai.get("cvss_estimate"): meta_txt.append(f"CVSS: {ai['cvss_estimate']}")
                    ai_rows.append([
                        Paragraph("Meta", ST["label"]),
                        Paragraph("  |  ".join(meta_txt), ST["body_sm"]),
                    ])

                if ai_rows:
                    ai_body = Table(ai_rows, colWidths=[15*mm, W-15*mm])
                    ai_body.setStyle(TableStyle([
                        ("BACKGROUND",    (0,0),(0,-1), colors.HexColor("#EBF5FB")),
                        ("BACKGROUND",    (1,0),(1,-1), colors.HexColor("#F8FBFF")),
                        ("GRID",          (0,0),(-1,-1), 0.3, colors.HexColor("#BDD7EE")),
                        ("TOPPADDING",    (0,0),(-1,-1), STEP_PAD_V),
                        ("BOTTOMPADDING", (0,0),(-1,-1), STEP_PAD_V),
                        ("LEFTPADDING",   (0,0),(-1,-1), STEP_PAD_H),
                        ("RIGHTPADDING",  (0,0),(-1,-1), STEP_PAD_H),
                        ("VALIGN",        (0,0),(-1,-1), "TOP"),
                        ("LINEAFTER",     (0,0),(0,-1), 1.5, BLUE),
                    ]))

            # ── Assemble: hdr → detail → [gap] → HOW TO FIX → [gap] → AI ────
            parts = [hdr, detail]

            parts.append(_gap(SECTION_GAP))
            parts.append(how_hdr)
            if how_body:
                parts.append(how_body)

            if ai_hdr:
                parts.append(_gap(SECTION_GAP2))
                parts.append(ai_hdr)
                if ai_body:
                    parts.append(ai_body)

            try:
                E.append(KeepTogether(parts))
            except Exception:
                E.extend(parts)

            # Gap + thin rule between vulnerability cards
            E.append(_gap(CARD_GAP))
            E.append(_hr(GRAY3, 0.5))
            E.append(_gap(CARD_GAP))

    # ══════════════════════════ RECON RESULTS ════════════════════════════════
    E.append(PageBreak())
    E.append(Paragraph("Reconnaissance Results", ST["h1"]))
    E.append(_hr(BLUE, 1.5))
    E.append(_gap(6))

    if recon:
        rows = [[
            Paragraph("Type",    ST["label"]),
            Paragraph("Value",   ST["label"]),
            Paragraph("Details", ST["label"]),
        ]]
        for r in recon[:50]:
            extra = _clean(r.get("extra",""))
            rows.append([
                Paragraph(_safe(r.get("result_type",""), 20), ST["label"]),
                Paragraph(_safe(r.get("value",""),       65), ST["mono"]),
                Paragraph(_safe(extra,                   90), ST["body_sm"]),
            ])
        rt = Table(rows, colWidths=[26*mm, W*0.38, W*0.43])
        rt.setStyle(TableStyle([
            ("BACKGROUND",     (0,0),(-1,0),  GRAY2),
            ("FONTNAME",       (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0),(-1,0),  7),
            ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, GRAY1]),
            ("GRID",           (0,0),(-1,-1), 0.3, GRAY3),
            ("PADDING",        (0,0),(-1,-1), 5),
            ("VALIGN",         (0,0),(-1,-1), "TOP"),
            ("TEXTCOLOR",      (0,0),(-1,-1), DARK),
        ]))
        E.append(rt)
    else:
        E.append(Paragraph("No recon data collected.", ST["body_sm"]))

    # ══════════════════════════ CRAWL STATS ══════════════════════════════════
    E.append(_gap(14))
    E.append(Paragraph("Crawl Statistics", ST["h1"]))
    E.append(_hr(BLUE, 1.5))
    E.append(_gap(6))

    cs = Table([
        [Paragraph("Pages Crawled",    ST["label"]),
         Paragraph(str(crawl_stats.get("pages",  0)), ST["body"]),
         Paragraph("Forms Found",      ST["label"]),
         Paragraph(str(crawl_stats.get("forms",  0)), ST["body"])],
        [Paragraph("URLs with Params", ST["label"]),
         Paragraph(str(crawl_stats.get("params", 0)), ST["body"]),
         Paragraph("Max Depth",        ST["label"]),
         Paragraph(str(crawl_stats.get("depth",  3)), ST["body"])],
    ], colWidths=[30*mm, W/2-30*mm, 30*mm, W/2-30*mm])
    cs.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(0,-1), GRAY2),
        ("BACKGROUND", (2,0),(2,-1), GRAY2),
        ("BACKGROUND", (1,0),(1,-1), WHITE),
        ("BACKGROUND", (3,0),(3,-1), WHITE),
        ("GRID",       (0,0),(-1,-1), 0.4, GRAY3),
        ("PADDING",    (0,0),(-1,-1), 8),
        ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
        ("TEXTCOLOR",  (0,0),(-1,-1), DARK),
    ]))
    E.append(cs)

    # ══════════════════════════ FOOTER ═══════════════════════════════════════
    E.append(_gap(20))
    E.append(_hr())
    ft = Table([[
        Paragraph("Generated by VulnX Security Scanner", ST["body_sm"]),
        Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M"),
                  ParagraphStyle("fc", fontSize=7, textColor=GRAY4,
                                alignment=TA_CENTER)),
        Paragraph("CONFIDENTIAL — For authorized testing only",
                  ParagraphStyle("fr", fontSize=7, fontName="Helvetica-Bold",
                                textColor=RED, alignment=TA_RIGHT)),
    ]], colWidths=[W*0.38, W*0.28, W*0.34])
    ft.setStyle(TableStyle([
        ("PADDING", (0,0),(-1,-1), 0),
        ("VALIGN",  (0,0),(-1,-1), "MIDDLE"),
    ]))
    E.append(ft)

    try:
        doc.build(E)
        return True, output_path
    except Exception as e:
        return False, str(e)
