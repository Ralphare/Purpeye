"""
PurpEye - PDF Report Generator (v2, redesigned)
Turns a scan result into a clean, professional PDF a business owner
could be handed or emailed: branded header band, clear score panel,
plain-English summary, and a color-coded findings table.

Uses reportlab. Install with:  pip install reportlab --break-system-packages
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Flowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime


# --- Brand palette ---
PURPLE = colors.HexColor("#6B4FBB")       # primary brand
PURPLE_DK = colors.HexColor("#4A3488")    # deep accent
LILAC = colors.HexColor("#F3F0FA")        # soft background tint
INK = colors.HexColor("#2A2A33")          # near-black body text
GREY = colors.HexColor("#6C6C78")         # muted captions
HAIRLINE = colors.HexColor("#E4E0EF")     # light dividers

GREEN = colors.HexColor("#2E9E5B")
ORANGE = colors.HexColor("#E08A1E")
AMBER = colors.HexColor("#C9A227")
RED = colors.HexColor("#D64545")

SEVERITY_COLOR = {
    "Critical": RED, "High": RED, "Medium": ORANGE, "Low": AMBER, "Info": GREEN,
}


def _score_color(score):
    if score >= 85:
        return GREEN
    elif score >= 60:
        return ORANGE
    else:
        return RED


class HeaderBand(Flowable):
    """A full-width purple header band with the PurpEye wordmark."""
    def __init__(self, width, height=30 * mm):
        super().__init__()
        self.width = width
        self.height = height
        # A small bleed so the band's edges line up flush with the body
        # text margins below it (corrects reportlab's flowable indent).
        self.bleed = 1 * mm

    def draw(self):
        c = self.canv
        left = -self.bleed
        full_w = self.width + (self.bleed * 2)
        # Band background - spans the full content width, edge to edge
        c.setFillColor(PURPLE)
        c.rect(left, 0, full_w, self.height, fill=1, stroke=0)
        # A thin deep-purple accent stripe along the bottom of the band
        c.setFillColor(PURPLE_DK)
        c.rect(left, 0, full_w, 3 * mm, fill=1, stroke=0)
        # Inner padding so text isn't cramped against the band's edges.
        inset = 7 * mm
        # Vertically centre the text within the band (a bit above middle).
        text_y = (self.height + 3 * mm) / 2 - 3 * mm
        # Wordmark on the left
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 26)
        c.drawString(inset, text_y, "PurpEye")
        # Tagline on the right, baseline nudged to sit with the wordmark
        c.setFont("Helvetica", 10)
        c.drawRightString(self.width - inset, text_y + 3 * mm,
                          "Website Security Report")


class Divider(Flowable):
    """A simple hairline divider with a short purple lead."""
    def __init__(self, width):
        super().__init__()
        self.width = width
        self.height = 4 * mm

    def draw(self):
        c = self.canv
        y = 2 * mm
        # short purple segment
        c.setStrokeColor(PURPLE)
        c.setLineWidth(2)
        c.line(0, y, 22 * mm, y)
        # rest hairline
        c.setStrokeColor(HAIRLINE)
        c.setLineWidth(0.8)
        c.line(22 * mm, y, self.width, y)


def generate(scan_result, summary_text, output_path="purpeye_report.pdf"):
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=14 * mm, bottomMargin=16 * mm,
        leftMargin=16 * mm, rightMargin=16 * mm,
    )
    content_width = doc.width

    styles = getSampleStyleSheet()

    meta_style = ParagraphStyle("Meta", parent=styles["Normal"],
        fontSize=10.5, textColor=GREY, leading=15)
    meta_strong = ParagraphStyle("MetaStrong", parent=styles["Normal"],
        fontSize=10.5, textColor=INK, leading=15)
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"],
        textColor=PURPLE_DK, fontSize=13, spaceBefore=4, spaceAfter=8,
        fontName="Helvetica-Bold")
    body_style = ParagraphStyle("Body", parent=styles["Normal"],
        fontSize=10.5, leading=16, textColor=INK)
    cell_style = ParagraphStyle("Cell", parent=styles["Normal"],
        fontSize=9.5, leading=13, textColor=INK)

    story = []

    # --- Header band ---
    story.append(HeaderBand(content_width))
    story.append(Spacer(1, 12))

    # --- Meta line: what + when, as a clean two-column table ---
    scan_date = datetime.now().strftime("%d %B %Y  ·  %H:%M")
    meta_table = Table(
        [[Paragraph("<b>Website scanned</b>", meta_strong),
          Paragraph(scan_result["target"], meta_style)],
         [Paragraph("<b>Date</b>", meta_strong),
          Paragraph(scan_date, meta_style)]],
        colWidths=[38 * mm, content_width - 38 * mm],
    )
    meta_table.setStyle(TableStyle([
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # --- Score panel: score on the left, rating + bar on the right ---
    score = scan_result["risk_score"]
    rating = scan_result["rating"]
    sc = _score_color(score)

    big_score = ParagraphStyle("BigScore", parent=styles["Normal"],
        fontSize=46, textColor=sc, alignment=TA_CENTER, leading=48,
        fontName="Helvetica-Bold")
    score_label = ParagraphStyle("ScoreLabel", parent=styles["Normal"],
        fontSize=9, textColor=GREY, alignment=TA_CENTER)
    rating_style = ParagraphStyle("RatingBig", parent=styles["Normal"],
        fontSize=18, textColor=sc, fontName="Helvetica-Bold", leading=22)
    rating_sub = ParagraphStyle("RatingSub", parent=styles["Normal"],
        fontSize=10, textColor=GREY, leading=15)

    left_cell = [Paragraph(f"{score}", big_score),
                 Paragraph("out of 100", score_label)]
    right_cell = [Paragraph(rating, rating_style), Spacer(1, 4),
                  Paragraph("Overall security posture based on all checks run.",
                            rating_sub)]

    score_panel = Table([[left_cell, right_cell]],
                        colWidths=[46 * mm, content_width - 46 * mm])
    score_panel.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LILAC),
        ("BOX", (0, 0), (-1, -1), 0.8, HAIRLINE),
        ("LINEAFTER", (0, 0), (0, 0), 0.8, HAIRLINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(score_panel)
    story.append(Spacer(1, 20))

    # --- Assessment Scope & Objective ---
    story.append(Paragraph("Assessment Scope &amp; Objective", heading_style))
    story.append(Divider(content_width))
    story.append(Spacer(1, 6))
    scope_text = (
        f"This assessment evaluated the public-facing web presence of "
        f"<b>{scan_result['target']}</b> against a set of common, high-impact "
        f"web security weaknesses. The objective was to give the site owner a "
        f"clear, prioritized understanding of their current security posture and "
        f"the practical steps needed to improve it. Testing was non-intrusive and "
        f"limited to information the site returns to any ordinary visitor."
    )
    story.append(Paragraph(scope_text, body_style))
    story.append(Spacer(1, 18))

    # --- Executive Summary section ---
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(Divider(content_width))
    story.append(Spacer(1, 6))
    story.append(Paragraph(summary_text.replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 18))

    # --- Severity Ratings explanation ---
    story.append(Paragraph("Understanding the Severity Ratings", heading_style))
    story.append(Divider(content_width))
    story.append(Spacer(1, 6))
    sev_rows = [
        ["Critical", "A weakness that could lead to full compromise; address immediately."],
        ["High", "A serious weakness that a motivated attacker could exploit; address promptly."],
        ["Medium", "A meaningful gap that increases risk; should be scheduled for correction."],
        ["Low", "A minor issue with limited impact; worth tidying up."],
        ["Info", "An observation or a control already working correctly; no action required."],
    ]
    sev_cell = ParagraphStyle("SevCell", parent=styles["Normal"],
        fontSize=9.5, leading=13, textColor=INK)
    sev_data = []
    for label, desc in sev_rows:
        sev_data.append([
            Paragraph(f'<b>{label}</b>', ParagraphStyle("SL", parent=sev_cell,
                textColor=SEVERITY_COLOR.get(label, GREY))),
            Paragraph(desc, sev_cell),
        ])
    sev_table = Table(sev_data, colWidths=[24 * mm, content_width - 24 * mm])
    sev_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 18))

    # --- Split findings: real issues vs. positive/good notes ---
    issues = [f for f in scan_result["all_findings"]
              if f["severity"] in ("Critical", "High", "Medium", "Low")]
    positives = [f for f in scan_result["all_findings"]
                 if f["severity"] == "Info"]

    # Sort issues worst-first.
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    issues.sort(key=lambda f: order.get(f["severity"], 4))

    # --- Issues Found section (only real problems) ---
    story.append(Paragraph("Issues Found", heading_style))
    story.append(Divider(content_width))
    story.append(Spacer(1, 6))

    if issues:
        table_data = [["Severity", "Finding", "Check"]]
        for f in issues:
            table_data.append([
                f["severity"],
                Paragraph(f["issue"], cell_style),
                Paragraph(f.get("source_check", ""), cell_style),
            ])

        col1 = 26 * mm
        col3 = 44 * mm
        col2 = content_width - col1 - col3
        findings_table = Table(table_data, colWidths=[col1, col2, col3], repeatRows=1)

        ts = [
            ("BACKGROUND", (0, 0), (-1, 0), PURPLE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("FONTSIZE", (0, 1), (-1, -1), 9.5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 0.6, HAIRLINE),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ]
        for i, f in enumerate(issues, start=1):
            if i % 2 == 0:
                ts.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FAF9FD")))
            ts.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLOR.get(f["severity"], GREY)))
        findings_table.setStyle(TableStyle(ts))
        story.append(findings_table)
    else:
        # No problems at all - say so positively.
        no_issue_style = ParagraphStyle("NoIssue", parent=styles["Normal"],
            fontSize=10.5, textColor=GREEN, leading=15, fontName="Helvetica-Bold")
        story.append(Paragraph("No security issues were found. Excellent.", no_issue_style))

    story.append(Spacer(1, 20))

    # --- What's Working Well section (the good Info items) ---
    if positives:
        story.append(Paragraph("What's Working Well", heading_style))
        story.append(Divider(content_width))
        story.append(Spacer(1, 6))

        check_style = ParagraphStyle("Good", parent=styles["Normal"],
            fontSize=10.5, textColor=INK, leading=17)
        for f in positives:
            # Green check mark drawn as text, then the item.
            story.append(Paragraph(
                f'<font color="#2E9E5B"><b>&#10003;</b></font>&nbsp;&nbsp;{f["issue"]}',
                check_style))
        story.append(Spacer(1, 20))

    # --- How to Fix section (remediation for each issue) ---
    fixable = [f for f in issues if f.get("fix")]
    if fixable:
        story.append(Paragraph("How to Fix These Issues", heading_style))
        story.append(Divider(content_width))
        story.append(Spacer(1, 6))

        fix_num_style = ParagraphStyle("FixNum", parent=styles["Normal"],
            fontSize=10.5, textColor=PURPLE_DK, fontName="Helvetica-Bold", leading=15)
        fix_issue_style = ParagraphStyle("FixIssue", parent=styles["Normal"],
            fontSize=10.5, textColor=INK, fontName="Helvetica-Bold", leading=15)
        fix_step_style = ParagraphStyle("FixStep", parent=styles["Normal"],
            fontSize=10, textColor=INK, leading=15, leftIndent=6)

        for i, f in enumerate(fixable, start=1):
            story.append(Paragraph(
                f'{i}. <font color="#4A3488">{f["issue"]}</font>', fix_issue_style))
            story.append(Paragraph(f'{f["fix"]}', fix_step_style))
            story.append(Spacer(1, 8))
        story.append(Spacer(1, 12))

    # --- Limitations ---
    story.append(Paragraph("Limitations", heading_style))
    story.append(Divider(content_width))
    story.append(Spacer(1, 6))
    limitations_text = (
        "This report is based on automated, non-intrusive testing and reflects the "
        "state of the site at the time of the scan. It is intended as a practical "
        "starting point, not a substitute for a full manual security audit. Automated "
        "checks can miss issues that require human judgement, such as business-logic "
        "flaws or context-specific weaknesses. The findings should be treated as an "
        "input to your wider decisions about security, and re-testing is recommended "
        "after any fixes are applied."
    )
    story.append(Paragraph(limitations_text, body_style))
    story.append(Spacer(1, 18))

    # --- Footer ---
    footer_style = ParagraphStyle("Footer", parent=styles["Normal"],
        fontSize=8, textColor=GREY, alignment=TA_CENTER, leading=12)
    story.append(Divider(content_width))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generated by PurpEye — automated website security scanning.<br/>"
        "This report reflects passive checks and is a starting point, not a full audit.",
        footer_style))

    doc.build(story)
    return output_path


if __name__ == "__main__":
    example_scan = {
        "target": "https://example.com",
        "risk_score": 50,
        "rating": "At risk",
        "all_findings": [
            {"issue": "Site uses HTTPS", "detail": "Good - traffic is encrypted.",
             "severity": "Info", "source_check": "HTTPS & Security Headers"},
            {"issue": "Missing header: Content-Security-Policy", "detail": "x",
             "severity": "Medium", "source_check": "HTTPS & Security Headers",
             "fix": "Add a Content-Security-Policy header. Start in report-only mode, then tighten it."},
            {"issue": "Missing header: Strict-Transport-Security", "detail": "x",
             "severity": "Medium", "source_check": "HTTPS & Security Headers",
             "fix": "Ask whoever manages your website to add the Strict-Transport-Security header."},
            {"issue": "Missing header: X-Frame-Options", "detail": "x",
             "severity": "Medium", "source_check": "HTTPS & Security Headers",
             "fix": "Add the header X-Frame-Options: SAMEORIGIN on your web server."},
            {"issue": "No obvious software version disclosure", "detail": "Good - hidden.",
             "severity": "Info", "source_check": "Software Version & Outdated Components"},
        ],
    }
    example_summary = (
        "Overall score: 50/100 (At risk)\n\n"
        "Your website is reasonably safe but has some gaps worth closing. "
        "The main issues are missing security headers — small settings on your "
        "web server that protect visitors from common attacks. None are "
        "emergencies, but together they lower your score.\n\n"
        "Fix these first: add the Strict-Transport-Security and "
        "Content-Security-Policy headers. Both are quick changes for whoever "
        "manages your website."
    )
    path = generate(example_scan, example_summary, "purpeye_report.pdf")
    print(f"[PurpEye] PDF report saved to: {path}")
