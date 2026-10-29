import html
import io
import textwrap
import uuid
from typing import Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.finding import Finding
from app.models.mitigation import Mitigation
from app.models.scan import Scan


def generate_html_report(
    scan: Scan,
    findings: List[Finding],
    mitigations_map: Optional[Dict[uuid.UUID, Mitigation]] = None,
) -> str:
    """
    Generates a secure, standalone HTML vulnerability scan report.
    All untrusted data is strictly HTML-escaped. Standalone CSS with no external assets.
    """
    mitigations = mitigations_map or {}

    # Severity counts
    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    medium_count = sum(1 for f in findings if f.severity == "medium")
    low_count = sum(1 for f in findings if f.severity == "low")

    # Safe escaped metadata
    proj_name = html.escape(scan.project_name)
    scan_id_str = html.escape(str(scan.scan_id))
    status_str = html.escape(scan.status)
    sub_type_str = html.escape(scan.submission_type)
    lang_str = html.escape(scan.language)
    created_at_str = html.escape(scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.created_at else "N/A")
    completed_at_str = html.escape(scan.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.completed_at else "In Progress")

    # Risk badge styling
    risk_score = round(scan.risk_score, 1)
    if risk_score >= 8.0:
        risk_color = "#ef4444"
        risk_label = "CRITICAL RISK"
    elif risk_score >= 6.0:
        risk_color = "#f97316"
        risk_label = "HIGH RISK"
    elif risk_score >= 3.0:
        risk_color = "#eab308"
        risk_label = "MEDIUM RISK"
    elif risk_score > 0:
        risk_color = "#3b82f6"
        risk_label = "LOW RISK"
    else:
        risk_color = "#22c55e"
        risk_label = "CLEAN"

    # Build findings HTML cards
    findings_html_list = []
    if not findings:
        findings_html_list.append("""
        <div class="empty-state">
            <div class="empty-icon">&#10004;</div>
            <h3>No Security Vulnerabilities Detected</h3>
            <p>Static rules and ML heuristics found no matching security flaws in the submitted source code.</p>
        </div>
        """)
    else:
        for idx, f in enumerate(findings, 1):
            f_title = html.escape(f.title)
            f_sev = html.escape(f.severity.upper())
            f_file = html.escape(f.file_path)
            f_lines = f"{f.start_line}-{f.end_line}"
            f_source = html.escape(f.source.upper())
            f_cwe = html.escape(f.cwe_id or "Uncategorized")
            f_owasp = html.escape(f.owasp or "Unassigned")
            f_rule = html.escape(f.rule_id or "N/A")
            f_snippet = html.escape(f.snippet)
            f_mitigation = html.escape(f.mitigation)
            f_ml = f"{f.ml_score:.2f}" if f.ml_score is not None else "N/A"

            sev_class = f"sev-{f.severity.lower()}"

            mit_detail = mitigations.get(f.mitigation_id) if f.mitigation_id else None
            code_diff_html = ""
            if mit_detail and mit_detail.code_diff:
                code_diff_html = f"""
                <div class="code-diff-block">
                    <strong>Suggested Remediation Diff:</strong>
                    <pre class="diff-pre"><code>{html.escape(mit_detail.code_diff)}</code></pre>
                </div>
                """

            findings_html_list.append(f"""
            <div class="finding-card {sev_class}-border">
                <div class="finding-header">
                    <span class="finding-num">#{idx}</span>
                    <span class="badge {sev_class}">{f_sev}</span>
                    <span class="finding-title">{f_title}</span>
                </div>
                <div class="finding-meta-grid">
                    <div><strong>Location:</strong> <code>{f_file}:{f_lines}</code></div>
                    <div><strong>Detection Source:</strong> <span class="tag">{f_source}</span> (ML Score: {f_ml})</div>
                    <div><strong>CWE Identifier:</strong> <code>{f_cwe}</code></div>
                    <div><strong>Rule Identifier:</strong> <code>{f_rule}</code></div>
                    <div class="full-width"><strong>Provisional OWASP (2025):</strong> {f_owasp}</div>
                </div>
                <div class="snippet-box">
                    <div class="snippet-label">Vulnerable Snippet:</div>
                    <pre><code>{f_snippet}</code></pre>
                </div>
                <div class="mitigation-box">
                    <strong>Remediation Guidance:</strong>
                    <p>{f_mitigation}</p>
                    {code_diff_html}
                </div>
            </div>
            """)

    findings_content = "\n".join(findings_html_list)

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroSentinel Security Scan Report - {proj_name}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --clean: #22c55e;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: var(--font-sans);
            line-height: 1.5;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem 2rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .logo-area h1 {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #38bdf8;
            letter-spacing: -0.025em;
        }}
        .logo-area p {{
            color: var(--text-muted);
            font-size: 0.875rem;
        }}
        .risk-badge {{
            background: rgba(0,0,0,0.3);
            border: 2px solid {risk_color};
            border-radius: 8px;
            padding: 0.75rem 1.25rem;
            text-align: right;
        }}
        .risk-score {{
            font-size: 2rem;
            font-weight: 800;
            color: {risk_color};
            line-height: 1;
        }}
        .risk-label {{
            font-size: 0.75rem;
            font-weight: 700;
            color: {risk_color};
            text-transform: uppercase;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem 1.25rem;
        }}
        .summary-card .label {{
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 600;
        }}
        .summary-card .value {{
            font-size: 1.25rem;
            font-weight: 700;
            margin-top: 0.25rem;
        }}
        .severity-bar {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
            align-items: center;
        }}
        .sev-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            font-weight: 600;
        }}
        .sev-pill {{
            padding: 0.2rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            color: #fff;
        }}
        .badge {{
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            color: #fff;
        }}
        .sev-critical {{ background-color: var(--critical); }}
        .sev-high {{ background-color: var(--high); }}
        .sev-medium {{ background-color: var(--medium); color: #000; }}
        .sev-low {{ background-color: var(--low); }}
        .sev-critical-border {{ border-left: 4px solid var(--critical); }}
        .sev-high-border {{ border-left: 4px solid var(--high); }}
        .sev-medium-border {{ border-left: 4px solid var(--medium); }}
        .sev-low-border {{ border-left: 4px solid var(--low); }}
        .finding-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }}
        .finding-num {{
            color: var(--text-muted);
            font-weight: 700;
            font-size: 0.875rem;
        }}
        .finding-title {{
            font-size: 1.1rem;
            font-weight: 600;
        }}
        .finding-meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 0.75rem;
            font-size: 0.85rem;
            background: rgba(0,0,0,0.2);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }}
        .full-width {{ grid-column: 1 / -1; }}
        code {{
            font-family: var(--font-mono);
            background: rgba(255,255,255,0.08);
            padding: 0.15rem 0.35rem;
            border-radius: 3px;
            font-size: 0.825rem;
        }}
        .tag {{
            background: #0284c7;
            color: #fff;
            padding: 0.1rem 0.4rem;
            border-radius: 3px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .snippet-box {{
            margin-bottom: 1rem;
        }}
        .snippet-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }}
        pre {{
            background: #090d16;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            color: #e2e8f0;
        }}
        .mitigation-box {{
            background: rgba(56, 189, 248, 0.05);
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            font-size: 0.875rem;
        }}
        .mitigation-box strong {{
            color: #38bdf8;
        }}
        .code-diff-block {{
            margin-top: 0.75rem;
        }}
        .diff-pre {{
            background: #000;
            color: #86efac;
            margin-top: 0.25rem;
        }}
        .empty-state {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 3rem 1rem;
            text-align: center;
        }}
        .empty-icon {{
            font-size: 3rem;
            color: var(--clean);
            margin-bottom: 0.5rem;
        }}
        footer {{
            margin-top: 3rem;
            text-align: center;
            font-size: 0.75rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">
                <h1>ZeroSentinel Security Report</h1>
                <p>Automated Source Vulnerability Detection & Mitigation Platform</p>
            </div>
            <div class="risk-badge">
                <div class="risk-score">{risk_score}</div>
                <div class="risk-label">{risk_label}</div>
            </div>
        </header>

        <section class="summary-grid">
            <div class="summary-card">
                <div class="label">Project Name</div>
                <div class="value">{proj_name}</div>
            </div>
            <div class="summary-card">
                <div class="label">Total Findings</div>
                <div class="value">{len(findings)}</div>
            </div>
            <div class="summary-card">
                <div class="label">Submission Mode</div>
                <div class="value">{sub_type_str.upper()} ({lang_str})</div>
            </div>
            <div class="summary-card">
                <div class="label">Execution Status</div>
                <div class="value">{status_str.upper()}</div>
            </div>
            <div class="summary-card">
                <div class="label">Scan ID</div>
                <div class="value" style="font-size: 0.85rem; font-family: var(--font-mono); word-break: break-all;">{scan_id_str}</div>
            </div>
            <div class="summary-card">
                <div class="label">Scan Completed</div>
                <div class="value" style="font-size: 0.85rem;">{completed_at_str}</div>
            </div>
        </section>

        <section class="severity-bar">
            <span style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 700;">Severity Breakdown:</span>
            <div class="sev-item"><span class="sev-pill sev-critical">{critical_count}</span> Critical</div>
            <div class="sev-item"><span class="sev-pill sev-high">{high_count}</span> High</div>
            <div class="sev-item"><span class="sev-pill sev-medium">{medium_count}</span> Medium</div>
            <div class="sev-item"><span class="sev-pill sev-low">{low_count}</span> Low</div>
        </section>

        <section class="findings-section">
            <h2 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem;">Detailed Findings</h2>
            {findings_content}
        </section>

        <footer>
            <p><strong>Notice:</strong> This report was generated by the ZeroSentinel prototype. Detections are algorithmic heuristics and machine learning predictions, and do not constitute confirmed zero-day exploits.</p>
            <p style="margin-top: 0.25rem;">Timestamp: {created_at_str} &bull; Confidential Security Analysis</p>
        </footer>
    </div>
</body>
</html>
"""
    return html_template


def generate_pdf_report(
    scan: Scan,
    findings: List[Finding],
    mitigations_map: Optional[Dict[uuid.UUID, Mitigation]] = None,
) -> bytes:
    """
    Generates a secure, professionally styled PDF report using ReportLab.
    Safely wraps snippets, handles Unicode safely, and enforces page layout constraints.
    """
    mitigations = mitigations_map or {}
    buffer = io.BytesIO()

    # Document setup: 0.5 in margins for maximum readable printable area
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6,
    )
    cell_label_style = ParagraphStyle(
        "CellLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#475569"),
    )
    cell_val_style = ParagraphStyle(
        "CellVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    )
    snippet_style = ParagraphStyle(
        "SnippetText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0f172a"),
    )
    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=12,
        textColor=colors.HexColor("#0f172a"),
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155"),
    )
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#64748b"),
        alignment=1,  # Centered
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("ZeroSentinel Security Vulnerability Report", title_style))
    story.append(Paragraph("Automated Source Vulnerability Detection & Mitigation Platform &bull; Confidential", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # 2. Executive Summary Metadata Table
    proj_name = xml_escape(scan.project_name or "Unknown")
    scan_id_str = xml_escape(str(scan.scan_id))
    status_str = xml_escape((scan.status or "unknown").upper())
    sub_type_str = xml_escape((scan.submission_type or "code").upper())
    completed_at_str = xml_escape(scan.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.completed_at else "In Progress")

    meta_data = [
        [
            Paragraph("Project Name:", cell_label_style),
            Paragraph(proj_name, cell_val_style),
            Paragraph("Risk Score:", cell_label_style),
            Paragraph(f"<b>{scan.risk_score:.1f} / 10.0</b>", cell_val_style),
        ],
        [
            Paragraph("Scan ID:", cell_label_style),
            Paragraph(scan_id_str, cell_val_style),
            Paragraph("Total Findings:", cell_label_style),
            Paragraph(str(len(findings)), cell_val_style),
        ],
        [
            Paragraph("Submission:", cell_label_style),
            Paragraph(f"{sub_type_str} ({xml_escape(scan.language)})", cell_val_style),
            Paragraph("Status:", cell_label_style),
            Paragraph(status_str, cell_val_style),
        ],
        [
            Paragraph("Date Completed:", cell_label_style),
            Paragraph(completed_at_str, cell_val_style),
            Paragraph("", cell_label_style),
            Paragraph("", cell_val_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[80, 190, 80, 190])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 3. Severity Distribution Table
    crit_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    med_count = sum(1 for f in findings if f.severity == "medium")
    low_count = sum(1 for f in findings if f.severity == "low")

    sev_data = [
        [
            Paragraph("<b>Critical</b>", cell_label_style),
            Paragraph("<b>High</b>", cell_label_style),
            Paragraph("<b>Medium</b>", cell_label_style),
            Paragraph("<b>Low</b>", cell_label_style),
        ],
        [
            Paragraph(f"<b>{crit_count}</b>", cell_val_style),
            Paragraph(f"<b>{high_count}</b>", cell_val_style),
            Paragraph(f"<b>{med_count}</b>", cell_val_style),
            Paragraph(f"<b>{low_count}</b>", cell_val_style),
        ],
    ]
    sev_table = Table(sev_data, colWidths=[135, 135, 135, 135])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fee2e2")),
        ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#ffedd5")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#fef9c3")),
        ("BACKGROUND", (3, 0), (3, -1), colors.HexColor("#dbeafe")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 12))

    # 4. Findings Section
    story.append(Paragraph(f"Findings Catalog ({len(findings)} Total)", h2_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=8))

    if not findings:
        clean_p = Paragraph(
            "<b>No security vulnerabilities identified.</b> All static rule checks and ML heuristics evaluated clean.",
            body_style,
        )
        story.append(clean_p)
        story.append(Spacer(1, 15))
    else:
        for idx, f in enumerate(findings, 1):
            finding_blocks = []

            # Severity color
            sev_colors = {
                "critical": colors.HexColor("#dc2626"),
                "high": colors.HexColor("#ea580c"),
                "medium": colors.HexColor("#d97706"),
                "low": colors.HexColor("#2563eb"),
            }
            bar_color = sev_colors.get(f.severity.lower(), colors.HexColor("#64748b"))

            title_text = f"#{idx}. {xml_escape(f.title)} [{xml_escape(f.severity.upper())}]"
            finding_blocks.append(Paragraph(title_text, finding_title_style))

            ml_info = f" | ML Score: {f.ml_score:.2f}" if f.ml_score is not None else ""
            rule_info = f" | Rule: {xml_escape(f.rule_id)}" if f.rule_id else ""
            meta_line = (
                f"<b>Location:</b> {xml_escape(f.file_path)}:{f.start_line}-{f.end_line} | "
                f"<b>Source:</b> {xml_escape(f.source.upper())}{ml_info}{rule_info}"
            )
            finding_blocks.append(Paragraph(meta_line, cell_val_style))

            cwe_owasp_line = (
                f"<b>CWE:</b> {xml_escape(f.cwe_id or 'None')} | "
                f"<b>Provisional OWASP:</b> {xml_escape(f.owasp or 'Unassigned')}"
            )
            finding_blocks.append(Paragraph(cwe_owasp_line, cell_val_style))
            finding_blocks.append(Spacer(1, 3))

            # Code snippet with line truncation to avoid table overflow
            snippet_raw = f.snippet or ""
            wrapped_lines = []
            for line in snippet_raw.splitlines():
                wrapped_lines.append(textwrap.shorten(line, width=90, placeholder="..."))
            formatted_snippet = "\n".join(wrapped_lines) if wrapped_lines else "(No snippet available)"

            snip_table = Table([[Preformatted(xml_escape(formatted_snippet), snippet_style)]], colWidths=[520])
            snip_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            finding_blocks.append(snip_table)
            finding_blocks.append(Spacer(1, 3))

            # Mitigation guidance
            mit_text = f"<b>Remediation:</b> {xml_escape(f.mitigation or 'Review code for security compliance.')}"
            finding_blocks.append(Paragraph(mit_text, body_style))

            mit_detail = mitigations.get(f.mitigation_id) if f.mitigation_id else None
            if mit_detail and mit_detail.code_diff:
                diff_table = Table([[Preformatted(f"Suggested Diff:\n{xml_escape(mit_detail.code_diff)}", snippet_style)]], colWidths=[520])
                diff_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#86efac")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                finding_blocks.append(Spacer(1, 2))
                finding_blocks.append(diff_table)

            finding_blocks.append(Spacer(1, 6))
            finding_blocks.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=6))

            story.append(KeepTogether(finding_blocks))

    # 5. Disclaimer Footer
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Notice: ZeroSentinel prototype automated security assessment. Static rules and ML detections are heuristic "
        "indicators and do not constitute confirmed zero-day exploits. Verify before applying production changes.",
        disclaimer_style,
    ))

    # Build the PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
