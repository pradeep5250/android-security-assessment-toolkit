"""
Report Generator.

Generates PDF, HTML, and CSV security assessment reports.
"""

import csv
import io
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from app.config import settings
from app.core.risk_scorer import generate_recommendations, get_risk_level

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security assessment reports in multiple formats."""

    def __init__(self):
        self.reports_dir = settings.reports_path

    async def generate_pdf(
        self, title: str, scan_results: List[Dict[str, Any]], device_info: Dict[str, Any] | None = None
    ) -> Path:
        """Generate a PDF security report using ReportLab."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak, HRFlowable,
            )
        except ImportError:
            logger.warning("ReportLab not installed, generating text-based PDF alternative")
            return await self._generate_text_report(title, scan_results, device_info, "pdf")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.pdf"
        filepath = self.reports_dir / filename

        doc = SimpleDocTemplate(str(filepath), pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle", parent=styles["Title"],
            fontSize=24, spaceAfter=30, textColor=colors.HexColor("#1a1a2e"),
        )
        heading_style = ParagraphStyle(
            "CustomHeading", parent=styles["Heading2"],
            fontSize=16, spaceAfter=12, textColor=colors.HexColor("#16213e"),
        )
        body_style = styles["Normal"]

        # ── Header ───────────────────────────────────────────────────────
        elements.append(Paragraph("🛡️ Android Security Assessment Report", title_style))
        elements.append(Paragraph(title, heading_style))
        elements.append(Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            body_style,
        ))
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0f3460")))
        elements.append(Spacer(1, 20))

        # ── Device Info ──────────────────────────────────────────────────
        if device_info:
            elements.append(Paragraph("Device Information", heading_style))
            dev_data = [
                ["Property", "Value"],
                ["Model", device_info.get("model", "N/A")],
                ["Manufacturer", device_info.get("manufacturer", "N/A")],
                ["Android Version", device_info.get("android_version", "N/A")],
                ["Security Patch", device_info.get("security_patch", "N/A")],
                ["Serial", device_info.get("serial", "N/A")],
            ]
            dev_table = Table(dev_data, colWidths=[2 * inch, 4 * inch])
            dev_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ]))
            elements.append(dev_table)
            elements.append(Spacer(1, 20))

        # ── Risk Summary ─────────────────────────────────────────────────
        all_findings = []
        for scan in scan_results:
            findings = scan.get("findings", {})
            if isinstance(findings, dict):
                all_findings.extend(findings.get("findings", []))
            elif isinstance(findings, list):
                all_findings.extend(findings)

        from app.core.risk_scorer import calculate_risk_score, aggregate_findings
        risk_score = calculate_risk_score(all_findings)
        risk_info = get_risk_level(risk_score)

        elements.append(Paragraph("Risk Summary", heading_style))
        severity_counts = {}
        for f in all_findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_data = [
            ["Metric", "Value"],
            ["Overall Risk Score", f"{risk_score:.1f} / 100"],
            ["Risk Level", risk_info["level"]],
            ["Total Findings", str(len(all_findings))],
            ["Critical", str(severity_counts.get("critical", 0))],
            ["High", str(severity_counts.get("high", 0))],
            ["Medium", str(severity_counts.get("medium", 0))],
            ["Low", str(severity_counts.get("low", 0))],
            ["Info", str(severity_counts.get("info", 0))],
        ]
        risk_table = Table(risk_data, colWidths=[2.5 * inch, 3.5 * inch])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e94560")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 20))

        # ── Findings Detail ──────────────────────────────────────────────
        if all_findings:
            elements.append(Paragraph("Detailed Findings", heading_style))

            severity_colors = {
                "critical": colors.HexColor("#dc2626"),
                "high": colors.HexColor("#ea580c"),
                "medium": colors.HexColor("#d97706"),
                "low": colors.HexColor("#2563eb"),
                "info": colors.HexColor("#6b7280"),
            }

            findings_data = [["#", "Severity", "Title", "Category"]]
            for i, finding in enumerate(all_findings[:50], 1):
                findings_data.append([
                    str(i),
                    finding.get("severity", "info").upper(),
                    finding.get("title", "")[:60],
                    finding.get("category", ""),
                ])

            findings_table = Table(
                findings_data,
                colWidths=[0.4 * inch, 0.9 * inch, 3.3 * inch, 1.4 * inch],
            )
            findings_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(findings_table)
            elements.append(Spacer(1, 20))

        # ── Recommendations ──────────────────────────────────────────────
        recommendations = generate_recommendations(all_findings)
        if recommendations:
            elements.append(PageBreak())
            elements.append(Paragraph("Security Recommendations", heading_style))
            for i, rec in enumerate(recommendations[:20], 1):
                elements.append(Paragraph(
                    f"<b>{i}. [{rec['priority'].upper()}]</b> {rec['recommendation']}",
                    body_style,
                ))
                elements.append(Spacer(1, 6))

        # ── Footer ───────────────────────────────────────────────────────
        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        elements.append(Paragraph(
            "<i>Generated by Android Security Assessment Toolkit (ASAT) — "
            "For authorized security testing only.</i>",
            ParagraphStyle("Footer", parent=body_style, fontSize=8, textColor=colors.grey),
        ))

        doc.build(elements)
        return filepath

    async def generate_html(
        self, title: str, scan_results: List[Dict[str, Any]], device_info: Dict[str, Any] | None = None
    ) -> Path:
        """Generate a self-contained HTML report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.html"
        filepath = self.reports_dir / filename

        # Collect findings
        all_findings = []
        for scan in scan_results:
            findings = scan.get("findings", {})
            if isinstance(findings, dict):
                all_findings.extend(findings.get("findings", []))
            elif isinstance(findings, list):
                all_findings.extend(findings)

        from app.core.risk_scorer import calculate_risk_score
        risk_score = calculate_risk_score(all_findings)
        risk_info = get_risk_level(risk_score)

        severity_counts = {}
        for f in all_findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        recommendations = generate_recommendations(all_findings)

        # Build findings rows
        findings_rows = ""
        for i, f in enumerate(all_findings[:100], 1):
            sev = f.get("severity", "info")
            findings_rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="badge badge-{sev}">{sev.upper()}</span></td>
                <td>{f.get('title', '')}</td>
                <td>{f.get('category', '')}</td>
                <td>{f.get('description', '')[:100]}</td>
            </tr>"""

        # Build recommendations
        rec_items = ""
        for rec in recommendations[:20]:
            rec_items += f"""
            <li>
                <span class="badge badge-{rec['priority']}">{rec['priority'].upper()}</span>
                {rec['recommendation']}
            </li>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ASAT Report - {title}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a1a; color: #e0e0e0; padding: 2rem; }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  h1 {{ color: #00d4ff; font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ color: #00d4ff; font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 2px solid #1a1a3e; padding-bottom: 0.5rem; }}
  .meta {{ color: #888; font-size: 0.9rem; margin-bottom: 2rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1rem 0; }}
  .card {{ background: #12122a; border: 1px solid #1a1a3e; border-radius: 12px; padding: 1.2rem; text-align: center; }}
  .card .value {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ color: #888; font-size: 0.85rem; margin-top: 0.3rem; }}
  .risk-critical {{ color: #ef4444; }}
  .risk-high {{ color: #f97316; }}
  .risk-medium {{ color: #eab308; }}
  .risk-low {{ color: #22c55e; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.7rem; text-align: left; border-bottom: 1px solid #1a1a3e; font-size: 0.85rem; }}
  th {{ background: #12122a; color: #00d4ff; font-weight: 600; }}
  tr:hover {{ background: #0d0d20; }}
  .badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
  .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
  .badge-high {{ background: #7c2d12; color: #fed7aa; }}
  .badge-medium {{ background: #713f12; color: #fef08a; }}
  .badge-low {{ background: #14532d; color: #bbf7d0; }}
  .badge-info {{ background: #1e3a5f; color: #93c5fd; }}
  ul {{ list-style: none; }}
  ul li {{ padding: 0.5rem 0; border-bottom: 1px solid #1a1a3e; }}
  .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #1a1a3e; color: #555; font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ {title}</h1>
  <p class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | ASAT Security Report</p>

  <h2>Risk Overview</h2>
  <div class="cards">
    <div class="card">
      <div class="value risk-{'critical' if risk_score >= 80 else 'high' if risk_score >= 55 else 'medium' if risk_score >= 30 else 'low'}">{risk_score:.0f}</div>
      <div class="label">Risk Score</div>
    </div>
    <div class="card">
      <div class="value">{risk_info['level']}</div>
      <div class="label">Risk Level</div>
    </div>
    <div class="card">
      <div class="value">{len(all_findings)}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="card">
      <div class="value risk-critical">{severity_counts.get('critical', 0)}</div>
      <div class="label">Critical</div>
    </div>
    <div class="card">
      <div class="value risk-high">{severity_counts.get('high', 0)}</div>
      <div class="label">High</div>
    </div>
    <div class="card">
      <div class="value risk-medium">{severity_counts.get('medium', 0)}</div>
      <div class="label">Medium</div>
    </div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Category</th><th>Description</th></tr></thead>
    <tbody>{findings_rows if findings_rows else '<tr><td colspan="5">No findings</td></tr>'}</tbody>
  </table>

  <h2>Recommendations</h2>
  <ul>{rec_items if rec_items else '<li>No recommendations</li>'}</ul>

  <div class="footer">
    Android Security Assessment Toolkit (ASAT) — For authorized security testing only.
  </div>
</div>
</body>
</html>"""

        filepath.write_text(html, encoding="utf-8")
        return filepath

    async def generate_csv(
        self, title: str, scan_results: List[Dict[str, Any]]
    ) -> Path:
        """Generate a CSV export of findings."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.csv"
        filepath = self.reports_dir / filename

        all_findings = []
        for scan in scan_results:
            findings = scan.get("findings", {})
            if isinstance(findings, dict):
                all_findings.extend(findings.get("findings", []))
            elif isinstance(findings, list):
                all_findings.extend(findings)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["#", "Severity", "Title", "Category", "Description", "Recommendation", "CWE"])

        for i, f in enumerate(all_findings, 1):
            writer.writerow([
                i,
                f.get("severity", "info"),
                f.get("title", ""),
                f.get("category", ""),
                f.get("description", ""),
                f.get("recommendation", ""),
                f.get("cwe_id", ""),
            ])

        filepath.write_text(output.getvalue(), encoding="utf-8")
        return filepath

    async def _generate_text_report(
        self, title: str, scan_results: List[Dict[str, Any]],
        device_info: Dict[str, Any] | None, ext: str,
    ) -> Path:
        """Fallback text report when ReportLab is not available."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.txt"
        filepath = self.reports_dir / filename

        lines = [
            "=" * 60,
            "ANDROID SECURITY ASSESSMENT REPORT",
            "=" * 60,
            f"Title: {title}",
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
        ]

        all_findings = []
        for scan in scan_results:
            findings = scan.get("findings", {})
            if isinstance(findings, dict):
                all_findings.extend(findings.get("findings", []))
            elif isinstance(findings, list):
                all_findings.extend(findings)

        lines.append(f"Total Findings: {len(all_findings)}")
        lines.append("-" * 60)

        for i, f in enumerate(all_findings, 1):
            lines.append(f"\n[{f.get('severity', 'info').upper()}] {f.get('title', '')}")
            lines.append(f"  Category: {f.get('category', '')}")
            lines.append(f"  {f.get('description', '')}")
            if f.get("recommendation"):
                lines.append(f"  → {f['recommendation']}")

        filepath.write_text("\n".join(lines), encoding="utf-8")
        return filepath


# Singleton
report_generator = ReportGenerator()
