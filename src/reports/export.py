"""
Export Module
Export vulnerability scan results to various formats (JSON, HTML, PDF)
"""

import json
import logging
from datetime import datetime
from typing import Dict
import os

logger = logging.getLogger(__name__)


class ReportExporter:
    """Export scan results to various formats"""

    def __init__(self):
        self.timestamp = datetime.now()

    def export_to_json(self, scan_results: Dict, output_path: str) -> bool:
        """Export scan results to JSON format"""
        try:
            # Add metadata
            export_data = {
                "export_timestamp": self.timestamp.isoformat(),
                "tool_version": "1.0",
                "scan_results": scan_results
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Exported scan results to JSON: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export to JSON: {e}")
            return False

    def export_to_html(self, scan_results: Dict, output_path: str) -> bool:
        """Export scan results to HTML format"""
        try:
            html_content = self._generate_html_report(scan_results)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"Exported scan results to HTML: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export to HTML: {e}")
            return False

    def export_to_pdf(self, scan_results: Dict, output_path: str) -> bool:
        """Export scan results to PDF format"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()

            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#2C3E50'),
                spaceAfter=30,
                alignment=TA_CENTER
            )

            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#34495E'),
                spaceAfter=12,
                spaceBefore=12
            )

            # Title
            story.append(Paragraph("Vulnerability Scan Report", title_style))
            story.append(Spacer(1, 0.2 * inch))

            # Metadata
            metadata = [
                ["Report Generated:", self.timestamp.strftime("%Y-%m-%d %H:%M:%S")],
                ["Target:", scan_results.get('target', 'Unknown')],
                ["Risk Score:", f"{scan_results.get('risk_score', 0):.1f}/10.0"]
            ]
            
            metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
            metadata_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ECF0F1')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(metadata_table)
            story.append(Spacer(1, 0.3 * inch))

            # Device Information
            device_info = scan_results.get('device_info', {})
            story.append(Paragraph("Device Information", heading_style))
            
            device_data = [
                ["Vendor:", device_info.get('vendor', 'Unknown').upper()],
                ["Product:", device_info.get('product', 'Unknown')],
                ["Version:", device_info.get('version', 'Unknown')],
                ["Device Type:", device_info.get('device_type', 'Unknown')],
                ["Confidence:", f"{device_info.get('confidence', 0):.1%}"]
            ]
            
            device_table = Table(device_data, colWidths=[2*inch, 4*inch])
            device_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#E8F4F8')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(device_table)
            story.append(Spacer(1, 0.3 * inch))

            # Vulnerabilities Summary
            vulnerabilities = scan_results.get('vulnerabilities', [])
            story.append(Paragraph(f"Vulnerabilities Found: {len(vulnerabilities)}", heading_style))

            if vulnerabilities:
                # Group by severity
                by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'Low')
                    if severity in by_severity:
                        by_severity[severity].append(vuln)

                # Summary table
                summary_data = [["Severity", "Count"]]
                severity_colors = {
                    'Critical': colors.HexColor('#E74C3C'),
                    'High': colors.HexColor('#E67E22'),
                    'Medium': colors.HexColor('#F39C12'),
                    'Low': colors.HexColor('#27AE60')
                }
                
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    count = len(by_severity[severity])
                    if count > 0:
                        summary_data.append([severity, str(count)])

                summary_table = Table(summary_data, colWidths=[3*inch, 1*inch])
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495E')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                ]))
                story.append(summary_table)
                story.append(PageBreak())

                # Detailed vulnerabilities
                story.append(Paragraph("Detailed Vulnerabilities", heading_style))
                
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    vulns = by_severity[severity]
                    if vulns:
                        story.append(Paragraph(f"{severity} Severity ({len(vulns)})", styles['Heading3']))
                        
                        for i, vuln in enumerate(vulns[:10], 1):  # Limit to 10 per severity
                            vuln_data = [
                                ["ID:", vuln.get('id', 'Unknown')],
                                ["Title:", vuln.get('title', 'No title')],
                                ["CVSS Score:", str(vuln.get('cvss_score', 'N/A'))],
                                ["Component:", vuln.get('affected_component', 'Unknown')]
                            ]
                            
                            vuln_table = Table(vuln_data, colWidths=[1.5*inch, 4.5*inch])
                            vuln_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F8F9FA')),
                                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                                ('FONTSIZE', (0, 0), (-1, -1), 9),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                            ]))
                            story.append(vuln_table)
                            story.append(Spacer(1, 0.1 * inch))

            # Recommendations
            recommendations = scan_results.get('recommendations', [])
            if recommendations:
                story.append(PageBreak())
                story.append(Paragraph("Security Recommendations", heading_style))
                
                for i, rec in enumerate(recommendations[:10], 1):
                    rec_text = f"{i}. {rec.get('recommendation', 'No recommendation')}"
                    story.append(Paragraph(rec_text, styles['Normal']))
                    story.append(Spacer(1, 0.1 * inch))

            # Build PDF
            doc.build(story)

            logger.info(f"Exported scan results to PDF: {output_path}")
            return True

        except ImportError:
            logger.error("reportlab not installed. Install with: pip install reportlab")
            return False
        except Exception as e:
            logger.error(f"Failed to export to PDF: {e}")
            return False

    def _generate_html_report(self, scan_results: Dict) -> str:
        """Generate HTML report content"""
        device_info = scan_results.get('device_info', {})
        vulnerabilities = scan_results.get('vulnerabilities', [])
        recommendations = scan_results.get('recommendations', [])
        risk_score = scan_results.get('risk_score', 0)

        # Group vulnerabilities by severity
        by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in by_severity:
                by_severity[severity].append(vuln)

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {scan_results.get('target', 'Unknown')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f7fa;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 15px;
            margin-bottom: 30px;
        }}
        h2 {{
            color: #34495e;
            margin: 30px 0 15px 0;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
        }}
        .metadata {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .metadata-item {{
            margin: 8px 0;
        }}
        .metadata-label {{
            font-weight: bold;
            display: inline-block;
            width: 150px;
        }}
        .risk-score {{
            font-size: 2em;
            font-weight: bold;
            text-align: center;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .risk-high {{ background: #e74c3c; color: white; }}
        .risk-medium {{ background: #f39c12; color: white; }}
        .risk-low {{ background: #27ae60; color: white; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ecf0f1;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .severity-critical {{ background: #e74c3c; color: white; }}
        .severity-high {{ background: #e67e22; color: white; }}
        .severity-medium {{ background: #f39c12; color: white; }}
        .severity-low {{ background: #27ae60; color: white; }}
        .vulnerability {{
            background: #f8f9fa;
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid #3498db;
            border-radius: 4px;
        }}
        .vuln-title {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 8px;
        }}
        .vuln-detail {{
            margin: 5px 0;
            color: #555;
        }}
        .recommendations {{
            background: #e8f4f8;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .recommendation-item {{
            margin: 12px 0;
            padding-left: 20px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Vulnerability Scan Report</h1>
        
        <div class="metadata">
            <div class="metadata-item">
                <span class="metadata-label">Report Generated:</span>
                {self.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Target:</span>
                {scan_results.get('target', 'Unknown')}
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Tool Version:</span>
                Router Security Tool v1.0
            </div>
        </div>

        <div class="risk-score {'risk-high' if risk_score >= 7.0 else 'risk-medium' if risk_score >= 4.0 else 'risk-low'}">
            Risk Score: {risk_score:.1f} / 10.0
        </div>

        <h2>📱 Device Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Vendor</td><td>{device_info.get('vendor', 'Unknown').upper()}</td></tr>
            <tr><td>Product</td><td>{device_info.get('product', 'Unknown')}</td></tr>
            <tr><td>Version</td><td>{device_info.get('version', 'Unknown')}</td></tr>
            <tr><td>Device Type</td><td>{device_info.get('device_type', 'Unknown')}</td></tr>
            <tr><td>Confidence</td><td>{device_info.get('confidence', 0):.1%}</td></tr>
        </table>

        <h2>🔍 Vulnerabilities Found: {len(vulnerabilities)}</h2>
        
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td><span class="severity-badge severity-critical">Critical</span></td><td>{len(by_severity['Critical'])}</td></tr>
            <tr><td><span class="severity-badge severity-high">High</span></td><td>{len(by_severity['High'])}</td></tr>
            <tr><td><span class="severity-badge severity-medium">Medium</span></td><td>{len(by_severity['Medium'])}</td></tr>
            <tr><td><span class="severity-badge severity-low">Low</span></td><td>{len(by_severity['Low'])}</td></tr>
        </table>

        <h2>📋 Detailed Vulnerabilities</h2>
"""

        for severity in ['Critical', 'High', 'Medium', 'Low']:
            vulns = by_severity[severity]
            if vulns:
                html += f"<h3>{severity} Severity ({len(vulns)})</h3>"
                for vuln in vulns[:20]:  # Limit to 20 per severity
                    html += f"""
        <div class="vulnerability">
            <div class="vuln-title">{vuln.get('id', 'Unknown')}: {vuln.get('title', 'No title')}</div>
            <div class="vuln-detail"><strong>CVSS Score:</strong> {vuln.get('cvss_score', 'N/A')}</div>
            <div class="vuln-detail"><strong>Component:</strong> {vuln.get('affected_component', 'Unknown')}</div>
            <div class="vuln-detail"><strong>Description:</strong> {vuln.get('description', 'No description')[:200]}...</div>
        </div>
"""

        if recommendations:
            html += """
        <h2>💡 Security Recommendations</h2>
        <div class="recommendations">
"""
            for i, rec in enumerate(recommendations[:10], 1):
                html += f"""
            <div class="recommendation-item">
                <strong>{i}.</strong> {rec.get('recommendation', 'No recommendation')}<br>
                <small>Priority: {rec.get('priority', 0)}/4 | Affects: {', '.join(rec.get('affected_components', [])[:3])}</small>
            </div>
"""
            html += "</div>"

        html += f"""
        <div class="footer">
            <p>Generated by Router Security Tool v1.0 | {self.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
"""
        return html
