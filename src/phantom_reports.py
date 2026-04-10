#!/usr/bin/env python3
"""
PHANTOM REPORTS ENGINE - Report Generation (PDF/HTML/JSON)
Generates professional penetration testing reports
"""

import json
import os
import datetime
from pathlib import Path

REPORTS_DIR = os.path.expanduser("~/.phantom/reports")
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR, exist_ok=True)


class PhantomReporter:
    """Report generation engine for PHANTOM"""

    def __init__(self, scan_id=None, scan_data=None):
        self.scan_id = scan_id
        self.scan_data = scan_data or {}
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_json_report(self, output_path=None):
        """Generate JSON report"""
        if not output_path:
            output_path = os.path.join(
                REPORTS_DIR,
                f"scan_report_{self.timestamp}.json"
            )

        try:
            with open(output_path, "w") as f:
                json.dump(self.scan_data, f, indent=2, default=str)
            print(f"✓ JSON report generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"❌ JSON report generation failed: {e}")
            return None

    def generate_html_report(self, output_path=None):
        """Generate HTML report"""
        if not output_path:
            output_path = os.path.join(
                REPORTS_DIR,
                f"scan_report_{self.timestamp}.html"
            )

        html_content = self._build_html()

        try:
            with open(output_path, "w") as f:
                f.write(html_content)
            print(f"✓ HTML report generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"❌ HTML report generation failed: {e}")
            return None

    def generate_pdf_report(self, output_path=None):
        """Generate PDF report (requires reportlab)"""
        if not output_path:
            output_path = os.path.join(
                REPORTS_DIR,
                f"scan_report_{self.timestamp}.pdf"
            )

        if not REPORTLAB_AVAILABLE:
            print("⚠ reportlab not installed. Install with: pip3 install reportlab")
            return None

        try:
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()

            # Custom styles
            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Heading1"],
                fontSize=24,
                textColor=colors.HexColor("#00FF88"),
                spaceAfter=30,
                alignment=1,
            )

            # Title
            elements.append(Paragraph("PHANTOM PENETRATION TEST REPORT", title_style))
            elements.append(Spacer(1, 0.2 * inch))

            # Scan summary
            scan_info = self.scan_data.get("scan", {})
            summary_text = f"""
            <b>Scan ID:</b> {scan_info.get('scan_id', 'N/A')}<br/>
            <b>Target:</b> {scan_info.get('target', 'N/A')}<br/>
            <b>Scan Type:</b> {scan_info.get('scan_type', 'N/A')}<br/>
            <b>Date:</b> {scan_info.get('timestamp', 'N/A')}<br/>
            <b>Status:</b> {scan_info.get('status', 'N/A')}<br/>
            <b>Risk Level:</b> {scan_info.get('risk_level', 'N/A')}<br/>
            """
            elements.append(Paragraph(summary_text, styles["Normal"]))
            elements.append(Spacer(1, 0.3 * inch))

            # Vulnerabilities
            vulns = self.scan_data.get("vulnerabilities", [])
            if vulns:
                elements.append(Paragraph("VULNERABILITIES FOUND", styles["Heading2"]))
                elements.append(Spacer(1, 0.1 * inch))

                vuln_data = [["Type", "Severity", "Description", "CVE"]]
                for vuln in vulns[:10]:  # Limit to first 10
                    vuln_data.append([
                        vuln.get("vuln_type", "N/A")[:20],
                        vuln.get("severity", "N/A"),
                        vuln.get("description", "N/A")[:40],
                        vuln.get("cve_id", "N/A"),
                    ])

                table = Table(vuln_data)
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#00FF88")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0a0d0f")),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#e0e8f0")),
                    ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#1e2d3d")),
                ]))
                elements.append(table)
                elements.append(Spacer(1, 0.3 * inch))

            # Hosts discovered
            hosts = self.scan_data.get("hosts", [])
            if hosts:
                elements.append(PageBreak())
                elements.append(Paragraph("HOSTS DISCOVERED", styles["Heading2"]))
                elements.append(Spacer(1, 0.1 * inch))

                host_data = [["IP Address", "Hostname", "OS", "Open Ports"]]
                for host in hosts[:10]:
                    host_data.append([
                        host.get("ip_address", "N/A"),
                        host.get("hostname", "N/A"),
                        host.get("os", "N/A")[:20],
                        host.get("open_ports", "N/A")[:30],
                    ])

                table = Table(host_data)
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#00FF88")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#1e2d3d")),
                ]))
                elements.append(table)

            # Build PDF
            doc.build(elements)
            print(f"✓ PDF report generated: {output_path}")
            return output_path

        except Exception as e:
            print(f"❌ PDF report generation failed: {e}")
            return None

    def generate_all_reports(self):
        """Generate all report formats"""
        results = {
            "json": self.generate_json_report(),
            "html": self.generate_html_report(),
        }

        if REPORTLAB_AVAILABLE:
            results["pdf"] = self.generate_pdf_report()
        else:
            print("⚠ Skipping PDF (reportlab not installed)")
            results["pdf"] = None

        return results

    def _build_html(self):
        """Build HTML report content"""
        scan_info = self.scan_data.get("scan", {})
        vulns = self.scan_data.get("vulnerabilities", [])
        hosts = self.scan_data.get("hosts", [])
        exploits = self.scan_data.get("exploits", [])

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PHANTOM Penetration Test Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            background: #0a0d0f;
            color: #e0e8f0;
            font-family: 'Courier New', monospace;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #0f1318;
            padding: 30px;
            border: 1px solid #1e2d3d;
            border-radius: 4px;
        }}
        
        .header {{
            text-align: center;
            border-bottom: 2px solid #00ff88;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            color: #00ff88;
            letter-spacing: 3px;
            font-size: 28px;
            margin-bottom: 10px;
        }}
        
        .header p {{
            color: #999;
            font-size: 12px;
        }}
        
        .scan-summary {{
            background: #15191e;
            border-left: 4px solid #00ff88;
            padding: 15px;
            margin-bottom: 30px;
            border-radius: 4px;
        }}
        
        .scan-summary div {{
            display: inline-block;
            margin-right: 40px;
            margin-bottom: 10px;
        }}
        
        .scan-summary label {{
            color: #999;
            font-size: 12px;
            display: block;
        }}
        
        .scan-summary span {{
            color: #00ff88;
            font-weight: bold;
            font-size: 14px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #00ff88;
            border-bottom: 1px solid #1e2d3d;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 18px;
            letter-spacing: 2px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        
        th {{
            background: #00ff88;
            color: #0a0d0f;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }}
        
        td {{
            padding: 10px;
            border-bottom: 1px solid #1e2d3d;
        }}
        
        tr:hover {{
            background: #15191e;
        }}
        
        .severity-critical {{
            color: #ff4444;
            font-weight: bold;
        }}
        
        .severity-high {{
            color: #ff8800;
        }}
        
        .severity-medium {{
            color: #ffcc00;
        }}
        
        .severity-low {{
            color: #00ff88;
        }}
        
        .footer {{
            text-align: center;
            border-top: 1px solid #1e2d3d;
            padding-top: 20px;
            margin-top: 40px;
            color: #666;
            font-size: 12px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-box {{
            background: #15191e;
            padding: 15px;
            text-align: center;
            border-radius: 4px;
            border: 1px solid #1e2d3d;
        }}
        
        .stat-box .number {{
            font-size: 24px;
            color: #00ff88;
            font-weight: bold;
        }}
        
        .stat-box .label {{
            font-size: 12px;
            color: #999;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>◈ PHANTOM FRAMEWORK</h1>
            <p>Penetration Testing Report</p>
        </div>
        
        <div class="scan-summary">
            <div><label>SCAN ID</label><span>{scan_info.get('scan_id', 'N/A')}</span></div>
            <div><label>TARGET</label><span>{scan_info.get('target', 'N/A')}</span></div>
            <div><label>TYPE</label><span>{scan_info.get('scan_type', 'N/A')}</span></div>
            <div><label>DATE</label><span>{scan_info.get('timestamp', 'N/A')}</span></div>
            <div><label>STATUS</label><span>{scan_info.get('status', 'N/A')}</span></div>
            <div><label>RISK</label><span>{scan_info.get('risk_level', 'N/A')}</span></div>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="number">{len(vulns)}</div>
                <div class="label">VULNERABILITIES</div>
            </div>
            <div class="stat-box">
                <div class="number">{len(hosts)}</div>
                <div class="label">HOSTS</div>
            </div>
            <div class="stat-box">
                <div class="number">{len(exploits)}</div>
                <div class="label">EXPLOITS</div>
            </div>
            <div class="stat-box">
                <div class="number">{max(v.get('confidence', 0) for v in vulns) if vulns else 0}%</div>
                <div class="label">CONFIDENCE</div>
            </div>
        </div>
"""

        # Vulnerabilities
        if vulns:
            html += """
        <div class="section">
            <h2>VULNERABILITIES DISCOVERED</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Remediation</th>
                </tr>
"""
            for vuln in vulns:
                severity = vuln.get("severity", "low").lower()
                html += f"""
                <tr>
                    <td>{vuln.get('vuln_type', 'N/A')}</td>
                    <td>{vuln.get('description', 'N/A')}</td>
                    <td><span class="severity-{severity}">{severity.upper()}</span></td>
                    <td>{vuln.get('confidence', 'N/A')}%</td>
                    <td>{vuln.get('remediation', 'N/A')}</td>
                </tr>
"""
            html += """
            </table>
        </div>
"""

        # Hosts
        if hosts:
            html += """
        <div class="section">
            <h2>HOSTS DISCOVERED</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>OS</th>
                    <th>Open Ports</th>
                    <th>Services</th>
                </tr>
"""
            for host in hosts:
                html += f"""
                <tr>
                    <td>{host.get('ip_address', 'N/A')}</td>
                    <td>{host.get('hostname', 'N/A')}</td>
                    <td>{host.get('os', 'N/A')}</td>
                    <td>{host.get('open_ports', 'N/A')}</td>
                    <td>{host.get('services', 'N/A')}</td>
                </tr>
"""
            html += """
            </table>
        </div>
"""

        # Exploits
        if exploits:
            html += """
        <div class="section">
            <h2>RECOMMENDED EXPLOITS</h2>
            <table>
                <tr>
                    <th>Vulnerability</th>
                    <th>Exploit</th>
                    <th>CVSS Score</th>
                </tr>
"""
            for exploit in exploits:
                html += f"""
                <tr>
                    <td>{exploit.get('vulnerability', 'N/A')}</td>
                    <td>{exploit.get('exploit_name', 'N/A')}</td>
                    <td>{exploit.get('cvss_score', 'N/A')}</td>
                </tr>
"""
            html += """
            </table>
        </div>
"""

        html += """
        <div class="footer">
            <p>Generated by PHANTOM Framework v2.0</p>
            <p>Use for authorized security testing only</p>
        </div>
    </div>
</body>
</html>
"""
        return html


# ─── HELPER FUNCTIONS ───────────────────────────

def generate_report(scan_data, formats=["json", "html"]):
    """Quick report generation"""
    generator = PhantomReportGenerator(scan_data)

    results = {}
    for fmt in formats:
        if fmt.lower() == "json":
            results[fmt] = generator.generate_json_report()
        elif fmt.lower() == "html":
            results[fmt] = generator.generate_html_report()
        elif fmt.lower() == "pdf":
            results[fmt] = generator.generate_pdf_report()

    return results


if __name__ == "__main__":
    print("✓ Reports module ready")
    print(f"✓ Reports directory: {REPORTS_DIR}")
