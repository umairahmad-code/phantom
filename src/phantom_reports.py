#!/usr/bin/env python3
"""
PHANTOM REPORTS ENGINE - Report Generation (PDF/HTML/JSON)
Generates professional penetration testing reports
"""

import json
import os
import datetime
from pathlib import Path
from html import escape as html_escape

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import phantom_config as config
    import phantom_findings as findings_mod
    import phantom_ce as ce
    import phantom_frameworks as frameworks
    import phantom_branding as branding
    import phantom_retest as retest
    import phantom_owasp as owasp
    import phantom_pdf as pdf_engine
except ImportError:  # imported as src.phantom_reports
    from src import phantom_config as config
    from src import phantom_findings as findings_mod
    from src import phantom_ce as ce
    from src import phantom_frameworks as frameworks
    from src import phantom_branding as branding
    from src import phantom_retest as retest
    from src import phantom_owasp as owasp
    from src import phantom_pdf as pdf_engine

REPORTS_DIR = config.reports_dir()
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR, exist_ok=True)


class PhantomReporter:
    """Report generation engine for PHANTOM"""

    def __init__(self, scan_id=None, scan_data=None, engagement=None):
        self.scan_id = scan_id
        self.scan_data = scan_data or {}
        self.engagement = engagement or {}
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── Engagement / branding metadata ────────────────────────────
    def _eng(self, key, default=""):
        """Read an engagement/branding field with a safe default."""
        return self.engagement.get(key, default) or default

    def _ce_assessment(self):
        """Map findings onto the Cyber Essentials controls (cached)."""
        if getattr(self, "_ce_cache", None) is None:
            self._ce_cache = self._framework_assessment("cyber_essentials")
        return self._ce_cache

    def _framework_assessment(self, framework_id):
        """Assess findings against any supported compliance framework."""
        findings = self._get_findings()
        target = self.scan_data.get("scan", {}).get("target", "")
        scope = self.engagement.get("scope") or None
        internal = self.engagement.get("internal_results")
        a = frameworks.assess(framework_id, findings, target=target,
                              scope=scope, internal_results=internal)
        # Optional email/domain spoofing section (if a domain was provided).
        domain = self.engagement.get("domain") or target
        if self.engagement.get("include_email") and domain:
            try:
                import phantom_email_security as emailsec
                a["email"] = emailsec.assess_email_security(domain)
            except Exception:
                pass
        return a

    def generate_json_report(self, output_path=None):
        """Generate JSON report"""
        if not output_path:
            output_path = os.path.join(
                REPORTS_DIR,
                f"scan_report_{self.timestamp}.json"
            )

        try:
            findings = self._get_findings()
            target = self.scan_data.get("scan", {}).get("target", "")
            payload = dict(self.scan_data)
            payload["explained_findings"] = findings
            payload["client_summary"] = findings_mod.client_summary(findings, target)
            payload["severity_counts"] = findings_mod.severity_counts(findings)
            with open(output_path, "w") as f:
                json.dump(payload, f, indent=2, default=str)
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
        """Generate the technical PDF report.

        Preferred path: render the full branded HTML report with headless
        Chrome, so the PDF matches the HTML deliverable exactly (branding,
        CVSS/OWASP, severity styling). Falls back to the reportlab layout only
        when no browser is available.
        """
        if not output_path:
            output_path = os.path.join(
                REPORTS_DIR,
                f"scan_report_{self.timestamp}.pdf"
            )

        # 1) Best quality: render the HTML deliverable via headless Chrome.
        if pdf_engine.available():
            result = pdf_engine.html_string_to_pdf(self._build_html(), output_path)
            if result:
                print(f"✓ PDF report generated (Chrome): {result}")
                return result
            print("⚠ Chrome PDF render failed; trying reportlab fallback...")

        # 2) Fallback: legacy reportlab layout.
        if not REPORTLAB_AVAILABLE:
            print("⚠ No PDF engine available. Install Google Chrome (preferred) "
                  "or run: pip3 install reportlab")
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
            <b>Assessment ID:</b> {scan_info.get('scan_id', 'N/A')}<br/>
            <b>Target:</b> {scan_info.get('target', 'N/A')}<br/>
            <b>Assessment Type:</b> {scan_info.get('scan_type', 'N/A')}<br/>
            <b>Timestamp:</b> {scan_info.get('timestamp', 'N/A')}<br/>
            <b>Execution Status:</b> {scan_info.get('status', 'N/A')}<br/>
            <b>Risk Classification:</b> {scan_info.get('risk_level', 'N/A')}<br/>
            """
            elements.append(Paragraph(summary_text, styles["Normal"]))
            elements.append(Spacer(1, 0.3 * inch))

            elements.append(Paragraph("TECHNICAL INTERPRETATION", styles["Heading2"]))
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph(self._technical_summary_text(), styles["Normal"]))
            elements.append(Spacer(1, 0.3 * inch))

            # Vulnerabilities
            vulns = self.scan_data.get("vulnerabilities", [])
            if vulns:
                elements.append(Paragraph("OBSERVED VULNERABILITIES", styles["Heading2"]))
                elements.append(Spacer(1, 0.1 * inch))

                vuln_data = [["Class", "Severity", "Technical Description", "CVE"]]
                for vuln in vulns[:10]:  # Limit to first 10
                    vuln_data.append([
                        vuln.get("vuln_type", "N/A")[:20],
                        vuln.get("severity", "N/A"),
                        self._technical_vuln_description(vuln)[:40],
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
                elements.append(Paragraph("OBSERVED SERVICES AND HOSTS", styles["Heading2"]))
                elements.append(Spacer(1, 0.1 * inch))

                host_data = [["Address", "Hostname", "OS Fingerprint", "Listening Services"]]
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

    # ════════════════════════════════════════════════════════════════
    #  CYBER ESSENTIALS READINESS REPORT  (client-facing deliverable)
    # ════════════════════════════════════════════════════════════════

    def generate_ce_report(self, output_path=None):
        """
        Generate the Cyber Essentials Readiness Report (HTML).

        This is the sales-grade, client-facing deliverable: a light,
        print-ready page that maps the scan findings onto the five Cyber
        Essentials control areas with a plain-language verdict and a
        prioritised remediation roadmap.
        """
        if not output_path:
            client = self._slug(self._eng("client_name", "client"))
            output_path = os.path.join(
                REPORTS_DIR,
                f"cyber_essentials_readiness_{client}_{self.timestamp}.html",
            )

        html_content = self._build_assessment_html(self._ce_assessment())
        try:
            with open(output_path, "w") as f:
                f.write(html_content)
            print(f"✓ Cyber Essentials readiness report generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"❌ CE report generation failed: {e}")
            return None

    def generate_framework_report(self, framework_id="cyber_essentials", output_path=None):
        """Generate a readiness report for any supported framework."""
        a = self._framework_assessment(framework_id)
        fname = a.get("framework", {}).get("id", framework_id)
        if not output_path:
            client = self._slug(self._eng("client_name", "client"))
            output_path = os.path.join(
                REPORTS_DIR, f"{fname}_readiness_{client}_{self.timestamp}.html")
        html_content = self._build_assessment_html(a)
        try:
            with open(output_path, "w") as f:
                f.write(html_content)
            label = a.get("framework", {}).get("name", framework_id)
            print(f"✓ {label} report generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"❌ {framework_id} report generation failed: {e}")
            return None

    def generate_exec_summary(self, framework_id="cyber_essentials", output_path=None):
        """One-page executive summary — for the busy business owner."""
        a = self._framework_assessment(framework_id)
        if not output_path:
            client = self._slug(self._eng("client_name", "client"))
            output_path = os.path.join(
                REPORTS_DIR, f"exec_summary_{client}_{self.timestamp}.html")
        html_content = self._build_exec_summary_html(a)
        try:
            with open(output_path, "w") as f:
                f.write(html_content)
            print(f"✓ Executive summary generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"❌ Exec summary generation failed: {e}")
            return None

    def generate_retest_report(self, diff, output_path=None):
        """Change/retest report from a phantom_retest.diff_findings result."""
        if not output_path:
            client = self._slug(self._eng("client_name", "client"))
            output_path = os.path.join(
                REPORTS_DIR, f"retest_{client}_{self.timestamp}.html")
        html_content = self._build_retest_html(diff)
        try:
            with open(output_path, "w") as f:
                f.write(html_content)
            print(f"✓ Retest report generated: {output_path}")
            return output_path
        except Exception as e:
            print(f"❌ Retest report generation failed: {e}")
            return None

    # ── Client-grade PDF deliverables (rendered from the branded HTML) ──
    def _html_to_pdf(self, html_content, output_path):
        """Render a built HTML deliverable to PDF via headless Chrome."""
        if not pdf_engine.available():
            print("⚠ No browser found for PDF. Install Google Chrome, or set "
                  "PHANTOM_CHROME=/path/to/chrome. (HTML report is still produced.)")
            return None
        result = pdf_engine.html_string_to_pdf(html_content, output_path)
        if result:
            print(f"✓ PDF deliverable generated: {result}")
        else:
            print("❌ PDF render failed.")
        return result

    def generate_framework_report_pdf(self, framework_id="cyber_essentials",
                                      output_path=None):
        """Client-grade PDF of a framework readiness deliverable."""
        a = self._framework_assessment(framework_id)
        fname = a.get("framework", {}).get("id", framework_id)
        if not output_path:
            client = self._slug(self._eng("client_name", "client"))
            output_path = os.path.join(
                REPORTS_DIR, f"{fname}_readiness_{client}_{self.timestamp}.pdf")
        return self._html_to_pdf(self._build_assessment_html(a), output_path)

    def generate_ce_report_pdf(self, output_path=None):
        """Client-grade PDF of the Cyber Essentials readiness report."""
        return self.generate_framework_report_pdf("cyber_essentials", output_path)

    def generate_exec_summary_pdf(self, framework_id="cyber_essentials",
                                  output_path=None):
        """Client-grade PDF of the one-page executive summary."""
        a = self._framework_assessment(framework_id)
        if not output_path:
            client = self._slug(self._eng("client_name", "client"))
            output_path = os.path.join(
                REPORTS_DIR, f"exec_summary_{client}_{self.timestamp}.pdf")
        return self._html_to_pdf(self._build_exec_summary_html(a), output_path)

    def generate_retest_report_pdf(self, diff, output_path=None):
        """Client-grade PDF of a retest / change-tracking report."""
        if not output_path:
            client = self._slug(self._eng("client_name", "client"))
            output_path = os.path.join(
                REPORTS_DIR, f"retest_{client}_{self.timestamp}.pdf")
        return self._html_to_pdf(self._build_retest_html(diff), output_path)

    @staticmethod
    def _slug(text):
        keep = "".join(c if c.isalnum() else "_" for c in str(text).lower())
        return "_".join(part for part in keep.split("_") if part) or "client"

    # Status → CSS class + display label
    _CE_STATUS_CLASS = {
        ce.PASS: ("ok", "PASS"),
        ce.ACTION: ("bad", "ACTION REQUIRED"),
        ce.ADVISORY: ("warn", "ADVISORY"),
        ce.VERIFY: ("info", "VERIFY INTERNALLY"),
    }
    _CE_VERDICT_CLASS = {
        "NOT YET READY": "bad",
        "ON TRACK": "warn",
        "LIKELY TO PASS": "ok",
    }

    def _brand(self):
        """Resolve branding (saved profile merged with per-engagement overrides)."""
        b = dict(branding.load())
        for k in ("company_name", "primary_color", "accent_color", "footer_note"):
            if self.engagement.get(k):
                b[k] = self.engagement[k]
        b["logo_uri"] = self.engagement.get("logo_uri") or \
            branding.logo_data_uri(b.get("logo_path", ""))
        return b

    def _build_assessment_html(self, a):
        e = html_escape
        b = self._brand()
        fw = a.get("framework", {"name": "Cyber Essentials",
                                 "subtitle": "5 technical controls"})
        fw_name = e(fw.get("name", "Security"))
        fw_sub = e(fw.get("subtitle", ""))
        primary = e(b.get("primary_color", "#0f2440"))
        accent = e(b.get("accent_color", "#0ea5a5"))
        logo_uri = b.get("logo_uri", "")
        logo_html = (f'<img src="{e(logo_uri)}" alt="logo" class="brand-logo">'
                     if logo_uri else "")
        footer_note = e(b.get("footer_note", ""))

        client = e(self._eng("client_name", "Client Organisation"))
        assessor = e(b.get("company_name", "PHANTOM Security"))
        prepared_by = e(self._eng("prepared_by", assessor))
        date_str = e(self._eng("date",
                     datetime.datetime.now().strftime("%d %B %Y")))
        ref = e(self._eng("report_ref", f"{fw.get('id','CE').upper()[:4]}-{self.timestamp}"))
        auth_ref = e(self._eng("authorization_ref",
                     "Written authorisation on file"))
        scope = a.get("scope") or []
        scope_html = ", ".join(e(str(s)) for s in scope) if scope else \
            e(self.scan_data.get("scan", {}).get("target", "In-scope systems"))

        verdict = a["verdict"]
        v_class = self._CE_VERDICT_CLASS.get(verdict["status"], "info")
        counts = a["counts"]

        # ── Control summary rows ───────────────────────────────────
        control_rows = ""
        for c in a["controls"]:
            scls, slabel = self._CE_STATUS_CLASS.get(c["status"], ("info", c["status"]))
            n = len(c["findings"])
            detail = f"{n} item(s) to address" if n else (
                "Verify on devices" if not c["external"] else "No external issues")
            control_rows += f"""
                <tr>
                    <td class="ctrl-name">{e(c['name'])}</td>
                    <td><span class="pill {scls}">{e(slabel)}</span></td>
                    <td class="muted">{e(detail)}</td>
                </tr>"""

        # ── Per-control detail sections ────────────────────────────
        control_detail = ""
        for i, c in enumerate(a["controls"], 1):
            scls, slabel = self._CE_STATUS_CLASS.get(c["status"], ("info", c["status"]))
            findings_html = ""
            if c["findings"]:
                for f in c["findings"]:
                    fcls, flabel = self._CE_STATUS_CLASS.get(f["status"], ("info", f["status"]))
                    ev = (f'<div class="evidence">{e(str(f["evidence"]))}</div>'
                          if f.get("evidence") else "")
                    findings_html += f"""
                    <div class="finding">
                        <div class="finding-top">
                            <span class="f-title">{e(str(f['title']))}</span>
                            <span class="tag sev-{e(f['severity'])}">{e(f['severity'].upper())}</span>
                            <span class="pill {fcls} sm">{e(flabel)}</span>
                        </div>
                        <p class="f-plain">{e(str(f['plain']))}</p>
                        <p class="f-fix"><strong>Fix:</strong> {e(str(f['remediation']))}</p>
                        {ev}
                    </div>"""
            note_html = (f'<p class="ctrl-note">{e(str(c["note"]))}</p>'
                         if c.get("note") else "")
            control_detail += f"""
            <div class="ctrl-block">
                <div class="ctrl-head">
                    <h3>{i}. {e(c['name'])}</h3>
                    <span class="pill {scls}">{e(slabel)}</span>
                </div>
                <p class="ctrl-about">{e(c['about'])}</p>
                {findings_html}
                {note_html}
            </div>"""

        # ── Remediation roadmap ────────────────────────────────────
        if a["roadmap"]:
            roadmap_rows = ""
            for item in a["roadmap"]:
                roadmap_rows += f"""
                    <tr>
                        <td class="num">{item['priority']}</td>
                        <td><span class="tag sev-{e(item['severity'])}">{e(item['severity'].upper())}</span></td>
                        <td>{e(str(item['action']))}</td>
                        <td class="muted">{e(str(item['control']))}</td>
                    </tr>"""
            roadmap_html = f"""
            <div class="card">
                <h2>Priority Remediation Roadmap</h2>
                <p class="lead">Address these in order. Once resolved, the systems
                should meet the externally-checkable Cyber Essentials requirements.</p>
                <table class="roadmap">
                    <thead><tr><th>#</th><th>Severity</th><th>Action</th><th>Control area</th></tr></thead>
                    <tbody>{roadmap_rows}</tbody>
                </table>
            </div>"""
        else:
            roadmap_html = f"""
            <div class="card">
                <h2>Priority Remediation Roadmap</h2>
                <p class="lead ok-text">No blocking issues were identified externally.
                Confirm the internal controls listed above to be assessment-ready.</p>
            </div>"""

        # ── Optional email/domain spoofing section ─────────────────
        email_html = ""
        email = a.get("email")
        if email:
            rows = ""
            for f in email.get("findings", []):
                sev = e(str(f.get("severity", "info")))
                rows += f"""
                <div class="finding">
                    <div class="finding-top">
                        <span class="f-title">{e(str(f.get('title','')))}</span>
                        <span class="tag sev-{sev}">{sev.upper()}</span>
                    </div>
                    <p class="f-plain">{e(str(f.get('plain','')))}</p>
                    <p class="f-fix"><strong>Fix:</strong> {e(str(f.get('remediation','')))}</p>
                </div>"""
            spoof = ("⚠ This domain can currently be spoofed in phishing emails."
                     if email.get("spoofable") else
                     "✓ Basic email spoofing protections are in place.")
            email_html = f"""
    <div class="card">
        <h2>Email &amp; Domain Security</h2>
        <p class="lead">Can criminals send phishing emails that look like they
        come from <strong>{e(str(email.get('domain','')))}</strong>? (Grade:
        <strong>{e(str(email.get('score',{}).get('grade','?')))}</strong>) {spoof}</p>
        {rows}
    </div>"""

        # ── Optional internal-controls confirmation note ───────────
        internal_html = ""
        internal = a.get("internal")
        if internal:
            s = internal.get("summary", {})
            internal_html = f"""
    <div class="card">
        <h2>Internal Controls (device-confirmed)</h2>
        <p class="lead">Confirmed on <strong>{e(str(internal.get('host','the device')))}</strong>
        ({e(str(internal.get('os','')))}): {s.get('passed',0)} passed,
        {s.get('failed',0)} failed, {s.get('unknown',0)} unknown.</p>
    </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{fw_name} Readiness Report — {client}</title>
<style>
    :root {{
        --navy:{primary}; --navy2:#1b3a5c; --teal:{accent}; --ink:#1a2332;
        --muted:#5b6b7f; --line:#e2e8f0; --bg:#f4f6f9; --card:#ffffff;
        --ok:#188a5a; --ok-bg:#e6f6ee; --warn:#b7791f; --warn-bg:#fdf6e3;
        --bad:#c0392b; --bad-bg:#fdecea; --info:#2a6fb0; --info-bg:#e8f1fa;
    }}
    .brand-logo {{ max-height:48px; max-width:200px; margin-bottom:16px;
        background:#fff; padding:4px 8px; border-radius:4px; }}
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{
        background:var(--bg); color:var(--ink);
        font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
        line-height:1.6; font-size:15px; padding:32px 16px;
    }}
    .page {{ max-width:900px; margin:0 auto; }}
    .card {{
        background:var(--card); border:1px solid var(--line);
        border-radius:10px; padding:28px 32px; margin-bottom:22px;
        box-shadow:0 1px 3px rgba(15,36,64,.04);
    }}
    /* Cover */
    .cover {{
        background:linear-gradient(135deg,var(--navy),var(--navy2));
        color:#fff; border:none; padding:38px 34px;
    }}
    .cover .eyebrow {{ color:var(--teal); font-weight:700; letter-spacing:2px;
        font-size:12px; text-transform:uppercase; margin-bottom:10px; }}
    .cover h1 {{ font-size:30px; line-height:1.25; margin-bottom:6px; font-weight:700; }}
    .cover .client {{ font-size:20px; color:#cfe0f0; margin-bottom:22px; }}
    .cover .meta {{ display:grid; grid-template-columns:repeat(2,1fr);
        gap:12px 28px; border-top:1px solid rgba(255,255,255,.15); padding-top:18px; }}
    .cover .meta div label {{ display:block; color:#9fb6cf; font-size:11px;
        text-transform:uppercase; letter-spacing:1px; margin-bottom:2px; }}
    .cover .meta div span {{ color:#fff; font-weight:600; font-size:14px; }}
    /* Verdict */
    .verdict {{ display:flex; align-items:center; gap:22px; flex-wrap:wrap; }}
    .verdict .stamp {{
        font-size:20px; font-weight:800; letter-spacing:1px; padding:14px 22px;
        border-radius:10px; white-space:nowrap;
    }}
    .verdict .stamp.ok  {{ background:var(--ok-bg);  color:var(--ok);  border:2px solid var(--ok); }}
    .verdict .stamp.warn{{ background:var(--warn-bg);color:var(--warn);border:2px solid var(--warn); }}
    .verdict .stamp.bad {{ background:var(--bad-bg); color:var(--bad); border:2px solid var(--bad); }}
    .verdict .stamp.info{{ background:var(--info-bg);color:var(--info);border:2px solid var(--info); }}
    .verdict .headline {{ flex:1; min-width:240px; color:var(--ink); font-size:15px; }}
    h2 {{ font-size:19px; color:var(--navy); margin-bottom:14px;
        padding-bottom:8px; border-bottom:2px solid var(--line); }}
    h3 {{ font-size:16px; color:var(--navy); }}
    .lead {{ color:var(--muted); margin-bottom:16px; }}
    .ok-text {{ color:var(--ok); }}
    /* Stat tiles */
    .tiles {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-top:6px; }}
    .tile {{ text-align:center; background:var(--bg); border:1px solid var(--line);
        border-radius:8px; padding:14px 6px; }}
    .tile .n {{ font-size:26px; font-weight:800; }}
    .tile .l {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }}
    .tile.critical .n {{ color:#c0392b; }} .tile.high .n {{ color:#e67e22; }}
    .tile.medium .n {{ color:#b7791f; }} .tile.low .n {{ color:#188a5a; }}
    .tile.info .n {{ color:#2a6fb0; }}
    /* Pills / tags */
    .pill {{ display:inline-block; font-size:12px; font-weight:700; padding:4px 11px;
        border-radius:20px; letter-spacing:.3px; white-space:nowrap; }}
    .pill.sm {{ font-size:10px; padding:2px 8px; }}
    .pill.ok  {{ background:var(--ok-bg);  color:var(--ok); }}
    .pill.warn{{ background:var(--warn-bg);color:var(--warn); }}
    .pill.bad {{ background:var(--bad-bg); color:var(--bad); }}
    .pill.info{{ background:var(--info-bg);color:var(--info); }}
    .tag {{ display:inline-block; font-size:10px; font-weight:700; padding:2px 8px;
        border-radius:4px; color:#fff; letter-spacing:.5px; }}
    .sev-critical {{ background:#c0392b; }} .sev-high {{ background:#e67e22; }}
    .sev-medium {{ background:#b7791f; }} .sev-low {{ background:#188a5a; }}
    .sev-info {{ background:#2a6fb0; }}
    /* Tables */
    table {{ width:100%; border-collapse:collapse; }}
    .summary td, .roadmap td, .roadmap th {{ padding:11px 10px; border-bottom:1px solid var(--line);
        text-align:left; vertical-align:top; }}
    .roadmap th {{ font-size:12px; text-transform:uppercase; letter-spacing:.5px;
        color:var(--muted); border-bottom:2px solid var(--line); }}
    .summary .ctrl-name {{ font-weight:600; color:var(--navy); }}
    .muted {{ color:var(--muted); font-size:13px; }}
    .num {{ font-weight:800; color:var(--navy); width:34px; }}
    /* Control detail */
    .ctrl-block {{ padding:18px 0; border-bottom:1px solid var(--line); }}
    .ctrl-block:last-child {{ border-bottom:none; }}
    .ctrl-head {{ display:flex; justify-content:space-between; align-items:center; gap:12px; }}
    .ctrl-about {{ color:var(--muted); font-size:14px; margin:6px 0 10px; }}
    .ctrl-note {{ background:var(--info-bg); color:#245b8c; border-radius:6px;
        padding:10px 12px; font-size:13px; margin-top:8px; }}
    .finding {{ background:var(--bg); border:1px solid var(--line);
        border-left:4px solid var(--teal); border-radius:6px; padding:12px 14px; margin:10px 0; }}
    .finding-top {{ display:flex; align-items:center; gap:9px; flex-wrap:wrap; margin-bottom:6px; }}
    .f-title {{ font-weight:700; color:var(--navy); }}
    .f-plain {{ font-size:14px; margin-bottom:5px; }}
    .f-fix {{ font-size:14px; color:#0b6b4f; }}
    .evidence {{ font-family:"SFMono-Regular",Consolas,monospace; font-size:12px;
        color:#5b6b7f; background:#eef2f7; padding:4px 8px; border-radius:4px;
        margin-top:6px; display:inline-block; word-break:break-all; }}
    /* Info boxes */
    .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
    .kv label {{ display:block; font-size:11px; text-transform:uppercase;
        letter-spacing:1px; color:var(--muted); margin-bottom:2px; }}
    .kv span {{ font-weight:600; color:var(--navy); }}
    .fine {{ font-size:12.5px; color:var(--muted); line-height:1.7; }}
    .footer {{ text-align:center; color:var(--muted); font-size:12px; padding:18px 0; }}
    @media (max-width:640px) {{
        .tiles {{ grid-template-columns:repeat(3,1fr); }}
        .cover .meta, .grid2 {{ grid-template-columns:1fr; }}
    }}
    @media print {{
        body {{ background:#fff; padding:0; font-size:12px; }}
        .card {{ box-shadow:none; border:1px solid #ccc; page-break-inside:avoid; }}
        .cover {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
        .ctrl-block, .finding {{ page-break-inside:avoid; }}
    }}
</style>
</head>
<body>
<div class="page">

    <div class="card cover">
        {logo_html}
        <div class="eyebrow">{fw_name} · {fw_sub}</div>
        <h1>{fw_name} Readiness Report</h1>
        <div class="client">{client}</div>
        <div class="meta">
            <div><label>Prepared for</label><span>{client}</span></div>
            <div><label>Prepared by</label><span>{prepared_by}</span></div>
            <div><label>Assessment date</label><span>{date_str}</span></div>
            <div><label>Report reference</label><span>{ref}</span></div>
        </div>
    </div>

    <div class="card">
        <h2>Overall Readiness</h2>
        <div class="verdict">
            <div class="stamp {v_class}">{e(verdict['status'])}</div>
            <div class="headline">{e(verdict['headline'])}</div>
        </div>
        <div class="tiles">
            <div class="tile critical"><div class="n">{counts['critical']}</div><div class="l">Critical</div></div>
            <div class="tile high"><div class="n">{counts['high']}</div><div class="l">High</div></div>
            <div class="tile medium"><div class="n">{counts['medium']}</div><div class="l">Medium</div></div>
            <div class="tile low"><div class="n">{counts['low']}</div><div class="l">Low</div></div>
            <div class="tile info"><div class="n">{counts['info']}</div><div class="l">Info</div></div>
        </div>
    </div>

    <div class="card">
        <h2>Scope &amp; Authorisation</h2>
        <div class="grid2">
            <div class="kv"><label>Systems in scope</label><span>{scope_html}</span></div>
            <div class="kv"><label>Authorisation</label><span>{auth_ref}</span></div>
        </div>
        <p class="fine" style="margin-top:14px;">This assessment was carried out
        only against the systems listed above, with the client's written
        permission. Testing was non-intrusive and limited to externally
        observable information.</p>
    </div>

    <div class="card">
        <h2>Control Area Summary</h2>
        <p class="lead">How the in-scope systems currently line up against the
        {fw_name} controls.</p>
        <table class="summary">
            <tbody>{control_rows}</tbody>
        </table>
    </div>

    <div class="card">
        <h2>Control Area Detail</h2>
        {control_detail}
    </div>

    {email_html}

    {internal_html}

    {roadmap_html}

    <div class="card">
        <h2>Methodology &amp; Limitations</h2>
        <p class="fine">Findings were produced by the PHANTOM assessment
        framework from an external perspective (the view an attacker has of your
        internet-facing systems) and mapped onto the {fw_name} control areas.
        Controls marked &ldquo;Verify Internally&rdquo; (such as malware
        protection and device configuration) cannot be confirmed from outside
        and must be checked on the devices themselves — the PHANTOM internal
        controls checker can confirm these. This readiness report is preparatory
        guidance and is not itself a certificate.</p>
    </div>

    <div class="footer">
        <p>{ref} &nbsp;·&nbsp; Prepared by {prepared_by} &nbsp;·&nbsp; {date_str}</p>
        <p>Confidential — prepared for {client}. Generated with the PHANTOM Framework.</p>
    </div>

</div>
</body>
</html>"""

    def _mini_style(self, primary, accent):
        """Shared compact CSS for the one-page summary / retest reports."""
        return f"""
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ background:#f4f6f9; color:#1a2332; padding:32px 16px;
        font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
        line-height:1.6; }}
    .page {{ max-width:760px; margin:0 auto; }}
    .card {{ background:#fff; border:1px solid #e2e8f0; border-radius:10px;
        padding:26px 30px; margin-bottom:18px; }}
    .cover {{ background:linear-gradient(135deg,{primary},#1b3a5c); color:#fff; border:none; }}
    .cover .eyebrow {{ color:{accent}; font-weight:700; letter-spacing:2px;
        font-size:11px; text-transform:uppercase; margin-bottom:8px; }}
    .cover h1 {{ font-size:24px; }}
    .cover .client {{ color:#cfe0f0; font-size:17px; margin-top:4px; }}
    h2 {{ font-size:17px; color:{primary}; margin-bottom:12px;
        padding-bottom:6px; border-bottom:2px solid #e2e8f0; }}
    .stamp {{ display:inline-block; font-size:19px; font-weight:800; padding:12px 20px;
        border-radius:9px; letter-spacing:.5px; }}
    .ok {{ background:#e6f6ee; color:#188a5a; border:2px solid #188a5a; }}
    .warn {{ background:#fdf6e3; color:#b7791f; border:2px solid #b7791f; }}
    .bad {{ background:#fdecea; color:#c0392b; border:2px solid #c0392b; }}
    .row {{ display:flex; align-items:center; gap:18px; flex-wrap:wrap; }}
    ol, ul {{ margin:6px 0 0 20px; }} li {{ margin-bottom:7px; }}
    .muted {{ color:#5b6b7f; font-size:13px; }}
    .big {{ font-size:34px; font-weight:800; }}
    .grid3 {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }}
    .tile {{ text-align:center; background:#f4f6f9; border:1px solid #e2e8f0;
        border-radius:8px; padding:14px; }}
    .brand-logo {{ max-height:44px; max-width:180px; margin-bottom:12px;
        background:#fff; padding:4px 8px; border-radius:4px; }}
    @media print {{ body {{ background:#fff; padding:0; }} .card {{ border:1px solid #ccc; }}
        .cover {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }} }}
"""

    def _build_exec_summary_html(self, a):
        """One-page executive summary for the business owner."""
        e = html_escape
        b = self._brand()
        primary = b.get("primary_color", "#0f2440")
        accent = b.get("accent_color", "#0ea5a5")
        fw = a.get("framework", {"name": "Security"})
        client = e(self._eng("client_name", "Client Organisation"))
        verdict = a["verdict"]
        vclass = {"NOT YET READY": "bad", "ON TRACK": "warn",
                  "LIKELY TO PASS": "ok"}.get(verdict["status"], "warn")
        logo = b.get("logo_uri", "")
        logo_html = f'<img src="{e(logo)}" class="brand-logo">' if logo else ""

        # Top risks = blocking roadmap items (max 3).
        top = a.get("roadmap", [])[:3]
        risks = "".join(
            f"<li><strong>{e(str(r['title']))}</strong> — {e(str(r['action']))}</li>"
            for r in top) or "<li>No blocking issues found externally.</li>"

        controls_ok = sum(1 for c in a["controls"] if c["status"] == ce.PASS)
        controls_action = sum(1 for c in a["controls"] if c["status"] == ce.ACTION)

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Executive Summary — {client}</title>
<style>{self._mini_style(e(primary), e(accent))}</style></head>
<body><div class="page">
    <div class="card cover">
        {logo_html}
        <div class="eyebrow">{e(fw.get('name','Security'))} · Executive Summary</div>
        <h1>Security Assessment — Executive Summary</h1>
        <div class="client">{client}</div>
    </div>
    <div class="card">
        <div class="row">
            <div class="stamp {vclass}">{e(verdict['status'])}</div>
            <div style="flex:1; min-width:220px;">{e(verdict['headline'])}</div>
        </div>
    </div>
    <div class="card">
        <div class="grid3">
            <div class="tile"><div class="big" style="color:#c0392b;">{verdict['blocking']}</div>
                <div class="muted">Issues to fix</div></div>
            <div class="tile"><div class="big" style="color:#188a5a;">{controls_ok}</div>
                <div class="muted">Controls passing</div></div>
            <div class="tile"><div class="big" style="color:#b7791f;">{controls_action}</div>
                <div class="muted">Controls needing work</div></div>
        </div>
    </div>
    <div class="card">
        <h2>Top Priorities</h2>
        <ol>{risks}</ol>
    </div>
    <div class="card">
        <h2>What This Means</h2>
        <p class="muted">This one-page summary highlights the headline result and
        the most important fixes. Full technical detail, every finding, and the
        step-by-step remediation plan are in the accompanying full report.</p>
    </div>
    <div class="card" style="text-align:center;">
        <p class="muted">Prepared by {e(b.get('company_name','PHANTOM Security'))}
        &nbsp;·&nbsp; Confidential — for {client}</p>
    </div>
</div></body></html>"""

    def _build_retest_html(self, diff):
        """Change/retest report: fixed vs new vs persisting."""
        e = html_escape
        b = self._brand()
        primary = b.get("primary_color", "#0f2440")
        accent = b.get("accent_color", "#0ea5a5")
        client = e(self._eng("client_name", "Client Organisation"))
        s = diff["summary"]
        head = retest.headline(diff)
        vclass = "ok" if s["improved"] else ("bad" if s["new"] > s["fixed"] else "warn")
        logo = b.get("logo_uri", "")
        logo_html = f'<img src="{e(logo)}" class="brand-logo">' if logo else ""

        def _list(items, empty):
            if not items:
                return f"<p class='muted'>{empty}</p>"
            return "<ul>" + "".join(
                f"<li>[{e(str(f.get('severity','info')).upper())}] "
                f"{e(str(f.get('title','')))} "
                f"<span class='muted'>{e(str(f.get('evidence','')))}</span></li>"
                for f in items) + "</ul>"

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Retest / Change Report — {client}</title>
<style>{self._mini_style(e(primary), e(accent))}
    .fixed {{ color:#188a5a; }} .new {{ color:#c0392b; }} .persist {{ color:#b7791f; }}
</style></head>
<body><div class="page">
    <div class="card cover">
        {logo_html}
        <div class="eyebrow">Retest · Change Report</div>
        <h1>What Changed Since Last Assessment</h1>
        <div class="client">{client}</div>
    </div>
    <div class="card">
        <div class="row"><div class="stamp {vclass}">
            {'IMPROVED' if s['improved'] else ('REGRESSED' if s['new'] > s['fixed'] else 'UNCHANGED')}
        </div><div style="flex:1; min-width:220px;">{e(head)}</div></div>
    </div>
    <div class="card">
        <div class="grid3">
            <div class="tile"><div class="big fixed">{s['fixed']}</div><div class="muted">Fixed</div></div>
            <div class="tile"><div class="big new">{s['new']}</div><div class="muted">New</div></div>
            <div class="tile"><div class="big persist">{s['persisting']}</div><div class="muted">Still open</div></div>
        </div>
        <p class="muted" style="margin-top:12px;">Previous: {s['before']} issue(s) · Now: {s['after']} issue(s)</p>
    </div>
    <div class="card"><h2 class="fixed">✓ Resolved Since Last Time</h2>{_list(diff['fixed'], 'Nothing resolved yet.')}</div>
    <div class="card"><h2 class="new">⚠ New Issues</h2>{_list(diff['new'], 'No new issues — good.')}</div>
    <div class="card"><h2 class="persist">● Still Outstanding</h2>{_list(diff['persisting'], 'Nothing outstanding.')}</div>
    <div class="card" style="text-align:center;">
        <p class="muted">Prepared by {e(b.get('company_name','PHANTOM Security'))} · Confidential — for {client}</p>
    </div>
</div></body></html>"""

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

        .summary-block {{
            background: #15191e;
            border-left: 4px solid #00d4ff;
            padding: 15px;
            margin-bottom: 30px;
            border-radius: 4px;
        }}

        .summary-block h2 {{
            color: #00d4ff;
            border-bottom: 1px solid #1e2d3d;
            padding-bottom: 10px;
            margin-bottom: 15px;
            font-size: 18px;
            letter-spacing: 2px;
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

        .finding-card {{
            background: #12161b;
            border: 1px solid #1e2d3d;
            border-left: 4px solid #00d4ff;
            border-radius: 4px;
            padding: 16px 18px;
            margin-bottom: 18px;
        }}
        .finding-card.sev-critical {{ border-left-color: #ff4444; }}
        .finding-card.sev-high     {{ border-left-color: #ff8800; }}
        .finding-card.sev-medium   {{ border-left-color: #ffcc00; }}
        .finding-card.sev-low      {{ border-left-color: #00ff88; }}
        .finding-card.sev-info     {{ border-left-color: #00d4ff; }}

        .finding-head {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-title {{ color: #e8f0f8; font-size: 16px; font-weight: bold; }}
        .badge {{
            font-size: 11px; font-weight: bold; padding: 3px 10px;
            border-radius: 3px; letter-spacing: 1px; color: #0a0d0f;
        }}
        .badge.sev-critical {{ background: #ff4444; color: #fff; }}
        .badge.sev-high     {{ background: #ff8800; }}
        .badge.sev-medium   {{ background: #ffcc00; }}
        .badge.sev-low      {{ background: #00ff88; }}
        .badge.sev-info     {{ background: #00d4ff; }}
        .badge.cvss {{ margin-left: auto; margin-right: 8px; letter-spacing: .3px; }}

        .layer {{ margin: 8px 0; }}
        .layer .lbl {{
            display: inline-block; min-width: 130px; color: #66d9ff;
            font-size: 11px; font-weight: bold; text-transform: uppercase;
            letter-spacing: 1px; vertical-align: top;
        }}
        .layer .val {{ display: inline-block; width: calc(100% - 140px); }}
        .layer.plain .val {{ color: #ffe9a8; }}
        .layer.fix   .val {{ color: #9effc4; }}
        .evidence {{
            font-family: 'Courier New', monospace; font-size: 12px;
            color: #8fa6bd; background: #0a0d0f; padding: 4px 8px;
            border-radius: 3px; display: inline-block; margin-top: 4px;
        }}

        .client-summary {{
            background: #14110a;
            border-left: 4px solid #ffcc00;
            padding: 18px 20px;
            border-radius: 4px;
            margin-bottom: 30px;
        }}
        .client-summary h2 {{ color: #ffcc00; letter-spacing: 2px; font-size: 18px; margin-bottom: 12px; }}
        .client-summary p, .client-summary li {{ color: #f0e6cc; margin-bottom: 8px; line-height: 1.7; }}
        .client-summary ul {{ list-style: none; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>◈ PHANTOM FRAMEWORK</h1>
            <p>Technical Security Assessment Report</p>
        </div>
        
        <div class="scan-summary">
            <div><label>ASSESSMENT ID</label><span>{html_escape(str(scan_info.get('scan_id', 'N/A')))}</span></div>
            <div><label>TARGET</label><span>{html_escape(str(scan_info.get('target', 'N/A')))}</span></div>
            <div><label>ASSESSMENT TYPE</label><span>{html_escape(str(scan_info.get('scan_type', 'N/A')))}</span></div>
            <div><label>TIMESTAMP</label><span>{html_escape(str(scan_info.get('timestamp', 'N/A')))}</span></div>
            <div><label>EXECUTION STATUS</label><span>{html_escape(str(scan_info.get('status', 'N/A')))}</span></div>
            <div><label>RISK CLASSIFICATION</label><span>{html_escape(str(scan_info.get('risk_level', 'N/A')))}</span></div>
        </div>

        <div class="summary-block">
            <h2>TECHNICAL INTERPRETATION</h2>
            <ul>
                {self._technical_summary_list_items()}
            </ul>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="number">{len(vulns)}</div>
                <div class="label">OBSERVED VULNERABILITIES</div>
            </div>
            <div class="stat-box">
                <div class="number">{len(hosts)}</div>
                <div class="label">HOST ENTRIES</div>
            </div>
            <div class="stat-box">
                <div class="number">{len(exploits)}</div>
                <div class="label">EXPLOIT CANDIDATES</div>
            </div>
            <div class="stat-box">
                <div class="number">{max(v.get('confidence', 0) for v in vulns) if vulns else 0}%</div>
                <div class="label">MAX CONFIDENCE</div>
            </div>
        </div>
"""

        # ── Plain-language summary (for the client) + explained findings ──
        html += self._build_client_summary()
        html += self._build_findings_section()

        # Vulnerabilities
        if vulns:
            html += """
        <div class="section">
            <h2>OBSERVED VULNERABILITIES</h2>
            <table>
                <tr>
                    <th>Class</th>
                    <th>Technical Description</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Remediation Guidance</th>
                </tr>
"""
            for vuln in vulns:
                severity = vuln.get("severity", "low").lower()
                html += f"""
                <tr>
                    <td>{html_escape(str(vuln.get('vuln_type', 'N/A')))}</td>
                    <td>{html_escape(self._technical_vuln_description(vuln))}</td>
                    <td><span class="severity-{severity}">{severity.upper()}</span></td>
                    <td>{vuln.get('confidence', 'N/A')}%</td>
                    <td>{html_escape(str(vuln.get('remediation', 'N/A')))}</td>
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
            <h2>OBSERVED SERVICES AND HOSTS</h2>
            <table>
                <tr>
                    <th>Address</th>
                    <th>Hostname</th>
                    <th>OS Fingerprint</th>
                    <th>Listening Services</th>
                    <th>Service Map</th>
                </tr>
"""
            for host in hosts:
                html += f"""
                <tr>
                    <td>{html_escape(str(host.get('ip_address', 'N/A')))}</td>
                    <td>{html_escape(str(host.get('hostname', 'N/A')))}</td>
                    <td>{html_escape(str(host.get('os', 'N/A')))}</td>
                    <td>{html_escape(str(host.get('open_ports', 'N/A')))}</td>
                    <td>{html_escape(str(host.get('services', 'N/A')))}</td>
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
            <h2>EXPLOIT CANDIDATES</h2>
            <table>
                <tr>
                    <th>Vulnerability Class</th>
                    <th>Candidate Exploit</th>
                    <th>CVSS Score</th>
                </tr>
"""
            for exploit in exploits:
                html += f"""
                <tr>
                    <td>{html_escape(str(exploit.get('vulnerability', 'N/A')))}</td>
                    <td>{html_escape(str(exploit.get('exploit_name', 'N/A')))}</td>
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
            <p>Authorized technical assessment output only</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _technical_summary_lines(self):
        scan_info = self.scan_data.get("scan", {})
        vulns = self.scan_data.get("vulnerabilities", [])
        hosts = self.scan_data.get("hosts", [])
        exploits = self.scan_data.get("exploits", [])

        lines = [
            f"Assessment target: {scan_info.get('target', 'N/A')}",
            f"Assessment type: {scan_info.get('scan_type', 'N/A')}",
            f"Observed host entries: {len(hosts)}",
            f"Observed vulnerability records: {len(vulns)}",
            f"Exploit candidates identified: {len(exploits)}",
        ]

        if vulns:
            lines.append(f"Highest observed severity class: {max(v.get('severity', 'low') for v in vulns)}")

        return lines

    def _technical_summary_text(self):
        return "<br/>".join(f"• {html_escape(line)}" for line in self._technical_summary_lines())

    def _technical_summary_list_items(self):
        return "".join(f"<li>{html_escape(line)}</li>" for line in self._technical_summary_lines())

    def _get_findings(self):
        """Extract + explain findings from the raw tool output (cached).

        Findings are additionally enriched with an OWASP Top 10 (2021) category
        and an indicative CVSS v3.1 base score for client-grade reporting.
        """
        if getattr(self, "_findings_cache", None) is None:
            results = self.scan_data.get("results", [])
            target = self.scan_data.get("scan", {}).get("target", "")
            try:
                findings = findings_mod.extract_findings(results, target)
                owasp.enrich(findings)
                self._findings_cache = findings
            except Exception:
                self._findings_cache = []
        return self._findings_cache

    def _build_client_summary(self):
        """Plain-language, non-technical section for handing to the client."""
        findings = self._get_findings()
        target = self.scan_data.get("scan", {}).get("target", "the target")
        lines = findings_mod.client_summary(findings, target)
        items = "".join(f"<li>{html_escape(line)}</li>" for line in lines)
        return f"""
        <div class="client-summary">
            <h2>PLAIN-LANGUAGE SUMMARY (FOR CLIENT)</h2>
            <p>This section explains, without technical jargon, what we found and
            what it means for you.</p>
            <ul>{items}</ul>
        </div>
"""

    def _build_findings_section(self):
        """Per-finding cards: technical detail + plain translation + risk + fix."""
        findings = self._get_findings()
        if not findings:
            return ""
        cards = []
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            evidence = f.get("evidence", "")
            ev_html = (f'<div class="layer"><span class="lbl">Evidence</span>'
                       f'<span class="val"><span class="evidence">{html_escape(str(evidence))}</span></span></div>'
                       if evidence else "")
            cvss = f.get("cvss") or {}
            cvss_html = ""
            if cvss.get("score"):
                cvss_html = (f'<span class="badge cvss sev-{html_escape(str(cvss.get("band", sev)))}" '
                             f'title="Indicative CVSS v3.1 base score">'
                             f'CVSS {html_escape(str(cvss["score"]))}</span>')
            owasp_info = f.get("owasp") or {}
            owasp_html = ""
            if owasp_info.get("label"):
                owasp_html = (f'<div class="layer"><span class="lbl">OWASP Top 10</span>'
                              f'<span class="val">{html_escape(str(owasp_info["label"]))}</span></div>')
            cve = f.get("cve")
            cve_html = ""
            if cve:
                cve_html = (f'<div class="layer"><span class="lbl">Reference</span>'
                            f'<span class="val">{html_escape(str(cve))}</span></div>')
            cards.append(f"""
            <div class="finding-card sev-{sev}">
                <div class="finding-head">
                    <span class="finding-title">{html_escape(str(f.get('title', 'Finding')))}</span>
                    {cvss_html}
                    <span class="badge sev-{sev}">{sev.upper()}</span>
                </div>
                {owasp_html}
                {cve_html}
                <div class="layer"><span class="lbl">Technical</span><span class="val">{html_escape(str(f.get('technical', '')))}</span></div>
                <div class="layer plain"><span class="lbl">In plain terms</span><span class="val">{html_escape(str(f.get('plain', '')))}</span></div>
                <div class="layer"><span class="lbl">Why it matters</span><span class="val">{html_escape(str(f.get('risk', '')))}</span></div>
                <div class="layer fix"><span class="lbl">Recommendation</span><span class="val">{html_escape(str(f.get('remediation', '')))}</span></div>
                {ev_html}
            </div>""")
        return f"""
        <div class="section">
            <h2>TECHNICAL FINDINGS — EXPLAINED</h2>
            {''.join(cards)}
        </div>
"""

    def _technical_vuln_description(self, vuln):
        vuln_type = str(vuln.get("vuln_type", "")).lower()
        descriptions = {
            "sql injection": "SQL injection condition observed. Input handling may permit query manipulation against backend database operations.",
            "sql_injection": "SQL injection condition observed. Input handling may permit query manipulation against backend database operations.",
            "xss": "Cross-site scripting condition observed. Untrusted data may execute in a client-side context.",
            "rce": "Remote code execution condition observed. Untrusted input may reach a command execution sink.",
            "open_ports": "Listening services were observed. Exposed attack surface should be validated against access control and hardening requirements.",
            "weak_authentication": "Weak authentication control observed. Credential brute force or reuse may be feasible.",
            "unpatched_service": "Service version exposure may map to a known exploit chain or public CVE.",
        }

        if vuln_type in descriptions:
            return descriptions[vuln_type]

        return vuln.get("description", "Technical detail not available.")


# ─── HELPER FUNCTIONS ───────────────────────────

def generate_report(scan_data, formats=["json", "html"], engagement=None):
    """Quick report generation.

    formats may include:
      "json", "html", "pdf"        — technical pentest report
      "ce" / "ce-pdf"              — Cyber Essentials readiness deliverable
      "framework" / "framework-pdf" — any framework (id from engagement
                                      ["framework_id"], default cyber_essentials)
      "exec" / "exec-pdf"         — one-page executive summary

    Pass ``engagement`` with client_name / prepared_by / date / scope /
    authorization_ref (and optionally framework_id) to brand the deliverables.
    """
    generator = PhantomReporter(scan_data=scan_data, engagement=engagement)
    fw_id = (engagement or {}).get("framework_id", "cyber_essentials")

    results = {}
    for fmt in formats:
        f = fmt.lower()
        if f == "json":
            results[fmt] = generator.generate_json_report()
        elif f == "html":
            results[fmt] = generator.generate_html_report()
        elif f == "pdf":
            results[fmt] = generator.generate_pdf_report()
        elif f in ("ce", "cyber_essentials"):
            results[fmt] = generator.generate_ce_report()
        elif f in ("ce-pdf", "cyber_essentials-pdf"):
            results[fmt] = generator.generate_ce_report_pdf()
        elif f == "framework":
            results[fmt] = generator.generate_framework_report(fw_id)
        elif f == "framework-pdf":
            results[fmt] = generator.generate_framework_report_pdf(fw_id)
        elif f == "exec":
            results[fmt] = generator.generate_exec_summary(fw_id)
        elif f == "exec-pdf":
            results[fmt] = generator.generate_exec_summary_pdf(fw_id)

    return results


PhantomReportGenerator = PhantomReporter


if __name__ == "__main__":
    print("✓ Reports module ready")
    print(f"✓ Reports directory: {REPORTS_DIR}")
