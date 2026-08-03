#!/usr/bin/env python3
"""
Demo: render a full Cyber Essentials Readiness Report from mock scan data.

Run:  python3 tests/demo_ce_report.py
Produces a branded, print-ready HTML file under the configured reports dir and
prints its path. Open it in a browser — this is the sales-grade sample.

The mock data below is realistic raw tool output (nmap / nikto / hydra /
sslscan) for a fictional client so the finding extractor and Cyber Essentials
mapper exercise every control area.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import phantom_reports as reports  # noqa: E402


# ── Mock raw tool output for a fictional client ("Meridian Legal LLP") ──
MOCK_RESULTS = [
    {
        "tool_name": "nmap",
        "tool_output": """
Starting Nmap scan against meridianlegal.example
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.3.4
22/tcp    open  ssh         OpenSSH 7.4
80/tcp    open  http        Apache httpd 2.4.49
443/tcp   open  ssl/http    Apache httpd 2.4.49
3306/tcp  open  mysql       MySQL 5.5.62
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
Service detection performed.
""",
    },
    {
        "tool_name": "nikto",
        "tool_output": """
+ Server: Apache/2.4.49
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set.
+ Server may leak inodes via ETags.
+ OSVDB-3268: /images/: Index of / directory listing found.
""",
    },
    {
        "tool_name": "hydra",
        "tool_output": """
Hydra starting brute force against ssh://meridianlegal.example
[22][ssh] host: meridianlegal.example   login: admin   password: Password1
[STATUS] attack finished
""",
    },
    {
        "tool_name": "sslscan",
        "tool_output": """
Testing SSL server meridianlegal.example on port 443
  TLSv1.0   enabled
  Accepted  TLSv1.0  112 bits  DES-CBC3-SHA
  Certificate has expired
""",
    },
]


def main():
    scan_data = {
        "scan": {
            "scan_id": "DEMO-001",
            "target": "meridianlegal.example",
            "scan_type": "External readiness assessment",
            "timestamp": "2026-08-03 10:00",
            "status": "completed",
            "risk_level": "medium",
        },
        "results": MOCK_RESULTS,
    }

    engagement = {
        "client_name": "Meridian Legal LLP",
        "prepared_by": "PHANTOM Security Services",
        "assessor": "PHANTOM Security Services",
        "date": "3 August 2026",
        "report_ref": "CE-2026-0042",
        "authorization_ref": "Signed engagement letter, 28 Jul 2026",
        "scope": ["meridianlegal.example", "mail.meridianlegal.example"],
    }

    out = reports.generate_report(scan_data, formats=["ce"], engagement=engagement)
    path = out.get("ce")
    if path:
        print(f"\n✓ Sample report ready — open in a browser:\n  {os.path.abspath(path)}")
    else:
        print("❌ Report generation returned no path")
        sys.exit(1)


if __name__ == "__main__":
    main()
