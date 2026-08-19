#!/usr/bin/env python3
"""
Demo: produce a COMPLETE sales-grade deliverable set from mock scan data.

Generates, for a fictional client, every client-facing artefact PHANTOM can
sell — as branded HTML *and* client-grade PDF (rendered via headless Chrome):

  * Cyber Essentials readiness report      (ce  / ce-pdf)
  * PCI DSS external-subset readiness       (framework / framework-pdf)
  * One-page executive summary              (exec / exec-pdf)
  * Full technical findings report          (html / pdf)

Run:  python3 tests/demo_full_report.py
Prints the path to every artefact produced. Open the PDFs — this is the exact
sample you can show a prospective client.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import phantom_reports as reports          # noqa: E402
import phantom_pdf as pdf_engine           # noqa: E402

# Reuse the realistic mock tool output from the CE demo.
from demo_ce_report import MOCK_RESULTS     # noqa: E402


def main():
    scan_data = {
        "scan": {
            "scan_id": "DEMO-FULL-001",
            "target": "meridianlegal.example",
            "scan_type": "External security assessment",
            "timestamp": "2026-08-08 10:00",
            "status": "completed",
            "risk_level": "high",
        },
        "results": MOCK_RESULTS,
    }
    engagement = {
        "client_name": "Meridian Legal LLP",
        "prepared_by": "PHANTOM Security Services",
        "assessor": "PHANTOM Security Services",
        "date": "8 August 2026",
        "report_ref": "PSS-2026-0042",
        "authorization_ref": "Signed engagement letter, 28 Jul 2026",
        "scope": ["meridianlegal.example", "mail.meridianlegal.example"],
        "framework_id": "pci_lite",   # second deliverable = PCI external subset
    }

    print("PDF engine:", "Chrome available ✓" if pdf_engine.available()
          else "NOT available (HTML only)")
    print("-" * 60)

    formats = ["ce", "ce-pdf", "framework", "framework-pdf",
               "exec", "exec-pdf", "html", "pdf"]
    out = reports.generate_report(scan_data, formats=formats,
                                  engagement=engagement)

    print("-" * 60)
    print("Deliverables produced:\n")
    for fmt in formats:
        path = out.get(fmt)
        mark = "✓" if path else "—"
        print(f"  {mark} {fmt:<15} {os.path.abspath(path) if path else '(skipped)'}")


if __name__ == "__main__":
    main()
