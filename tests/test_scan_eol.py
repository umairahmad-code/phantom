#!/usr/bin/env python3
"""Tests for EOL/outdated detection and the scan orchestrator (mocked)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import phantom_knowledge as kb   # noqa: E402
import phantom_findings as fm    # noqa: E402
import phantom_scan as scan_mod  # noqa: E402


class TestEOLDetection(unittest.TestCase):
    def test_flags_old_openssh(self):
        # The exact miss from the scanme.nmap.org test run.
        out = kb.match_eol("OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13")
        self.assertTrue(out)
        self.assertEqual(out[0]["severity"], "high")
        self.assertEqual(out[0]["kind"], "outdated_service")

    def test_no_false_positive_on_current_openssh(self):
        for banner in ("OpenSSH 9.6p1", "OpenSSH 8.9p1", "OpenSSH 7.4"):
            self.assertEqual(kb.match_eol(banner), [], f"false positive on {banner}")

    def test_flags_apache_22_and_php5(self):
        self.assertTrue(kb.match_eol("Apache/2.2.15"))
        self.assertTrue(kb.match_eol("PHP/5.6.40"))

    def test_extraction_includes_eol_finding(self):
        res = [{"tool_name": "nmap",
                "tool_output": "22/tcp open ssh OpenSSH 6.6.1p1 Ubuntu"}]
        titles = [f["title"] for f in fm.extract_findings(res, "x")]
        self.assertTrue(any("End-of-Life" in t for t in titles))

    def test_eol_maps_to_update_management_blocking(self):
        # An EOL finding must drive the CE "Security Update Management" control.
        import phantom_ce as ce
        res = [{"tool_name": "nmap",
                "tool_output": "22/tcp open ssh OpenSSH 6.6.1p1 Ubuntu"}]
        findings = fm.extract_findings(res, "x")
        a = ce.assess(findings, "x")
        upd = next(c for c in a["controls"] if c["id"] == "update_mgmt")
        self.assertEqual(upd["status"], ce.ACTION)


class TestScanOrchestrator(unittest.TestCase):
    def test_open_port_parsing(self):
        sample = ("22/tcp   open  ssh\n"
                  "80/tcp   filtered http\n"
                  "9929/tcp open  nping-echo\n"
                  "31337/tcp open tcpwrapped\n")
        ports = sorted(int(m.group(1))
                       for m in scan_mod._OPEN_PORT_RE.finditer(sample))
        self.assertEqual(ports, [22, 9929, 31337])   # 80 filtered → excluded

    def test_web_scan_skipped_without_web_port(self):
        # No web port open → web_scan returns nothing (efficiency fix).
        res = scan_mod.web_scan("x", [22, 9929], scope=None)
        self.assertEqual(res, [])

    def test_run_scan_uses_orchestration(self, ):
        # Patch the stage functions so no real network is touched.
        orig_disc = scan_mod.discover_ports
        orig_sv = scan_mod.service_scan
        orig_web = scan_mod.web_scan
        try:
            scan_mod.discover_ports = lambda *a, **k: ([22, 9929], "raw")
            scan_mod.service_scan = lambda *a, **k: (
                "22/tcp open ssh OpenSSH 6.6.1p1\n9929/tcp open nping-echo", [22, 9929])
            scan_mod.web_scan = lambda *a, **k: []
            r = scan_mod.run_scan("x", scope=None)
            self.assertEqual(r["open_ports"], [22, 9929])
            self.assertTrue(r["results"])
            self.assertIn("duration", r)
        finally:
            scan_mod.discover_ports = orig_disc
            scan_mod.service_scan = orig_sv
            scan_mod.web_scan = orig_web


if __name__ == "__main__":
    unittest.main()
