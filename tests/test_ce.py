#!/usr/bin/env python3
"""Tests for the Cyber Essentials readiness mapper (phantom_ce)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import phantom_findings as fm  # noqa: E402
import phantom_ce as ce  # noqa: E402


def _assess(results):
    findings = fm.extract_findings(results, "target.example")
    return ce.assess(findings, "target.example")


def _control(assessment, cid):
    return next(c for c in assessment["controls"] if c["id"] == cid)


class TestCleanScan(unittest.TestCase):
    def test_no_findings_is_likely_pass(self):
        a = ce.assess([], "target.example")
        self.assertEqual(a["verdict"]["status"], "LIKELY TO PASS")
        self.assertEqual(a["verdict"]["blocking"], 0)

    def test_malware_always_verify_internally(self):
        a = ce.assess([], "target.example")
        self.assertEqual(_control(a, "malware")["status"], ce.VERIFY)

    def test_five_controls_present(self):
        a = ce.assess([], "target.example")
        self.assertEqual(len(a["controls"]), 5)


class TestControlMapping(unittest.TestCase):
    def test_known_cve_fails_update_management(self):
        results = [{"tool_name": "nmap",
                    "tool_output": "80/tcp open http Apache httpd 2.4.49"}]
        a = _assess(results)
        self.assertEqual(_control(a, "update_mgmt")["status"], ce.ACTION)
        self.assertEqual(a["verdict"]["status"], "NOT YET READY")

    def test_weak_credentials_fail_access_control(self):
        results = [{"tool_name": "hydra",
                    "tool_output": "[22][ssh] host: x login: admin password: 123456"}]
        a = _assess(results)
        self.assertEqual(_control(a, "access_control")["status"], ce.ACTION)

    def test_exposed_database_fails_firewalls(self):
        results = [{"tool_name": "nmap",
                    "tool_output": "3306/tcp open mysql MySQL 5.7"}]
        a = _assess(results)
        self.assertEqual(_control(a, "firewalls")["status"], ce.ACTION)

    def test_cleartext_ftp_hits_firewall_and_secure_config(self):
        results = [{"tool_name": "nmap",
                    "tool_output": "21/tcp open ftp SomeFTP 1.0"}]
        a = _assess(results)
        self.assertEqual(_control(a, "firewalls")["status"], ce.ACTION)
        self.assertEqual(_control(a, "secure_config")["status"], ce.ACTION)

    def test_standard_web_port_is_not_a_firewall_failure(self):
        results = [{"tool_name": "nmap",
                    "tool_output": "443/tcp open ssl/http nginx 1.24.0"}]
        a = _assess(results)
        # 443 is expected; nginx 1.24 has no CVE match -> nothing blocking.
        self.assertEqual(_control(a, "firewalls")["status"], ce.PASS)


class TestRoadmap(unittest.TestCase):
    def test_roadmap_is_severity_ordered_and_numbered(self):
        results = [{
            "tool_name": "multi",
            "tool_output": """
21/tcp open ftp vsftpd 2.3.4
80/tcp open http Apache httpd 2.4.49
[22][ssh] host: x login: admin password: Password1
""",
        }]
        a = _assess(results)
        roadmap = a["roadmap"]
        self.assertTrue(roadmap)
        # Priorities are sequential starting at 1.
        self.assertEqual([i["priority"] for i in roadmap],
                         list(range(1, len(roadmap) + 1)))
        # Severity rank is non-increasing (critical first).
        ranks = [ce.kb.severity_rank(i["severity"]) for i in roadmap]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


if __name__ == "__main__":
    unittest.main()
