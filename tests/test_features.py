#!/usr/bin/env python3
"""Tests for the market-feature modules: retest, frameworks, planner, branding, email."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import phantom_findings as fm       # noqa: E402
import phantom_retest as retest     # noqa: E402
import phantom_frameworks as fw     # noqa: E402
import phantom_planner as planner   # noqa: E402
import phantom_branding as branding # noqa: E402
import phantom_email_security as es # noqa: E402
import phantom_ce as ce             # noqa: E402

R_OLD = [{"tool_name": "nmap",
          "tool_output": "21/tcp open ftp vsftpd 2.3.4\n80/tcp open http Apache httpd 2.4.49"}]
R_NEW = [{"tool_name": "nmap",
          "tool_output": "80/tcp open http Apache httpd 2.4.51\n22/tcp open ssh OpenSSH 8.9"}]


class TestRetest(unittest.TestCase):
    def test_diff_counts(self):
        d = retest.diff_from_results(R_OLD, R_NEW, "x")
        s = d["summary"]
        self.assertGreater(s["fixed"], 0)      # old vsftpd/apache issues gone
        self.assertEqual(s["persisting"], 0)   # nothing identical across both
        self.assertIn("before", s)

    def test_identical_scans_no_change(self):
        d = retest.diff_from_results(R_OLD, R_OLD, "x")
        self.assertEqual(d["summary"]["fixed"], 0)
        self.assertEqual(d["summary"]["new"], 0)
        self.assertGreater(d["summary"]["persisting"], 0)

    def test_headline_is_string(self):
        d = retest.diff_from_results(R_OLD, R_NEW, "x")
        self.assertIsInstance(retest.headline(d), str)


class TestFrameworks(unittest.TestCase):
    def setUp(self):
        self.findings = fm.extract_findings(R_OLD, "x")

    def test_all_frameworks_assess(self):
        for fid, _name in fw.available():
            a = fw.assess(fid, self.findings, "x")
            self.assertIn("verdict", a)
            self.assertTrue(a["controls"])
            self.assertIn("framework", a)

    def test_unknown_framework_raises(self):
        with self.assertRaises(ValueError):
            fw.assess("nonsense", self.findings, "x")

    def test_internal_fail_flips_malware_to_action(self):
        internal = {"host": "PC", "os": "Windows",
                    "checks": [{"control": "malware", "status": "fail",
                                "detail": "off"}],
                    "summary": {"passed": 0, "failed": 1, "unknown": 0, "total": 1}}
        a = fw.assess("cyber_essentials", self.findings, "x",
                      internal_results=internal)
        malware = next(c for c in a["controls"] if c["id"] == "malware")
        self.assertEqual(malware["status"], ce.ACTION)

    def test_internal_pass_confirms_verify_control(self):
        internal = {"host": "PC", "os": "Windows",
                    "checks": [{"control": "malware", "status": "pass",
                                "detail": "Defender on"}],
                    "summary": {"passed": 1, "failed": 0, "unknown": 0, "total": 1}}
        a = fw.assess("cyber_essentials", [], "x", internal_results=internal)
        malware = next(c for c in a["controls"] if c["id"] == "malware")
        self.assertEqual(malware["status"], ce.PASS)


class TestPlanner(unittest.TestCase):
    def test_rules_always_return_steps(self):
        plan = planner.suggest_next_actions([], tools_run=[], use_ai=False)
        self.assertEqual(plan["engine"], "rules")
        self.assertTrue(plan["steps"])

    def test_rules_suggest_report_last(self):
        findings = fm.extract_findings(R_OLD, "x")
        plan = planner.suggest_next_actions(findings, tools_run=["nmap"], use_ai=False)
        self.assertTrue(any("report" in s["action"].lower() for s in plan["steps"]))

    def test_llm_failure_falls_back_to_rules(self):
        class Broken:
            def check_model(self):
                return True
            def query(self, *_a, **_k):
                raise RuntimeError("no model")
        plan = planner.suggest_next_actions([], use_ai=True, engine=Broken())
        self.assertEqual(plan["engine"], "rules")


class TestBranding(unittest.TestCase):
    def test_load_has_defaults(self):
        b = branding.load()
        for key in ("company_name", "primary_color", "accent_color"):
            self.assertIn(key, b)

    def test_missing_logo_returns_empty(self):
        self.assertEqual(branding.logo_data_uri("/no/such/logo.png"), "")

    def test_apply_to_engagement_sets_prepared_by(self):
        eng = branding.apply_to_engagement({"client_name": "X"})
        self.assertIn("prepared_by", eng)


class TestEmailSecurity(unittest.TestCase):
    def test_structure_without_network(self):
        # Even if DNS is unavailable, the shape must be valid and not crash.
        r = es.assess_email_security("example.com")
        self.assertIn("findings", r)
        self.assertIn("score", r)
        self.assertEqual(len(r["findings"]), 4)

    def test_breach_skips_without_key(self):
        old = os.environ.pop("HIBP_API_KEY", None)
        try:
            res = es.check_breach_exposure("example.com")
            self.assertFalse(res["available"])
        finally:
            if old:
                os.environ["HIBP_API_KEY"] = old


if __name__ == "__main__":
    unittest.main()
