#!/usr/bin/env python3
"""Tests for the knowledge base + findings extractor (dual-layer reporting)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import phantom_knowledge as kb
import phantom_findings as pf


class TestKnowledge(unittest.TestCase):
    def test_known_port_has_both_layers(self):
        ssh = kb.explain_port(22, "ssh")
        for key in ("technical", "plain", "risk", "remediation", "severity", "title"):
            self.assertTrue(ssh.get(key), f"missing {key}")
        self.assertIn("SSH", ssh["title"])

    def test_telnet_is_critical_cleartext(self):
        self.assertEqual(kb.explain_port(23)["severity"], "critical")

    def test_unknown_port_generic(self):
        g = kb.explain_port(9999, "weirdsvc")
        self.assertEqual(g["severity"], "info")
        self.assertIn("9999", g["title"])

    def test_vuln_layers(self):
        sqli = kb.explain_vuln("sql_injection")
        self.assertEqual(sqli["severity"], "critical")
        self.assertIn("database", sqli["plain"].lower())


class TestExtractor(unittest.TestCase):
    NMAP = """PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6
80/tcp   open  http    Apache 2.4.29
23/tcp   open  telnet
"""
    HYDRA = "[22][ssh] host: 10.0.0.5   login: admin   password: admin123\n"
    SQLMAP = "Parameter: id (GET)\n    Type: boolean-based blind\nGET parameter 'id' is vulnerable.\n"
    NIKTO = "+ The anti-clickjacking X-Frame-Options header is not present.\n+ Server: Apache/2.4.29\n"

    def _kinds(self, findings):
        return {f.get("kind") or f.get("title") for f in findings}

    def test_nmap_ports_extracted(self):
        f = pf.extract_findings([{"tool_name": "nmap", "tool_output": self.NMAP}])
        titles = {x["title"] for x in f}
        self.assertIn("Open port 22/SSH", titles)
        self.assertIn("Open port 80/HTTP", titles)
        self.assertIn("Open port 23/Telnet", titles)

    def test_weak_password_detected(self):
        f = pf.extract_findings([{"tool_name": "hydra", "tool_output": self.HYDRA}])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["kind"], "weak_credentials")
        self.assertIn("admin123", f[0]["evidence"])
        self.assertIn("easy to guess", f[0]["plain"].lower())

    def test_sql_injection_detected(self):
        f = pf.extract_findings([{"tool_name": "sqlmap", "tool_output": self.SQLMAP}])
        self.assertTrue(any(x["kind"] == "sql_injection" for x in f))

    def test_nikto_web_findings(self):
        f = pf.extract_findings([{"tool_name": "nikto", "tool_output": self.NIKTO}])
        kinds = self._kinds(f)
        self.assertIn("missing_security_headers", kinds)
        self.assertIn("info_disclosure", kinds)

    def test_severity_sorted_and_deduped(self):
        # telnet (critical) should rank above http/ssh; duplicate nmap block deduped
        f = pf.extract_findings([
            {"tool_name": "nmap", "tool_output": self.NMAP},
            {"tool_name": "nmap", "tool_output": self.NMAP},
        ])
        self.assertEqual(f[0]["title"], "Open port 23/Telnet")  # critical first
        titles = [x["title"] for x in f]
        self.assertEqual(len(titles), len(set(titles)))  # no duplicates

    def test_client_summary_and_counts(self):
        f = pf.extract_findings([
            {"tool_name": "nmap", "tool_output": self.NMAP},
            {"tool_name": "hydra", "tool_output": self.HYDRA},
        ])
        counts = pf.severity_counts(f)
        self.assertGreaterEqual(counts["critical"], 1)  # telnet
        summary = pf.client_summary(f, "10.0.0.5")
        self.assertTrue(summary)
        self.assertIn("10.0.0.5", summary[0])

    def test_empty_input(self):
        self.assertEqual(pf.extract_findings([]), [])
        self.assertTrue(pf.client_summary([], "x"))  # graceful "nothing found"


class TestExpandedCoverage(unittest.TestCase):
    def test_new_high_risk_ports(self):
        self.assertEqual(kb.explain_port(2375, "docker")["severity"], "critical")   # Docker API
        self.assertEqual(kb.explain_port(11211, "memcached")["severity"], "critical")
        self.assertEqual(kb.explain_port(2049, "nfs")["severity"], "high")           # NFS

    def test_ssl_weak_protocol_detected(self):
        out = "  TLSv1.0   enabled\n  SSLv3     enabled\n"
        f = pf.extract_findings([{"tool_name": "sslscan", "tool_output": out}])
        self.assertTrue(any(x.get("kind") == "ssl_weak_protocol" for x in f))

    def test_ssl_weak_cipher_and_cert(self):
        out = "Accepted  TLSv1.2  128 bits  RC4-SHA\nCertificate has expired\n"
        f = pf.extract_findings([{"tool_name": "sslscan", "tool_output": out}])
        kinds = {x.get("kind") for x in f}
        self.assertIn("ssl_weak_cipher", kinds)
        self.assertIn("ssl_cert_issue", kinds)

    def test_cve_from_nmap_version(self):
        out = "PORT   STATE SERVICE VERSION\n80/tcp open http Apache 2.4.49\n"
        f = pf.extract_findings([{"tool_name": "nmap", "tool_output": out}])
        cves = [x for x in f if x.get("kind") == "cve"]
        self.assertTrue(any("CVE-2021-41773" in x["title"] for x in cves))
        self.assertEqual(cves[0]["severity"], "critical")

    def test_cve_from_nikto_server_banner(self):
        out = "+ Server: Apache/2.4.49 (Unix)\n"
        f = pf.extract_findings([{"tool_name": "nikto", "tool_output": out}])
        self.assertTrue(any(x.get("kind") == "cve" for x in f))

    def test_heartbleed_banner(self):
        out = "22/tcp open ssh\n443/tcp open ssl/http OpenSSL 1.0.1e\n"
        f = pf.extract_findings([{"tool_name": "nmap", "tool_output": out}])
        self.assertTrue(any("Heartbleed" in x["title"] for x in f))

    def test_same_cve_deduped_across_sources(self):
        # Apache 2.4.49 appears in two nmap ports and the nikto banner.
        out_nmap = "80/tcp open http Apache 2.4.49\n443/tcp open ssl/http Apache 2.4.49\n"
        out_nikto = "+ Server: Apache/2.4.49\n"
        f = pf.extract_findings([
            {"tool_name": "nmap", "tool_output": out_nmap},
            {"tool_name": "nikto", "tool_output": out_nikto},
        ])
        cves = [x for x in f if x.get("kind") == "cve" and "CVE-2021-41773" in x["title"]]
        self.assertEqual(len(cves), 1)

    def test_no_false_cve_on_patched_version(self):
        out = "80/tcp open http Apache 2.4.58\n"
        f = pf.extract_findings([{"tool_name": "nmap", "tool_output": out}])
        self.assertFalse(any(x.get("kind") == "cve" for x in f))


if __name__ == "__main__":
    unittest.main(verbosity=2)
