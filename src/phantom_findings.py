#!/usr/bin/env python3
"""
PHANTOM FINDINGS EXTRACTOR
Parses raw tool output (nmap, hydra, sqlmap, nikto, ...) into structured
findings, each enriched with a two-layer explanation from the knowledge base.

Because the GUI stores full raw tool output per run, this works on both fresh
and historical scans without needing the (sparsely populated) hosts/vulns
tables. Content-based detection is used, so combined output (e.g. multi_scan)
is handled regardless of the recorded tool name.
"""

import re

try:
    import phantom_knowledge as kb
except ImportError:  # imported as src.phantom_findings
    from src import phantom_knowledge as kb

_NMAP_PORT = re.compile(r'^\s*(\d{1,5})/(tcp|udp)\s+open\s+([\w\-/]+)(?:\s+(.*\S))?', re.M)
_HYDRA_CRED = re.compile(
    r'\[(\d+)\]\[(\w+)\][^\n]*?login:\s*(\S+)\s+password:\s*(\S+)', re.I)
_SQLMAP_PARAM = re.compile(r'Parameter:\s*([^\n(]+)')


def _add(findings, seen, finding, tool):
    """Append a finding once. CVEs dedup by CVE id; others by kind+evidence."""
    ident = finding.get("cve") or finding.get("evidence", "")
    key = (finding.get("kind") or finding.get("title"), ident)
    if key in seen:
        return
    seen.add(key)
    finding["tool"] = tool
    findings.append(finding)


_WEAK_PROTO = re.compile(r'\b(SSLv2|SSLv3|TLSv?\s?1\.0|TLSv?\s?1\.1)\b[^\n]*\b(enabled|offered|accepted)\b', re.I)
_WEAK_CIPHER = re.compile(r'\b(Accepted|Preferred)\b[^\n]*\b(RC4|DES-CBC|3DES|NULL|EXP-|EXPORT|ADH|AECDH|MD5)\b', re.I)
_CERT_ISSUE = re.compile(r'self[\s\-]?signed|certificate\s+has\s+expired|expired\s+certificate|certificate.*expired', re.I)
_HEARTBLEED = re.compile(r'heartbleed[\s\S]{0,60}vulnerable|vulnerable[\s\S]{0,60}heartbleed', re.I)


def _parse_ports(output, findings, seen, tool):
    for port, proto, service, version in _NMAP_PORT.findall(output):
        version = (version or "").strip()
        _add(findings, seen, kb.explain_port(port, service, version), tool)
        for cve in kb.match_cve(version):
            _add(findings, seen, cve, tool)


def _parse_ssl(output, findings, seen, tool):
    if _WEAK_PROTO.search(output):
        _add(findings, seen, kb.explain_vuln("ssl_weak_protocol",
             evidence="Obsolete SSL/TLS protocol accepted"), tool)
    if _WEAK_CIPHER.search(output):
        _add(findings, seen, kb.explain_vuln("ssl_weak_cipher",
             evidence="Weak cipher suite accepted"), tool)
    if _CERT_ISSUE.search(output):
        _add(findings, seen, kb.explain_vuln("ssl_cert_issue",
             evidence="Untrusted/expired certificate"), tool)
    if _HEARTBLEED.search(output):
        _add(findings, seen, kb.explain_vuln("ssl_heartbleed",
             evidence="Heartbleed indicated by scanner"), tool)


def _parse_cve_banners(output, findings, seen, tool):
    """Match version banners anywhere in the output (e.g. nikto 'Server:')."""
    for m in re.finditer(r'(?:Server:|banner:|version)\s*([^\n]+)', output, re.I):
        for cve in kb.match_cve(m.group(1)):
            _add(findings, seen, cve, tool)


def _parse_credentials(output, findings, seen, tool):
    for _port, service, login, password in _HYDRA_CRED.findall(output):
        f = kb.explain_vuln(
            "weak_credentials",
            evidence=f"{service} login '{login}' with password '{password}'",
        )
        _add(findings, seen, f, tool)


def _parse_sqli(output, findings, seen, tool):
    if re.search(r'is vulnerable|identified the following injection|the back-end DBMS is',
                 output, re.I):
        m = _SQLMAP_PARAM.search(output)
        evidence = f"Injectable parameter: {m.group(1).strip()}" if m else "sqlmap flagged an injectable point"
        _add(findings, seen, kb.explain_vuln("sql_injection", evidence=evidence), tool)


def _parse_web(output, findings, seen, tool):
    if re.search(r'directory indexing|index of /', output, re.I):
        _add(findings, seen, kb.explain_vuln("directory_listing",
             evidence="Directory listing observed"), tool)
    if re.search(r'header is not present|is not (present|set|defined)', output, re.I):
        _add(findings, seen, kb.explain_vuln("missing_security_headers",
             evidence="Security header(s) missing"), tool)
    m = re.search(r'^\+?\s*Server:\s*(.+)$', output, re.M | re.I)
    if m and m.group(1).strip().lower() not in ("", "unknown"):
        _add(findings, seen, kb.explain_vuln("info_disclosure",
             evidence=f"Server banner: {m.group(1).strip()}"), tool)


def extract_findings(results, target=""):
    """
    results: list of dicts with 'tool_name' and 'tool_output'.
    Returns a severity-sorted list of enriched finding dicts.
    """
    findings, seen = [], set()
    for row in results or []:
        output = str(row.get("tool_output", "") or "")
        tool = row.get("tool_name", "tool")
        if not output.strip():
            continue
        _parse_ports(output, findings, seen, tool)
        _parse_credentials(output, findings, seen, tool)
        _parse_sqli(output, findings, seen, tool)
        _parse_web(output, findings, seen, tool)
        _parse_ssl(output, findings, seen, tool)
        _parse_cve_banners(output, findings, seen, tool)

    findings.sort(key=lambda f: (-kb.severity_rank(f.get("severity")), f.get("title", "")))
    return findings


def severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def client_summary(findings, target=""):
    """Plain-language, non-technical narrative lines for the client section."""
    if not findings:
        return [
            f"We tested {target or 'the target'} and did not automatically "
            f"detect notable weaknesses in the collected output. A manual "
            f"review is still recommended to confirm."
        ]
    counts = severity_counts(findings)
    lines = []
    headline = (f"We tested {target or 'the target'} and found "
                f"{len(findings)} item(s) worth attention")
    sev_bits = [f"{n} {name}" for name, n in counts.items() if n]
    if sev_bits:
        headline += " (" + ", ".join(sev_bits) + ")"
    lines.append(headline + ".")
    # Lead with the most serious few, in plain words.
    for f in findings[:6]:
        lines.append(f"• {f['plain']} (What to do: {f['remediation']})")
    if len(findings) > 6:
        lines.append(f"• ...and {len(findings) - 6} more, detailed in the technical section.")
    return lines
