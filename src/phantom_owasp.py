#!/usr/bin/env python3
"""
PHANTOM OWASP + CVSS ENRICHMENT

Adds two things clients and compliance auditors expect on every finding:

  * OWASP Top 10 (2021) category   — the recognised risk taxonomy
  * an indicative CVSS v3.1 base score + severity band

IMPORTANT / honesty note
------------------------
The CVSS score here is *indicative*: it is derived from a representative base
vector for each finding class, not computed from the exact environmental
metrics of the target. It gives clients a consistent, defensible severity
number for triage and reporting — it is clearly labelled "indicative" in the
reports so it is never mistaken for a hand-scored, environment-specific vector.

Findings are the enriched dicts from phantom_findings / phantom_knowledge, keyed
by ``kind``. Enrichment is additive (adds ``owasp`` and ``cvss`` keys) and never
overwrites values a finding already carries.
"""

# ── OWASP Top 10 : 2021 ───────────────────────────────────────────────
OWASP_2021 = {
    "A01": "A01:2021 – Broken Access Control",
    "A02": "A02:2021 – Cryptographic Failures",
    "A03": "A03:2021 – Injection",
    "A04": "A04:2021 – Insecure Design",
    "A05": "A05:2021 – Security Misconfiguration",
    "A06": "A06:2021 – Vulnerable and Outdated Components",
    "A07": "A07:2021 – Identification and Authentication Failures",
    "A08": "A08:2021 – Software and Data Integrity Failures",
    "A09": "A09:2021 – Security Logging and Monitoring Failures",
    "A10": "A10:2021 – Server-Side Request Forgery (SSRF)",
}

# finding kind -> OWASP category id
_KIND_TO_OWASP = {
    "cve": "A06",
    "outdated_service": "A06",
    "unpatched_service": "A06",
    "eol_software": "A06",
    "ssl_heartbleed": "A06",
    "sql_injection": "A03",
    "xss": "A03",
    "rce": "A03",
    "command_injection": "A03",
    "weak_credentials": "A07",
    "weak_authentication": "A07",
    "default_credentials": "A07",
    "ssl_weak_protocol": "A02",
    "ssl_weak_cipher": "A02",
    "ssl_cert_issue": "A02",
    "cleartext_protocol": "A02",
    "missing_security_headers": "A05",
    "directory_listing": "A05",
    "info_disclosure": "A05",
    "open_port": "A05",
    "exposed_service": "A05",
    "ssrf": "A10",
}

# Representative CVSS v3.1 base scores per finding class (indicative).
# Chosen to line up with the finding's own severity band and with how a human
# assessor would typically score that class on an external test.
_KIND_TO_CVSS = {
    "cve": 9.8,
    "ssl_heartbleed": 7.5,
    "outdated_service": 7.5,
    "unpatched_service": 7.5,
    "eol_software": 7.5,
    "sql_injection": 9.8,
    "rce": 9.8,
    "command_injection": 9.8,
    "xss": 6.1,
    "weak_credentials": 9.8,
    "default_credentials": 9.8,
    "weak_authentication": 8.1,
    "ssl_weak_protocol": 7.4,
    "cleartext_protocol": 7.4,
    "ssl_weak_cipher": 5.9,
    "ssl_cert_issue": 5.3,
    "missing_security_headers": 4.3,
    "directory_listing": 5.3,
    "info_disclosure": 5.3,
    "open_port": 3.7,
    "exposed_service": 5.3,
    "ssrf": 8.6,
}

# Fallback CVSS by the finding's textual severity, when kind is unknown.
_SEVERITY_TO_CVSS = {
    "critical": 9.5, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0,
}


def cvss_band(score):
    """CVSS v3.1 qualitative severity band for a base score."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def owasp_for(finding):
    """Return (id, label) OWASP Top-10 category for a finding, or (None, '')."""
    kind = str(finding.get("kind", "")).lower()
    oid = _KIND_TO_OWASP.get(kind)
    if not oid:
        # Heuristic fallbacks for kinds we haven't mapped explicitly.
        if kind.startswith("email_"):
            oid = "A05"
        elif "inject" in kind:
            oid = "A03"
        elif "cred" in kind or "auth" in kind or "password" in kind:
            oid = "A07"
        elif "ssl" in kind or "tls" in kind or "crypt" in kind:
            oid = "A02"
    return (oid, OWASP_2021.get(oid, "")) if oid else (None, "")


def cvss_for(finding):
    """Return an indicative CVSS base score (float) for a finding."""
    kind = str(finding.get("kind", "")).lower()
    if kind in _KIND_TO_CVSS:
        return _KIND_TO_CVSS[kind]
    sev = str(finding.get("severity", "info")).lower()
    return _SEVERITY_TO_CVSS.get(sev, 0.0)


def enrich(findings):
    """
    Add ``owasp`` and ``cvss`` fields to each finding (additive, in place).

    ``owasp`` -> {"id": "A03", "label": "A03:2021 – Injection"}  (or absent)
    ``cvss``  -> {"score": 9.8, "band": "critical", "indicative": True}
    Returns the same list for convenience.
    """
    for f in findings or []:
        if "owasp" not in f:
            oid, label = owasp_for(f)
            if oid:
                f["owasp"] = {"id": oid, "label": label}
        if "cvss" not in f:
            score = cvss_for(f)
            f["cvss"] = {"score": score, "band": cvss_band(score),
                         "indicative": True}
    return findings


def coverage(findings):
    """Summarise which OWASP categories the findings touch (for reporting)."""
    hits = {}
    for f in findings or []:
        oid, label = owasp_for(f)
        if oid:
            hits.setdefault(oid, {"label": label, "count": 0})
            hits[oid]["count"] += 1
    # Return ordered A01..A10 with counts (0 where untouched).
    ordered = []
    for oid in sorted(OWASP_2021):
        entry = hits.get(oid)
        ordered.append({
            "id": oid, "label": OWASP_2021[oid],
            "count": entry["count"] if entry else 0,
        })
    return ordered


if __name__ == "__main__":
    sample = [
        {"kind": "cve", "severity": "critical"},
        {"kind": "sql_injection", "severity": "critical"},
        {"kind": "weak_credentials", "severity": "critical"},
        {"kind": "missing_security_headers", "severity": "low"},
        {"kind": "ssl_weak_protocol", "severity": "high"},
    ]
    for f in enrich(sample):
        print(f"{f['kind']:>24}  CVSS {f['cvss']['score']:<4} "
              f"({f['cvss']['band']:<8})  {f.get('owasp',{}).get('label','—')}")
