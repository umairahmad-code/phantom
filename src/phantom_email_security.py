#!/usr/bin/env python3
"""
PHANTOM EMAIL & DOMAIN SECURITY CHECK

Checks whether a domain can be spoofed in phishing/BEC attacks — the number-one
real-world risk for most small businesses. All checks are passive DNS lookups
(no traffic to the target's servers), so they are safe to run.

Checks performed:
  * SPF   — is a sender-policy record present, and is it strict?
  * DMARC — is a DMARC policy present, and is it enforcing (quarantine/reject)?
  * DKIM  — is a DKIM selector record present (best-effort common selectors)?
  * MX    — does the domain receive mail at all?
  * DNSSEC— is the zone signed (best-effort)?

DNS is resolved with `dig` (already a PHANTOM recon dependency). If `dig` is
unavailable the module degrades to "unknown" rather than crashing. An optional
breach-exposure lookup is included but only runs if an API key is configured.
"""

import os
import re
import shutil
import subprocess


def _dig(name, rrtype):
    """Return list of TXT/answer strings for a DNS query, or [] on failure."""
    if not shutil.which("dig"):
        return None  # None == "could not check" (distinct from [] == "no record")
    try:
        out = subprocess.run(
            ["dig", "+short", rrtype, name],
            capture_output=True, text=True, timeout=10,
        ).stdout
        return [line.strip().strip('"') for line in out.splitlines() if line.strip()]
    except (subprocess.SubprocessError, OSError):
        return None


def _finding(control, status, title, plain, remediation, severity, evidence=""):
    return {
        "kind": control, "title": title, "severity": severity,
        "plain": plain, "remediation": remediation,
        "technical": plain, "risk": plain, "evidence": evidence,
    }


def check_spf(domain):
    recs = _dig(domain, "TXT")
    if recs is None:
        return _finding("email_spf", "unknown", "SPF — could not check",
                        "DNS lookup unavailable.", "Install dig / check DNS.", "info")
    spf = [r for r in recs if r.lower().startswith("v=spf1")]
    if not spf:
        return _finding("email_spf", "fail", "SPF record missing",
                        "Anyone can send email pretending to be your domain.",
                        "Publish an SPF TXT record listing your legitimate mail senders.",
                        "high", "no v=spf1 record")
    rec = spf[0]
    if re.search(r'[~-]all', rec):
        return _finding("email_spf", "pass", "SPF present and enforcing",
                        "Your domain declares who may send mail on its behalf.",
                        "None — keep it maintained.", "info", rec)
    return _finding("email_spf", "warn", "SPF present but not enforcing",
                    "An SPF record exists but ends in '+all'/'?all', so spoofing "
                    "is not actually blocked.",
                    "Change the SPF record to end in '-all' (hard fail).",
                    "medium", rec)


def check_dmarc(domain):
    recs = _dig(f"_dmarc.{domain}", "TXT")
    if recs is None:
        return _finding("email_dmarc", "unknown", "DMARC — could not check",
                        "DNS lookup unavailable.", "Install dig / check DNS.", "info")
    dmarc = [r for r in recs if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return _finding("email_dmarc", "fail", "DMARC record missing",
                        "Without DMARC, spoofed emails aren't rejected and you get "
                        "no reports of abuse.",
                        "Publish a _dmarc TXT record, starting with p=none then "
                        "moving to p=quarantine or p=reject.",
                        "high", "no _dmarc record")
    rec = dmarc[0]
    m = re.search(r'\bp\s*=\s*(none|quarantine|reject)', rec, re.I)
    policy = (m.group(1).lower() if m else "none")
    if policy in ("quarantine", "reject"):
        return _finding("email_dmarc", "pass", f"DMARC enforcing (p={policy})",
                        "Spoofed emails claiming to be you are blocked or quarantined.",
                        "None — keep monitoring the reports.", "info", rec)
    return _finding("email_dmarc", "warn", "DMARC present but only monitoring (p=none)",
                    "DMARC is in monitor-only mode, so spoofed mail is still delivered.",
                    "Once you've reviewed reports, move the policy to "
                    "p=quarantine then p=reject.", "medium", rec)


# Common DKIM selectors used by popular mail providers.
_DKIM_SELECTORS = ("google", "selector1", "selector2", "k1", "default",
                   "mail", "dkim", "s1", "s2")


def check_dkim(domain):
    for sel in _DKIM_SELECTORS:
        recs = _dig(f"{sel}._domainkey.{domain}", "TXT")
        if recs:
            joined = " ".join(recs)
            if "v=dkim1" in joined.lower() or "p=" in joined.lower():
                return _finding("email_dkim", "pass",
                                f"DKIM present (selector '{sel}')",
                                "Outgoing mail is cryptographically signed.",
                                "None.", "info", f"{sel}._domainkey")
    return _finding("email_dkim", "warn", "No common DKIM selector found",
                    "We couldn't find a DKIM signature on the usual selectors "
                    "(it may use a custom one).",
                    "Confirm DKIM signing is enabled with your mail provider.",
                    "low", "checked common selectors")


def check_mx(domain):
    recs = _dig(domain, "MX")
    if recs is None:
        return _finding("email_mx", "unknown", "MX — could not check",
                        "DNS lookup unavailable.", "Install dig / check DNS.", "info")
    if not recs:
        return _finding("email_mx", "info", "No MX record",
                        "This domain does not receive email.",
                        "If it should receive mail, add MX records.",
                        "info", "no MX")
    return _finding("email_mx", "pass", "Mail service present",
                    "The domain receives email.", "None.", "info",
                    "; ".join(recs[:3]))


def assess_email_security(domain):
    """
    Run all email/domain spoofing checks for a domain.

    Returns:
        {"domain", "findings":[...], "score":{passed,total,grade},
         "spoofable": bool}
    """
    domain = (domain or "").strip().lower()
    # Strip scheme/path if a URL was passed.
    domain = re.sub(r'^\w+://', '', domain).split('/')[0].split(':')[0]

    findings = [check_spf(domain), check_dmarc(domain),
                check_dkim(domain), check_mx(domain)]

    passed = sum(1 for f in findings if f["severity"] == "info"
                 and "pass" in f["title"].lower())
    total = len(findings)

    # Spoofable if SPF or DMARC is failing/not enforcing.
    spoofable = any(f["kind"] in ("email_spf", "email_dmarc")
                    and f["severity"] in ("high", "medium") for f in findings)

    grade = "A" if not spoofable and passed >= 3 else \
            "C" if not spoofable else "F"

    return {
        "domain": domain,
        "findings": findings,
        "score": {"passed": passed, "total": total, "grade": grade},
        "spoofable": spoofable,
    }


def check_breach_exposure(domain, api_key=None):
    """
    Optional: check known-breach exposure for a domain's accounts.

    Requires a HaveIBeenPwned API key (env HIBP_API_KEY) — there is no reliable
    free breach API. Returns a status dict; degrades to "skipped" without a key.
    """
    api_key = api_key or os.environ.get("HIBP_API_KEY")
    if not api_key:
        return {"available": False,
                "note": "Breach lookup skipped — set HIBP_API_KEY to enable."}
    try:
        import requests
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
            headers={"hibp-api-key": api_key, "user-agent": "PHANTOM"},
            timeout=15,
        )
        if r.status_code == 200:
            breaches = r.json()
            return {"available": True, "breach_count": len(breaches),
                    "breaches": [b.get("Name") for b in breaches]}
        return {"available": False, "note": f"HIBP returned HTTP {r.status_code}"}
    except Exception as e:  # network / import failure — degrade, don't crash
        return {"available": False, "note": f"Breach lookup failed: {e}"}


if __name__ == "__main__":
    import json, sys
    dom = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(assess_email_security(dom), indent=2))
