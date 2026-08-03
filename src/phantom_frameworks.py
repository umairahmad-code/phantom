#!/usr/bin/env python3
"""
PHANTOM COMPLIANCE FRAMEWORKS

Maps the same scan findings onto several assessment frameworks, so one scan can
be sold as several deliverables:

  * cyber_essentials  — UK Cyber Essentials (5 technical controls)
  * iasme             — IASME Cyber Assurance (CE + governance areas)
  * gdpr_lite         — GDPR Article 32 "security of processing" (data-security)
  * pci_lite          — externally-checkable subset of the PCI DSS SAQ

Every framework produces the SAME assessment structure as phantom_ce.assess
(verdict / controls / roadmap / counts) so a single report renderer serves them
all. Cyber Essentials delegates to phantom_ce (one source of truth); the others
use a shared "theme" engine below.

Optionally ingests the output of phantom_internal_check.py to turn the
"Verify Internally" controls into real PASS/ACTION results.
"""

try:
    import phantom_ce as ce
    import phantom_knowledge as kb
except ImportError:  # imported as src.phantom_frameworks
    from src import phantom_ce as ce
    from src import phantom_knowledge as kb

PASS, ACTION, ADVISORY, VERIFY = ce.PASS, ce.ACTION, ce.ADVISORY, ce.VERIFY
_RANK = {PASS: 0, ADVISORY: 1, VERIFY: 2, ACTION: 3}


# ── Finding → themes ──────────────────────────────────────────────────
# Each finding contributes one or more (theme, blocking) tuples. Frameworks
# then decide which themes belong to which of their controls.
def _themes(finding):
    kind = str(finding.get("kind", "")).lower()
    out = []
    if kind in ("cve", "outdated_service", "unpatched_service", "ssl_heartbleed"):
        out.append(("patch", True))
    if kind == "weak_credentials":
        out.append(("access", True))
    if kind in ("cleartext_protocol", "ssl_weak_protocol"):
        out.append(("tls", True))
    if kind in ("ssl_weak_cipher", "ssl_cert_issue"):
        out.append(("tls", False))
    if kind in ("sql_injection", "xss", "rce"):
        out.append(("webapp", True))
    if kind in ("missing_security_headers", "directory_listing", "info_disclosure"):
        out.append(("config", False))
    if kind.startswith("email_"):
        blocking = str(finding.get("severity", "")).lower() in ("high", "medium")
        out.append(("email", blocking))
    port = finding.get("port")
    if port is not None:
        try:
            p = int(port)
            if p in ce._CRITICAL_EXPOSURE_PORTS:
                out.append(("boundary", True))
            elif p in ce._NOTABLE_PORTS:
                out.append(("access", False))
                out.append(("boundary", False))
            elif p not in ce._EXPECTED_PORTS:
                out.append(("boundary", False))
        except (ValueError, TypeError):
            pass
    return out


# ── Framework specs ───────────────────────────────────────────────────
# control: (id, name, about, themes, external)
_SPECS = {
    "gdpr_lite": {
        "name": "GDPR Data Security",
        "subtitle": "Article 32 — Security of Processing",
        "controls": [
            ("encryption_transit", "Encryption in Transit",
             "Personal data must be encrypted when travelling over networks.",
             {"tls"}, True),
            ("access_control", "Access Control",
             "Only authorised people should be able to reach personal data.",
             {"access"}, True),
            ("system_security", "System Security & Patching",
             "Systems processing personal data must be kept secure and updated.",
             {"patch", "config", "boundary"}, True),
            ("app_security", "Application Security",
             "Web applications handling personal data must resist common attacks.",
             {"webapp"}, True),
            ("email_security", "Email & Anti-Phishing",
             "Guard against spoofing that leads to personal-data breaches.",
             {"email"}, True),
            ("resilience", "Confidentiality & Resilience",
             "Backups, availability and staff processes (verified internally).",
             set(), False),
        ],
    },
    "pci_lite": {
        "name": "PCI DSS (External Subset)",
        "subtitle": "Externally-checkable SAQ controls",
        "controls": [
            ("secure_network", "Secure Network & Firewalls",
             "Only required services exposed; no risky ports open to the internet.",
             {"boundary"}, True),
            ("no_defaults", "No Default / Weak Credentials",
             "Vendor defaults and weak passwords must be removed.",
             {"access"}, True),
            ("encrypt_transmission", "Encrypt Transmission of Data",
             "Cardholder data in transit must use strong cryptography.",
             {"tls"}, True),
            ("patch_systems", "Maintain & Patch Systems",
             "Systems must run supported, patched software.",
             {"patch", "config"}, True),
            ("secure_apps", "Secure Web Applications",
             "Public web apps must resist injection and common attacks.",
             {"webapp"}, True),
            ("anti_malware", "Anti-Malware",
             "All systems need anti-malware (verified on the devices).",
             set(), False),
        ],
    },
    "iasme": {
        "name": "IASME Cyber Assurance",
        "subtitle": "Cyber Essentials controls + governance",
        "controls": [
            ("firewalls", "Firewalls & Boundary",
             "Only necessary services exposed to the internet.",
             {"boundary"}, True),
            ("secure_config", "Secure Configuration",
             "No insecure defaults, weak crypto, or information leaks.",
             {"config", "tls", "webapp"}, True),
            ("update_mgmt", "Security Update Management",
             "Supported, patched software only.",
             {"patch"}, True),
            ("access_control", "User Access Control",
             "Strong, least-privilege account control.",
             {"access"}, True),
            ("malware", "Malware Protection",
             "Anti-malware on every device (verified internally).",
             set(), False),
            ("governance", "Backup & Governance",
             "Backups, policies, staff awareness and incident response "
             "(verified internally).", set(), False),
        ],
    },
}


def available():
    """List selectable framework ids and display names."""
    out = [("cyber_essentials", "Cyber Essentials")]
    out += [(fid, spec["name"]) for fid, spec in _SPECS.items()]
    return out


def _generic_assess(spec, findings, target, scope):
    findings = findings or []
    # theme -> list of blocking flags observed
    theme_hits = {}
    theme_findings = {}
    for f in findings:
        for theme, blocking in _themes(f):
            theme_hits.setdefault(theme, []).append(blocking)
            theme_findings.setdefault(theme, []).append((f, blocking))

    controls_out, blocking_total, advisory_total = [], 0, 0
    for cid, name, about, themes, external in spec["controls"]:
        if not external:
            controls_out.append({
                "id": cid, "name": name, "about": about, "external": False,
                "status": VERIFY, "findings": [],
                "note": "Not observable from an external scan — confirm on the "
                        "devices / with the organisation's processes.",
            })
            continue
        statuses, area_findings = [], []
        for theme in themes:
            for f, blocking in theme_findings.get(theme, []):
                st = ACTION if blocking else ADVISORY
                statuses.append(st)
                area_findings.append({
                    "title": f.get("title", "Finding"),
                    "severity": str(f.get("severity", "info")).lower(),
                    "status": st, "plain": f.get("plain", ""),
                    "remediation": f.get("remediation", ""),
                    "evidence": f.get("evidence", ""),
                })
        status = max(statuses, key=lambda s: _RANK[s]) if statuses else PASS
        # de-dup + sort
        seen, deduped = set(), []
        for af in sorted(area_findings, key=lambda a: -kb.severity_rank(a["severity"])):
            key = (af["title"], af["evidence"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(af)
            if af["status"] == ACTION:
                blocking_total += 1
            elif af["status"] == ADVISORY:
                advisory_total += 1
        controls_out.append({
            "id": cid, "name": name, "about": about, "external": True,
            "status": status, "findings": deduped,
            "note": ("No issues affecting this control were observed externally."
                     if status == PASS else None),
        })

    if blocking_total:
        verdict = {"status": "NOT YET READY",
                   "headline": f"{blocking_total} issue(s) need resolving before "
                               f"this framework's requirements are met.",
                   "blocking": blocking_total, "advisory": advisory_total}
    elif advisory_total:
        verdict = {"status": "ON TRACK",
                   "headline": f"No blocking issues externally; {advisory_total} "
                               f"good-practice item(s) to tidy up.",
                   "blocking": 0, "advisory": advisory_total}
    else:
        verdict = {"status": "LIKELY TO PASS",
                   "headline": "No externally-observable issues. Confirm the "
                               "internal controls to be assessment-ready.",
                   "blocking": 0, "advisory": 0}

    roadmap = ce.assess(findings, target, scope)["roadmap"]  # reuse roadmap logic
    counts = ce._severity_counts(findings)
    return {"target": target, "scope": scope or (target and [target]) or [],
            "verdict": verdict, "controls": controls_out,
            "roadmap": roadmap, "counts": counts}


def assess(framework_id, findings, target="", scope=None, internal_results=None):
    """Assess findings against the named framework."""
    if framework_id in ("cyber_essentials", "ce"):
        result = ce.assess(findings, target=target, scope=scope)
        result["framework"] = {"id": "cyber_essentials",
                               "name": "Cyber Essentials",
                               "subtitle": "5 technical controls"}
    elif framework_id in _SPECS:
        spec = _SPECS[framework_id]
        result = _generic_assess(spec, findings, target, scope)
        result["framework"] = {"id": framework_id, "name": spec["name"],
                               "subtitle": spec["subtitle"]}
    else:
        raise ValueError(f"Unknown framework: {framework_id}")

    if internal_results:
        _apply_internal(result, internal_results)
    return result


# ── Internal-controls ingestion ───────────────────────────────────────
# Maps phantom_internal_check.py output onto framework controls, upgrading
# "Verify Internally" to real PASS/ACTION where we now have evidence.
_INTERNAL_TO_CONTROL = {
    "malware": ("malware", "anti_malware"),
    "firewall": ("firewalls", "secure_network"),
    "disk_encryption": ("encryption_transit", "resilience", "governance"),
    "auto_updates": ("update_mgmt", "patch_systems", "system_security"),
}


def _apply_internal(result, internal_results):
    checks = {c["control"]: c for c in internal_results.get("checks", [])}
    by_id = {c["id"]: c for c in result["controls"]}
    added_block = 0
    for internal_key, control_ids in _INTERNAL_TO_CONTROL.items():
        chk = checks.get(internal_key)
        if not chk:
            continue
        for cid in control_ids:
            ctrl = by_id.get(cid)
            if not ctrl:
                continue
            if chk["status"] == "pass" and ctrl["status"] == VERIFY:
                ctrl["status"] = PASS
                ctrl["note"] = f"Confirmed on device: {chk['detail']}"
            elif chk["status"] == "fail":
                ctrl["status"] = ACTION
                ctrl["findings"].append({
                    "title": f"Internal control failing: {internal_key}",
                    "severity": "high", "status": ACTION,
                    "plain": chk["detail"],
                    "remediation": f"Enable/repair {internal_key} on {internal_results.get('host','the device')}.",
                    "evidence": chk["detail"],
                })
                added_block += 1
    if added_block:
        result["verdict"]["blocking"] += added_block
        if result["verdict"]["status"] != "NOT YET READY":
            result["verdict"]["status"] = "NOT YET READY"
            result["verdict"]["headline"] = (
                f"Internal control checks revealed {added_block} issue(s) to fix "
                f"before assessment.")
    result["internal"] = internal_results
    return result


if __name__ == "__main__":
    print("Frameworks:", ", ".join(f"{i} ({n})" for i, n in available()))
