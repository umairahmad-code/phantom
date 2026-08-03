#!/usr/bin/env python3
"""
PHANTOM — Cyber Essentials Readiness Mapper

Maps PHANTOM findings (from phantom_findings.extract_findings) onto the five
Cyber Essentials technical control areas and produces a per-area readiness
verdict plus a prioritised remediation roadmap.

The five Cyber Essentials controls:
    1. Firewalls
    2. Secure Configuration
    3. Security Update Management
    4. User Access Control
    5. Malware Protection

HONESTY NOTE (this is what keeps the deliverable credible):
An *external* assessment can only observe part of each control. Malware
Protection and most User Access Control / firewall *policy* live on the
endpoints and internal network and are invisible from outside. Those areas are
explicitly marked "VERIFY INTERNALLY" instead of being guessed at, and the
limitation is stated in the report. A readiness report that admits what it
cannot see is worth more to a client than one that fabricates a pass.
"""

try:
    import phantom_knowledge as kb
except ImportError:  # imported as src.phantom_ce
    from src import phantom_knowledge as kb


# ── Status vocabulary ─────────────────────────────────────────────────
PASS = "PASS"                       # no relevant issues observed externally
ACTION = "ACTION REQUIRED"          # blocking issue — would fail Cyber Essentials
ADVISORY = "ADVISORY"               # good-practice gap, not a strict CE failure
VERIFY = "VERIFY INTERNALLY"        # not assessable from an external scan

# Order used to roll a set of per-finding statuses up to one area status.
_STATUS_RANK = {PASS: 0, ADVISORY: 1, VERIFY: 2, ACTION: 3}


# ── The five controls, with plain-language framing for the client ─────
CONTROLS = [
    {
        "id": "firewalls",
        "name": "Firewalls & Boundary Protection",
        "about": "Only the services you actually need should be reachable from "
                 "the internet. Everything else should sit behind a firewall.",
        "external": True,
    },
    {
        "id": "secure_config",
        "name": "Secure Configuration",
        "about": "Systems and software should be set up securely — no default "
                 "settings, weak encryption, or information leaks.",
        "external": True,
    },
    {
        "id": "update_mgmt",
        "name": "Security Update Management",
        "about": "Software must be supported and patched. Known, unpatched "
                 "vulnerabilities are the most common way in.",
        "external": True,
    },
    {
        "id": "access_control",
        "name": "User Access Control",
        "about": "Accounts must use strong, unique credentials and least "
                 "privilege. Weak or default logins are an open door.",
        "external": True,
    },
    {
        "id": "malware",
        "name": "Malware Protection",
        "about": "Every device needs anti-malware protection. This is verified "
                 "on the devices themselves, not from an external scan.",
        "external": False,
    },
]

_CONTROL_NAME = {c["id"]: c["name"] for c in CONTROLS}


# Ports that should almost never be exposed directly to the internet.
# Presence of any of these fails the Firewalls control (unnecessary service).
_CRITICAL_EXPOSURE_PORTS = {
    21: "FTP (file transfer, cleartext)",
    23: "Telnet (remote shell, cleartext)",
    135: "MS RPC",
    139: "NetBIOS / SMB",
    445: "SMB file sharing",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL / MariaDB",
    3389: "Remote Desktop (RDP)",
    5432: "PostgreSQL",
    5900: "VNC remote desktop",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    2049: "NFS file sharing",
}

# Ports that are legitimate to expose but still worth a note (brute-force
# target / management surface).
_NOTABLE_PORTS = {22: "SSH remote administration"}

# Ports that are normal for a public presence — not flagged as a firewall issue.
_EXPECTED_PORTS = {80, 443, 25, 53, 587, 465, 993, 995}


def _port_of(finding):
    """Return int port for a port-type finding, else None."""
    p = finding.get("port")
    if p is None:
        return None
    try:
        return int(p)
    except (ValueError, TypeError):
        return None


def _classify(finding):
    """
    Map one finding to a list of (control_id, status) it affects.

    A finding can touch more than one control (e.g. an exposed Telnet port is
    both a Firewalls failure and a Secure Configuration failure).
    """
    kind = str(finding.get("kind", "")).lower()
    hits = []

    # ── Patch / update management ──────────────────────────────────
    if kind in ("cve", "outdated_service", "unpatched_service", "ssl_heartbleed"):
        hits.append(("update_mgmt", ACTION))

    # ── User access control ────────────────────────────────────────
    if kind == "weak_credentials":
        hits.append(("access_control", ACTION))

    # ── Secure configuration ───────────────────────────────────────
    if kind in ("cleartext_protocol", "ssl_weak_protocol", "sql_injection",
                "xss", "rce"):
        hits.append(("secure_config", ACTION))
    if kind in ("ssl_weak_cipher", "ssl_cert_issue", "directory_listing",
                "missing_security_headers", "info_disclosure"):
        hits.append(("secure_config", ADVISORY))

    # ── Firewalls / boundary (port-based) ──────────────────────────
    port = _port_of(finding)
    if port is not None:
        if port in _CRITICAL_EXPOSURE_PORTS:
            hits.append(("firewalls", ACTION))
            # Cleartext admin ports are also a secure-config failure.
            if port in (21, 23):
                hits.append(("secure_config", ACTION))
        elif port in _NOTABLE_PORTS:
            hits.append(("firewalls", ADVISORY))
            hits.append(("access_control", ADVISORY))
        elif port not in _EXPECTED_PORTS:
            hits.append(("firewalls", ADVISORY))

    return hits


def _area_status(statuses):
    """Roll a list of per-finding statuses up to the single worst status."""
    if not statuses:
        return PASS
    return max(statuses, key=lambda s: _STATUS_RANK.get(s, 0))


def assess(findings, target="", scope=None):
    """
    Turn a list of enriched findings into a Cyber Essentials readiness picture.

    Returns a dict the reporter renders directly:
        {
          "target", "scope",
          "verdict":   {status, headline, blocking, advisory},
          "controls":  [ {id, name, about, status, external, findings[], note}, ... ],
          "roadmap":   [ {priority, severity, action, control, title}, ... ],
          "counts":    {critical, high, medium, low, info},
        }
    """
    findings = findings or []

    # Bucket findings + statuses per control.
    buckets = {c["id"]: [] for c in CONTROLS}
    statuses = {c["id"]: [] for c in CONTROLS}
    for f in findings:
        for control_id, status in _classify(f):
            buckets[control_id].append((f, status))
            statuses[control_id].append(status)

    controls_out = []
    blocking_total = 0
    advisory_total = 0
    for c in CONTROLS:
        cid = c["id"]
        if not c["external"]:
            # Malware Protection — not externally assessable, always VERIFY.
            controls_out.append({
                "id": cid,
                "name": c["name"],
                "about": c["about"],
                "external": False,
                "status": VERIFY,
                "findings": [],
                "note": "Not observable from an external scan. Confirm that "
                        "anti-malware is installed, enabled, and updating on "
                        "every in-scope device (or that application "
                        "allow-listing is enforced).",
            })
            continue

        area_status = _area_status(statuses[cid])
        area_findings = []
        for f, st in buckets[cid]:
            area_findings.append({
                "title": f.get("title", "Finding"),
                "severity": str(f.get("severity", "info")).lower(),
                "status": st,
                "plain": f.get("plain", ""),
                "remediation": f.get("remediation", ""),
                "evidence": f.get("evidence", ""),
            })
            if st == ACTION:
                blocking_total += 1
            elif st == ADVISORY:
                advisory_total += 1

        # De-duplicate findings that landed in this area twice.
        seen = set()
        deduped = []
        for af in sorted(area_findings,
                         key=lambda a: -kb.severity_rank(a["severity"])):
            key = (af["title"], af["evidence"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(af)

        note = None
        if area_status == PASS:
            note = ("No issues affecting this control were observed externally. "
                    "Internal configuration should still be confirmed against "
                    "the Cyber Essentials requirements.")
        controls_out.append({
            "id": cid,
            "name": c["name"],
            "about": c["about"],
            "external": True,
            "status": area_status,
            "findings": deduped,
            "note": note,
        })

    # ── Overall verdict ────────────────────────────────────────────
    if blocking_total:
        verdict = {
            "status": "NOT YET READY",
            "headline": (f"{blocking_total} issue(s) would currently prevent a "
                         f"Cyber Essentials pass. All are fixable — see the "
                         f"remediation roadmap below."),
            "blocking": blocking_total,
            "advisory": advisory_total,
        }
    elif advisory_total:
        verdict = {
            "status": "ON TRACK",
            "headline": (f"No blocking issues were found externally. "
                         f"{advisory_total} good-practice item(s) should be "
                         f"tidied up, and the internal controls confirmed, "
                         f"before assessment."),
            "blocking": 0,
            "advisory": advisory_total,
        }
    else:
        verdict = {
            "status": "LIKELY TO PASS",
            "headline": ("No externally-observable issues were found. Confirm "
                         "the internal controls (malware protection, device "
                         "configuration, account policy) to be assessment-ready."),
            "blocking": 0,
            "advisory": 0,
        }

    # ── Prioritised roadmap (blocking first, by severity) ──────────
    roadmap = []
    ordered = sorted(
        findings,
        key=lambda f: -kb.severity_rank(f.get("severity")),
    )
    seen_actions = set()
    for f in ordered:
        hits = _classify(f)
        blocking_controls = [cid for cid, st in hits if st == ACTION]
        if not blocking_controls:
            continue
        cid = blocking_controls[0]
        action = f.get("remediation", "").strip()
        key = (action, f.get("evidence", ""))
        if not action or key in seen_actions:
            continue
        seen_actions.add(key)
        roadmap.append({
            "severity": str(f.get("severity", "info")).lower(),
            "action": action,
            "control": _CONTROL_NAME.get(cid, cid),
            "title": f.get("title", "Finding"),
        })
    for i, item in enumerate(roadmap, 1):
        item["priority"] = i

    counts = _severity_counts(findings)

    return {
        "target": target,
        "scope": scope or (target and [target]) or [],
        "verdict": verdict,
        "controls": controls_out,
        "roadmap": roadmap,
        "counts": counts,
    }


def _severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings or []:
        sev = str(f.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


if __name__ == "__main__":
    print("✓ Cyber Essentials mapper ready")
    print(f"✓ Controls: {', '.join(c['name'] for c in CONTROLS)}")
