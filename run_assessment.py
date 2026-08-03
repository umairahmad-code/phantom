#!/usr/bin/env python3
"""
PHANTOM — one-command assessment + report runner.

Runs an assessment against a domain and produces the client deliverables
(framework readiness report + one-page executive summary).

SAFETY / AUTHORISATION
----------------------
* PASSIVE checks (email/domain spoofing via DNS, attack-surface discovery via
  public certificate logs) send NO traffic to the target and are safe on any
  domain. They run by default.
* ACTIVE checks (nmap / nikto / whatweb / sslscan) DO probe the target's
  servers. They only run when you pass --authorized, which asserts that you own
  the domain or hold written permission to test it. Scanning without permission
  is illegal in most jurisdictions.

Usage:
    python3 run_assessment.py example.com --client "Example Ltd"
    python3 run_assessment.py example.com --client "Example Ltd" --authorized
    python3 run_assessment.py example.com --framework gdpr_lite --authorized

Reports are written to ~/.phantom/reports/ and their paths printed at the end.
"""

import os
import sys
import shutil
import tempfile
import datetime
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

import phantom_scope as scope_mod          # noqa: E402
import phantom_asm as asm                  # noqa: E402
import phantom_email_security as emailsec  # noqa: E402
import phantom_reports as reports          # noqa: E402

# Non-intrusive active profile. {t} -> target. Only run if the tool exists.
ACTIVE_PROFILE = [
    ("nmap", "nmap -sV -Pn -T3 --top-ports 200 {t}"),
    ("whatweb", "whatweb {t}"),
    ("sslscan", "sslscan {t}"),
    ("nikto", "nikto -host {t} -maxtime 120s"),
]


def _temp_scope(target):
    """An isolated, authorised scope for this run (does not touch ~/.phantom/scope.json)."""
    tmp = os.path.join(tempfile.gettempdir(),
                       f"phantom_scope_{os.getpid()}.json")
    sm = scope_mod.ScopeManager(path=tmp)
    sm.targets = [target]
    sm.enforced = True
    return sm, tmp


def run_active(target, scope):
    """Run the non-intrusive active profile through the scope gate."""
    results = []
    for tool, template in ACTIVE_PROFILE:
        if not shutil.which(tool):
            print(f"  · {tool}: not installed, skipped")
            continue
        cmd = template.format(t=target)
        allowed, reason = scope_mod.authorize_command(cmd, tool, scope)
        if not allowed:
            print(f"  · {tool}: blocked by scope gate ({reason})")
            continue
        print(f"  · {tool}: running...", flush=True)
        try:
            out = subprocess.run(cmd.split(), capture_output=True, text=True,
                                 timeout=300).stdout
        except subprocess.TimeoutExpired:
            out = f"[TIMEOUT] {tool} exceeded time limit"
        except (subprocess.SubprocessError, OSError) as e:
            out = f"[ERROR] {e}"
        results.append({"tool_name": tool, "tool_output": out})
    return results


def main():
    import argparse
    ap = argparse.ArgumentParser(description="PHANTOM assessment runner")
    ap.add_argument("domain")
    ap.add_argument("--client", default="")
    ap.add_argument("--framework", default="cyber_essentials")
    ap.add_argument("--authorized", action="store_true",
                    help="I own this domain or hold written permission to test it "
                         "(enables active scanning).")
    args = ap.parse_args()

    target = args.domain.strip().lower()
    client = args.client or target
    print(f"\nPHANTOM assessment — {target}  (client: {client})")
    print("=" * 60)

    # ── Passive (always safe) ──────────────────────────────────
    print("\n[1] Attack-surface discovery (passive)...")
    surface = asm.discover(target)
    s = surface["summary"]
    print(f"    {s['subdomains']} name(s), {s['live']} live, {s['unique_ips']} IP(s) "
          f"[source: {surface['source']}]")
    if surface.get("note"):
        print(f"    note: {surface['note']}")

    print("\n[2] Email/domain spoofing check (passive)...")
    email = emailsec.assess_email_security(target)
    print(f"    grade {email['score']['grade']} · "
          f"{'SPOOFABLE' if email['spoofable'] else 'protected'}")
    for f in email["findings"]:
        print(f"      - {f['title']}")

    # ── Active (only with authorisation) ───────────────────────
    results = []
    if args.authorized:
        print("\n[3] Active scan (authorised)...")
        scope, tmp = _temp_scope(target)
        try:
            results = run_active(target, scope)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
    else:
        print("\n[3] Active scan SKIPPED — pass --authorized to enable "
              "(only if you own / have permission to test this domain).")

    # ── Report ─────────────────────────────────────────────────
    print("\n[4] Generating reports...")
    scan_data = {
        "scan": {"target": target,
                 "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                 "scan_type": f"{args.framework} readiness assessment"},
        "results": results,
    }
    engagement = {
        "client_name": client,
        "scope": [target],
        "domain": target,
        "include_email": True,
        "authorization_ref": ("Operator-asserted authorisation"
                              if args.authorized else "Passive assessment only"),
    }
    try:
        import phantom_branding as branding
        engagement = branding.apply_to_engagement(engagement)
    except Exception:
        pass

    gen = reports.PhantomReporter(scan_data=scan_data, engagement=engagement)
    report = gen.generate_framework_report(args.framework)
    gen2 = reports.PhantomReporter(scan_data=scan_data, engagement=engagement)
    summary = gen2.generate_exec_summary(args.framework)

    print("\n" + "=" * 60)
    print("Done. Deliverables:")
    if report:
        print(f"  Full report:      {report}")
    if summary:
        print(f"  Exec summary:     {summary}")
    if not results:
        print("\nNote: report is based on PASSIVE checks only. Re-run with "
              "--authorized for a full external assessment.")


if __name__ == "__main__":
    main()
