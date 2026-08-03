#!/usr/bin/env python3
"""
PHANTOM SCHEDULED ASSESSMENT RUNNER

Runs an unattended, read-only re-assessment of an authorised target and
regenerates the client report — designed to be driven by cron/systemd so you
can offer "continuous monitoring" retainers.

Safety model (important):
  * It NEVER bypasses the scope gate. The target must already be in the approved
    scope (phantom_scope) or the run is refused. Scheduling cannot authorise a
    target that a human didn't.
  * The default profile is strictly NON-INTRUSIVE (service discovery + light web
    checks). No exploitation, brute force, or destructive actions.
  * It stores each run's results so the next run can produce a change/diff.

Email delivery is OPTIONAL and OFF by default. It only sends when you pass a
full SMTP config (your own server/credentials) and a recipient — i.e. you are
sending your own mail, deliberately. Nothing is sent automatically otherwise.

CLI (cron example — weekly):
    python3 src/phantom_schedule.py --target acme.co.uk --framework cyber_essentials
"""

import os
import json
import shutil
import datetime
import subprocess

try:
    import phantom_scope as scope_mod
    import phantom_findings as findings_mod
    import phantom_frameworks as frameworks
    import phantom_retest as retest
    import phantom_reports as reports
except ImportError:  # imported as src.phantom_schedule
    from src import phantom_scope as scope_mod
    from src import phantom_findings as findings_mod
    from src import phantom_frameworks as frameworks
    from src import phantom_retest as retest
    from src import phantom_reports as reports

STATE_DIR = os.path.expanduser("~/.phantom/schedule")

# Non-intrusive default commands. {t} is replaced by the target. Only commands
# whose tool is installed are run; the rest are skipped.
SAFE_PROFILE = [
    ("nmap", "nmap -sV -Pn -T3 --top-ports 200 {t}"),
    ("nikto", "nikto -host {t} -maxtime 120s"),
    ("whatweb", "whatweb {t}"),
]


def _state_path(target):
    safe = "".join(c if c.isalnum() else "_" for c in target)
    return os.path.join(STATE_DIR, f"{safe}.json")


def _load_previous(target):
    try:
        with open(_state_path(target)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _save_state(target, results):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(_state_path(target), "w") as fh:
            json.dump({"target": target,
                       "timestamp": datetime.datetime.now().isoformat(),
                       "results": results}, fh, indent=2)
    except OSError:
        pass


def run_scheduled_assessment(target, engagement=None, framework="cyber_essentials",
                             profile=None, scope=None):
    """
    Run a non-intrusive re-assessment. Returns a result dict:
        {"ok", "reason", "results", "report", "diff"}
    Refuses if the target is not in the approved scope.
    """
    target = (target or "").strip()
    if not target:
        return {"ok": False, "reason": "No target given."}

    scope = scope or scope_mod.ScopeManager()
    # Enforce the scope gate: scheduling must not run on unauthorised targets.
    if getattr(scope, "enforced", True) and not scope.is_in_scope(target):
        return {"ok": False,
                "reason": f"'{target}' is not in the approved scope. Add it in "
                          f"PHANTOM's Scope tab first — scheduling cannot "
                          f"authorise a target on its own."}

    profile = profile or SAFE_PROFILE
    results = []
    for tool, template in profile:
        if not shutil.which(tool):
            continue
        cmd = template.format(t=target)
        allowed, reason = scope_mod.authorize_command(cmd, tool, scope)
        if not allowed:
            results.append({"tool_name": tool, "tool_output": f"[SKIPPED] {reason}"})
            continue
        try:
            out = subprocess.run(cmd.split(), capture_output=True, text=True,
                                 timeout=300).stdout
        except (subprocess.SubprocessError, OSError) as e:
            out = f"[ERROR] {e}"
        results.append({"tool_name": tool, "tool_output": out})

    # Change tracking vs the previous run.
    previous = _load_previous(target)
    diff = None
    if previous:
        diff = retest.diff_from_results(previous.get("results", []), results, target)
    _save_state(target, results)

    # Build the framework report.
    scan_data = {"scan": {"target": target,
                          "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                          "scan_type": f"Scheduled {framework} assessment"},
                 "results": results}
    engagement = dict(engagement or {})
    engagement.setdefault("scope", [target])
    reporter = reports.PhantomReporter(scan_data=scan_data, engagement=engagement)
    report_path = reporter.generate_framework_report(framework)

    return {"ok": True, "reason": "", "results": results,
            "report": report_path, "diff": diff}


def send_report(smtp_config, to_addr, report_path, subject=None, body=None):
    """
    Email a report via YOUR OWN SMTP server. OFF by default — only runs when
    called with a full smtp_config. You are sending your own mail deliberately.

    smtp_config = {host, port, user, password, use_tls(bool), from_addr}
    """
    import smtplib
    from email.message import EmailMessage

    required = {"host", "port", "from_addr"}
    if not smtp_config or not required.issubset(smtp_config):
        return {"ok": False, "reason": "Incomplete SMTP config; email not sent."}
    if not report_path or not os.path.isfile(report_path):
        return {"ok": False, "reason": "Report file not found; email not sent."}

    msg = EmailMessage()
    msg["Subject"] = subject or "Your security assessment report"
    msg["From"] = smtp_config["from_addr"]
    msg["To"] = to_addr
    msg.set_content(body or "Please find your latest security assessment attached.")
    with open(report_path, "rb") as fh:
        msg.add_attachment(fh.read(), maintype="text", subtype="html",
                           filename=os.path.basename(report_path))
    try:
        with smtplib.SMTP(smtp_config["host"], int(smtp_config["port"]), timeout=30) as s:
            if smtp_config.get("use_tls", True):
                s.starttls()
            if smtp_config.get("user"):
                s.login(smtp_config["user"], smtp_config.get("password", ""))
            s.send_message(msg)
        return {"ok": True, "reason": f"Sent to {to_addr}"}
    except Exception as e:
        return {"ok": False, "reason": f"Send failed: {e}"}


def _main():
    import argparse
    ap = argparse.ArgumentParser(description="PHANTOM scheduled assessment runner")
    ap.add_argument("--target", required=True)
    ap.add_argument("--framework", default="cyber_essentials")
    ap.add_argument("--client", default="")
    args = ap.parse_args()

    eng = {"client_name": args.client} if args.client else {}
    res = run_scheduled_assessment(args.target, engagement=eng,
                                   framework=args.framework)
    if res["ok"]:
        print(f"✓ Report: {res['report']}")
        if res.get("diff"):
            print("Change: " + retest.headline(res["diff"]))
    else:
        print(f"✗ {res['reason']}")


if __name__ == "__main__":
    _main()
