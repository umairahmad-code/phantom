#!/usr/bin/env python3
"""
PHANTOM INTERNAL CONTROLS CHECKER  (client-run agent)

The external scan cannot see a device's malware protection, firewall, disk
encryption, or update settings — the parts of Cyber Essentials that are
"Verify Internally". This small, dependency-free script runs ON the client's
own machine, checks those controls, and writes a JSON file the assessor feeds
back into PHANTOM to complete the Cyber Essentials report (and unlock CE PLUS).

It is READ-ONLY: it only inspects status, never changes settings. Cross-platform
best-effort (Linux / Windows / macOS); anything it can't determine is reported
as "unknown" rather than guessed.

Usage (on the client's device):
    python3 phantom_internal_check.py > phantom_internal.json
Then import phantom_internal.json in PHANTOM's report step.
"""

import os
import sys
import json
import shutil
import platform
import subprocess


def _run(cmd, timeout=10):
    """Run a command, return (rc, stdout+stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.SubprocessError, OSError):
        return -1, ""


def _result(control, status, detail):
    """status: pass | fail | unknown"""
    return {"control": control, "status": status, "detail": detail}


# ── Firewall ──────────────────────────────────────────────────────────
def check_firewall(osname):
    if osname == "Linux":
        if shutil.which("ufw"):
            rc, out = _run(["ufw", "status"])
            if "status: active" in out.lower():
                return _result("firewall", "pass", "ufw active")
            if "status: inactive" in out.lower():
                return _result("firewall", "fail", "ufw inactive")
        rc, out = _run(["sh", "-c", "iptables -L -n 2>/dev/null | head -50"])
        if rc == 0 and out.strip():
            has_rules = any(x in out for x in ("DROP", "REJECT"))
            return _result("firewall", "pass" if has_rules else "unknown",
                           "iptables rules present" if has_rules
                           else "iptables reachable, no drop/reject rules seen")
        return _result("firewall", "unknown", "no ufw/iptables status available")
    if osname == "Windows":
        rc, out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        low = out.lower()
        if "state" in low:
            return _result("firewall", "pass" if "on" in low else "fail",
                           "Windows Firewall " + ("ON" if "on" in low else "OFF"))
        return _result("firewall", "unknown", "could not read firewall state")
    if osname == "Darwin":
        rc, out = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw",
                        "--getglobalstate"])
        if "enabled" in out.lower():
            return _result("firewall", "pass", "Application Firewall enabled")
        if "disabled" in out.lower():
            return _result("firewall", "fail", "Application Firewall disabled")
    return _result("firewall", "unknown", "unsupported platform check")


# ── Malware protection ────────────────────────────────────────────────
def check_malware(osname):
    if osname == "Windows":
        rc, out = _run(["powershell", "-NoProfile", "-Command",
                        "(Get-MpComputerStatus).RealTimeProtectionEnabled"])
        low = out.strip().lower()
        if "true" in low:
            return _result("malware", "pass", "Defender real-time protection on")
        if "false" in low:
            return _result("malware", "fail", "Defender real-time protection OFF")
        return _result("malware", "unknown", "could not query Defender")
    if osname == "Linux":
        for av in ("clamscan", "clamdscan", "freshclam"):
            if shutil.which(av):
                return _result("malware", "pass", f"{av} (ClamAV) installed")
        return _result("malware", "unknown",
                       "no common AV binary found (may use another product)")
    if osname == "Darwin":
        # macOS ships XProtect; presence is implied but not queryable simply.
        return _result("malware", "unknown",
                       "macOS built-in XProtect assumed; confirm manually")
    return _result("malware", "unknown", "unsupported platform check")


# ── Disk encryption ───────────────────────────────────────────────────
def check_disk_encryption(osname):
    if osname == "Linux":
        rc, out = _run(["sh", "-c", "lsblk -o TYPE,NAME 2>/dev/null"])
        if "crypt" in out.lower():
            return _result("disk_encryption", "pass", "LUKS/crypt volume present")
        return _result("disk_encryption", "unknown",
                       "no crypt device seen (may be unencrypted)")
    if osname == "Windows":
        rc, out = _run(["manage-bde", "-status", "C:"])
        low = out.lower()
        if "percentage encrypted" in low and "100" in low:
            return _result("disk_encryption", "pass", "BitLocker fully encrypted")
        if "protection off" in low or "fully decrypted" in low:
            return _result("disk_encryption", "fail", "BitLocker off")
        return _result("disk_encryption", "unknown", "could not read BitLocker")
    if osname == "Darwin":
        rc, out = _run(["fdesetup", "status"])
        if "filevault is on" in out.lower():
            return _result("disk_encryption", "pass", "FileVault on")
        if "filevault is off" in out.lower():
            return _result("disk_encryption", "fail", "FileVault off")
    return _result("disk_encryption", "unknown", "unsupported platform check")


# ── Automatic updates ─────────────────────────────────────────────────
def check_auto_updates(osname):
    if osname == "Linux":
        if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
            try:
                with open("/etc/apt/apt.conf.d/20auto-upgrades") as fh:
                    txt = fh.read()
                if '"1"' in txt:
                    return _result("auto_updates", "pass",
                                   "unattended-upgrades configured")
            except OSError:
                pass
        return _result("auto_updates", "unknown",
                       "automatic updates not confirmed")
    if osname == "Windows":
        rc, out = _run(["powershell", "-NoProfile", "-Command",
                        "(Get-Service wuauserv).Status"])
        if "running" in out.lower():
            return _result("auto_updates", "pass", "Windows Update service running")
        return _result("auto_updates", "unknown", "could not query Windows Update")
    if osname == "Darwin":
        rc, out = _run(["defaults", "read",
                        "/Library/Preferences/com.apple.SoftwareUpdate",
                        "AutomaticCheckEnabled"])
        if out.strip() == "1":
            return _result("auto_updates", "pass", "automatic update check on")
    return _result("auto_updates", "unknown", "unsupported platform check")


def run_all():
    osname = platform.system()
    checks = [
        check_firewall(osname),
        check_malware(osname),
        check_disk_encryption(osname),
        check_auto_updates(osname),
    ]
    passed = sum(1 for c in checks if c["status"] == "pass")
    failed = sum(1 for c in checks if c["status"] == "fail")
    return {
        "host": platform.node(),
        "os": f"{osname} {platform.release()}",
        "checks": checks,
        "summary": {"passed": passed, "failed": failed,
                    "unknown": len(checks) - passed - failed, "total": len(checks)},
    }


if __name__ == "__main__":
    json.dump(run_all(), sys.stdout, indent=2)
    sys.stdout.write("\n")
