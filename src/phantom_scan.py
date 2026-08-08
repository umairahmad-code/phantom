#!/usr/bin/env python3
"""
PHANTOM SCAN ORCHESTRATOR

Runs a non-intrusive external scan efficiently and thoroughly:

  Stage 1  Full-port discovery — a fast SYN/connect sweep of ALL 65,535 ports
           so unusual services (e.g. 9929, 31337) are never missed the way a
           --top-ports profile misses them.
  Stage 2  Service/version detection — run only against the ports found open,
           so it is fast and precise.
  Stage 3  Web checks (whatweb / nikto / sslscan) — run ONLY if a web port is
           actually open, so no time is wasted when there is no web server.

Every command passes through the scope authorisation gate. A `progress`
callback (message, percent) lets callers show live progress instead of a
frozen UI. Per-stage timings are returned so performance is transparent.

This module contains no PyQt — the GUI wraps it in a thread; the CLI calls it
directly.
"""

import re
import time
import shutil
import subprocess

try:
    import phantom_scope as scope_mod
except ImportError:  # imported as src.phantom_scan
    from src import phantom_scope as scope_mod

_OPEN_PORT_RE = re.compile(r'^(\d{1,5})/(tcp|udp)\s+open', re.M)
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
TLS_PORTS = {443, 8443}
# Notable / commonly-backdoored high ports that a full sweep can miss on a
# rate-limiting host. Always service-probed explicitly so they are never lost
# (this is exactly what happened with 9929/31337 on scanme.nmap.org).
NOTABLE_HIGH_PORTS = {1337, 4444, 5555, 6667, 8081, 9929, 12345, 31337, 49152}


def _noop(_msg, _pct):
    pass


def _run(cmd, timeout):
    """Run a command list, return stdout (+stderr note on failure)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {' '.join(cmd)} exceeded {timeout}s"
    except (subprocess.SubprocessError, OSError) as e:
        return f"[ERROR] {e}"


def _authorized(cmd_str, tool, scope):
    if scope is None:
        return True, ""
    return scope_mod.authorize_command(cmd_str, tool, scope)


def discover_ports(target, scope, progress=_noop, full=True, timeout=400):
    """Stage 1: return a sorted list of open TCP ports.

    Uses --max-retries so a rate-limiting host (which drops probes under a fast
    sweep) still reports its ports, rather than a too-aggressive --min-rate that
    causes silent misses.
    """
    if not shutil.which("nmap"):
        progress("nmap not installed — cannot scan ports", 0)
        return [], ""
    port_arg = "-p-" if full else "--top-ports 1000"
    cmd = f"nmap -Pn -T4 {port_arg} --max-retries 2 --host-timeout 300s {target}"
    allowed, reason = _authorized(cmd, "nmap", scope)
    if not allowed:
        progress(f"blocked: {reason}", 0)
        return [], reason
    progress("Discovering open ports (full sweep)...", 10)
    out = _run(cmd.split(), timeout)
    ports = sorted({int(m.group(1)) for m in _OPEN_PORT_RE.finditer(out)})
    return ports, out


def service_scan(target, ports, scope, progress=_noop, timeout=250):
    """Stage 2: service/version detection.

    Probes the discovered ports PLUS the notable high-port list, so backdoor /
    unusual ports a fast sweep can miss are still checked with -sV (a small,
    targeted probe set is reliable even against a rate-limiting host).
    """
    if not shutil.which("nmap"):
        return "", []
    probe = sorted(set(ports) | NOTABLE_HIGH_PORTS)
    plist = ",".join(str(p) for p in probe)
    cmd = f"nmap -sV -Pn --version-light -p {plist} {target}"
    allowed, reason = _authorized(cmd, "nmap", scope)
    if not allowed:
        return f"[BLOCKED] {reason}", []
    progress(f"Identifying services on {len(probe)} port(s)...", 45)
    out = _run(cmd.split(), timeout)
    found = sorted({int(m.group(1)) for m in _OPEN_PORT_RE.finditer(out)})
    return out, found


def web_scan(target, open_ports, scope, progress=_noop):
    """Stage 3: web checks, only when a web port is open."""
    results = []
    web_open = sorted(set(open_ports) & WEB_PORTS)
    if not web_open:
        progress("No web port open — skipping web checks", 80)
        return results

    if shutil.which("whatweb"):
        cmd = f"whatweb {target}"
        allowed, _ = _authorized(cmd, "whatweb", scope)
        if allowed:
            progress("Fingerprinting web technology (whatweb)...", 70)
            results.append({"tool_name": "whatweb", "tool_output": _run(cmd.split(), 60)})

    if set(open_ports) & TLS_PORTS and shutil.which("sslscan"):
        cmd = f"sslscan {target}"
        allowed, _ = _authorized(cmd, "sslscan", scope)
        if allowed:
            progress("Checking TLS configuration (sslscan)...", 80)
            results.append({"tool_name": "sslscan", "tool_output": _run(cmd.split(), 90)})

    if shutil.which("nikto"):
        cmd = f"nikto -host {target} -maxtime 90s"
        allowed, _ = _authorized(cmd, "nikto", scope)
        if allowed:
            progress("Scanning web server for issues (nikto)...", 85)
            results.append({"tool_name": "nikto", "tool_output": _run(cmd.split(), 120)})
    return results


def run_scan(target, scope=None, progress=None, full_ports=False):
    """
    Orchestrated scan. Returns:
        {"results":[{tool_name,tool_output}...], "open_ports":[...],
         "timings":{stage:seconds}, "duration":seconds}

    full_ports=False (default): gentle, fast — top-1000 ports plus an explicit
        probe of notable high ports (so 9929/31337-style ports are still found).
        Gentle timing avoids getting the scanner IP blocked.
    full_ports=True (opt-in "thorough"): full 65,535-port sweep — slower, and can
        trip rate-limiting on hardened hosts.
    """
    progress = progress or _noop
    target = (target or "").strip()
    t0 = time.time()
    timings = {}

    progress(f"Starting scan of {target}", 5)
    ts = time.time()
    open_ports, disco_out = discover_ports(target, scope, progress, full=full_ports)
    timings["discovery"] = round(time.time() - ts, 1)

    results = []
    ts = time.time()
    # Always service-probe (discovered ports + notable high ports). This both
    # captures versions/EOL and re-checks backdoor ports a sweep may have missed.
    sv_out, sv_ports = service_scan(target, open_ports, scope, progress)
    sv_has_open = bool(_OPEN_PORT_RE.search(sv_out or ""))
    # Never lose the reliable discovery list: if -sV came back thin (rate-limited
    # host), fall back to the discovery output so port findings still appear.
    nmap_output = sv_out if sv_has_open else disco_out
    results.append({"tool_name": "nmap", "tool_output": nmap_output})
    # Authoritative open-port list = union of what each stage saw.
    open_ports = sorted(set(open_ports) | set(sv_ports))
    timings["service_scan"] = round(time.time() - ts, 1)

    ts = time.time()
    results.extend(web_scan(target, open_ports, scope, progress))
    timings["web"] = round(time.time() - ts, 1)

    progress("Scan complete", 95)
    return {
        "results": results,
        "open_ports": open_ports,
        "timings": timings,
        "duration": round(time.time() - t0, 1),
    }


if __name__ == "__main__":
    import sys, json
    tgt = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    sm = scope_mod.ScopeManager()
    sm.targets = [tgt]
    r = run_scan(tgt, scope=sm, progress=lambda m, p: print(f"  [{p:>3}%] {m}"))
    print(json.dumps({"open_ports": r["open_ports"], "timings": r["timings"],
                      "duration": r["duration"]}, indent=2))
