#!/usr/bin/env python3
"""
PHANTOM ENGAGEMENT SCOPE
Manually-managed allowlist of authorized targets, plus the central
authorization gate every command passes through before it runs.

Design goals:
  * A target scan only runs against hosts the operator has explicitly approved.
  * Shell metacharacters in a target field can never reach a shell.
  * Local/auxiliary tools (payload gen, listeners, hash cracking, installs)
    are not blocked by an empty scope, but are still injection-checked.
"""

import os
import re
import json
import ipaddress

try:
    from phantom_validators import (
        classify_target, target_host, looks_like_file, looks_targetish,
    )
except ImportError:  # allow running as src.phantom_scope
    from src.phantom_validators import (
        classify_target, target_host, looks_like_file, looks_targetish,
    )

SCOPE_PATH = os.path.expanduser("~/.phantom/scope.json")

# Names whose commands are raw shell authored by the operator, or unattended
# installs. Injection checks are skipped for these (the operator owns them).
INTENTIONAL_SHELL = {"custom-shell", "vpn-connect", "vpn-disconnect", "manual"}

# Tools that do not scan a remote host (payload gen, listeners, local files,
# GUI launches). Exempt from scope enforcement, still injection-checked.
NO_SCOPE_TOOLS = {
    "msfvenom", "metasploit", "searchsploit", "nc", "netcat", "john",
    "hashcat", "tcpdump", "wireshark", "burpsuite", "zaproxy", "openvas",
    "nessus", "netdiscover", "custom-shell", "vpn-connect", "vpn-disconnect",
    # Local / post-exploitation tools from the style guide: they run on the
    # operator's box or on an already-compromised host, not against the scope.
    "mimikatz", "bloodhound", "linpeas", "winpeas", "responder",
    "cherrytree", "dradis", "legion", "recon-ng", "sherlock",
}

# Names permitted to use '&&' (built by Phantom itself, not user targets).
ALLOW_CHAIN = {"multi_scan", "nessus"}

# Shell metacharacters that must never appear in a non-shell command.
_INJECTION_RE = re.compile(r'[;`|<>]|\$\(|\$\{|\|\|')

# Per-tool options that enable *argument injection* — writing/reading files or
# executing code via a flag smuggled into a target value. These are matched by
# prefix (so '-oN/tmp/x' and '--file-write=...' are both caught). The list is
# deliberately limited to flags the GUI itself never generates, so legitimate
# built-in commands (e.g. nmap --script=default, sqlmap --dump) are unaffected.
# Operators who genuinely need these can use the manual console (raw shell).
DANGEROUS_FLAGS = {
    "nmap":     ("-oN", "-oX", "-oG", "-oS", "-oA", "-iL", "--datadir",
                 "--stylesheet", "--resume", "--append-output",
                 "--script-args", "--script-help"),
    "masscan":  ("-oL", "-oX", "-oG", "-oJ", "-oB", "-oD", "--output-filename"),
    "curl":     ("-o", "-O", "--output", "--remote-name", "-T", "--upload-file",
                 "-K", "--config", "-D", "--dump-header", "--trace"),
    "wget":     ("-O", "--output-document", "-i", "--input-file"),
    "sqlmap":   ("--os-cmd", "--os-shell", "--os-pwn", "--file-read",
                 "--file-write", "--file-dest", "--sql-shell", "--eval",
                 "-r", "--load-cookies", "--configfile"),
    "hydra":    ("-o", "-b"),
    "nikto":    ("-o", "-Save", "-output"),
    "gobuster": ("-o", "--output"),
    "dirb":     ("-o",),
    "wfuzz":    ("-o", "-f"),
    "wapiti":   ("-o", "--output", "-f"),
    "whatweb":  ("--log-verbose", "--log-brief", "--log-xml", "--log-json",
                 "--log-sql", "--log-errors", "--log-magictree"),
    "theharvester": ("-f",),
    "sslscan":  ("--xml",),
    "dnsenum":  ("-o", "--output"),
    "dnsrecon": ("-c", "-j", "-x", "-y", "-z", "--csv", "--xml", "--json"),
    "sublist3r": ("-o", "--output"),
    "wpscan":   ("-o", "--output", "--format", "--api-token"),
    "snmp-check": ("-w", "-d"),
    "onesixtyone": ("-o", "--outfile"),
    "enum4linux": ("-o", "-O", "-U", "-S", "-G", "-P"),
    "arp-scan": ("-o", "--outfile"),
    "masscan":  ("-oL", "-oX", "-oG", "-oJ", "-oB", "-oD", "--output-filename"),
}


def _dangerous_flag(tool, tok):
    """True if `tok` is a file/exec-enabling option not allowed for `tool`."""
    return any(tok.startswith(bad) for bad in DANGEROUS_FLAGS.get(tool, ()))


class ScopeManager:
    """Loads/saves the approved-target allowlist and answers scope queries."""

    def __init__(self, path=SCOPE_PATH):
        self.path = path
        self.targets = []
        self.enforced = True
        self.load()

    # ── persistence ───────────────────────────────
    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.targets = list(dict.fromkeys(data.get("targets", [])))
            self.enforced = bool(data.get("enforced", True))
        except (FileNotFoundError, ValueError, OSError):
            self.targets = []
            self.enforced = True

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(
                    {"enforced": self.enforced, "targets": self.targets},
                    fh, indent=2,
                )
            return True
        except OSError as exc:
            print(f"Cannot save scope: {exc}")
            return False

    # ── mutation ──────────────────────────────────
    def add(self, raw):
        """Validate and add a target. Returns (ok, message)."""
        entry = (raw or "").strip().lower()
        if not entry:
            return False, "Empty target."
        if classify_target(entry) == 'invalid':
            return False, f"Not a valid target: {raw!r} (use a domain, IP, CIDR, or URL)."
        entry = target_host(entry) if '://' in entry else entry
        if entry in self.targets:
            return False, f"Already in scope: {entry}"
        self.targets.append(entry)
        self.save()
        return True, f"Added to scope: {entry}"

    def remove(self, entry):
        if entry in self.targets:
            self.targets.remove(entry)
            self.save()
            return True
        return False

    def clear(self):
        self.targets = []
        self.save()

    def set_enforced(self, value):
        self.enforced = bool(value)
        self.save()

    def list(self):
        return list(self.targets)

    # ── query ─────────────────────────────────────
    def is_in_scope(self, tok):
        host = target_host(tok)
        low = tok.lower()
        for entry in self.targets:
            entry = entry.lower()
            if entry == low or entry == host:
                return True
            kind = classify_target(entry)
            if kind == 'domain' and host and (host == entry or host.endswith('.' + entry)):
                return True
            if kind == 'cidr':
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    ip = ipaddress.ip_address(host or tok)
                    if ip in net:
                        return True
                except ValueError:
                    pass
        return False


def authorize_command(cmd, name, scope):
    """
    Central gate. Returns (allowed: bool, reason: str).

    Blocks: shell-injection metacharacters, chained commands from untrusted
    contexts, malformed/unsafe targets, and any valid target not in scope.
    """
    raw = (cmd or "").strip()
    if not raw:
        return False, "Empty command."

    intentional = name in INTENTIONAL_SHELL or name.startswith("install:")
    no_scope = name in NO_SCOPE_TOOLS or name.startswith("install:")

    parts = [p.strip() for p in re.split(r'\s&&\s', raw) if p.strip()]
    if len(parts) > 1 and name not in ALLOW_CHAIN and not intentional:
        return False, "Chained commands (&&) are blocked here — possible command injection."

    for part in parts:
        p = part[:-1].strip() if part.endswith('&') else part  # drop background '&'

        if not intentional and ('&' in p or _INJECTION_RE.search(p)):
            return False, f"Blocked: shell metacharacters detected (possible injection): {part!r}"

        toks = p.split()
        tool = os.path.basename(toks[0]).lower() if toks else ""
        # Argument-injection guard applies to network scan tools only; local
        # tools (payload gen, hash cracking, listeners) legitimately use file
        # options and are exempt, and raw-shell contexts own their own args.
        arg_check = not intentional and not no_scope
        for tok in toks[1:]:
            if tok.startswith('-'):
                if arg_check and _dangerous_flag(tool, tok):
                    return False, (
                        f"Blocked: option '{tok}' is not permitted for {tool} here "
                        f"(possible argument injection). Use the manual console if intended."
                    )
                continue
            # KEY=VALUE argument (e.g. msfvenom LHOST=1.2.3.4): judge the value.
            cand = tok.split('=', 1)[1] if ('=' in tok and '://' not in tok) else tok
            if not cand or looks_like_file(cand) or os.path.exists(cand):
                continue
            kind = classify_target(cand)
            if kind != 'invalid':
                if not no_scope and getattr(scope, 'enforced', True):
                    if not scope.is_in_scope(cand):
                        return False, (
                            f"Target '{cand}' is not in the approved scope.\n"
                            f"Add it in the SCOPE tab (or disable enforcement there) to run this."
                        )
            elif not intentional and looks_targetish(cand):
                return False, f"Blocked: invalid or unsafe target '{cand}'."

    return True, ""
