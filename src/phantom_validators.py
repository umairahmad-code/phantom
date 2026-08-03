#!/usr/bin/env python3
"""
PHANTOM INPUT VALIDATORS
Strict, allowlist-based validation for network targets.

Purpose: a target typed into the GUI must only ever be a clean domain, IP,
CIDR, IP-range, or URL. Anything containing shell metacharacters is rejected
here, before it can ever be interpolated into a command. This is the first
line of defence against command injection in the tool itself.
"""

import re
import ipaddress
from urllib.parse import urlparse

# Characters that may legitimately appear in a benign target token.
# Shell metacharacters (; | & $ ( ) ` < > space quotes backslash) are absent
# on purpose: a token containing any of them is treated as invalid/unsafe.
SAFE_TOKEN_RE = re.compile(r'^[A-Za-z0-9._\-:/@%?=&\[\]~+]+$')

# RFC-1035-ish hostname (labels 1-63 chars, TLD alphabetic).
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)'
    r'(?!-)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
    r'[A-Za-z]{2,63}$'
)

# Argument values that are files, not network targets. Prevents scope/injection
# checks from mis-flagging wordlists, key files, resource scripts, etc.
FILE_EXTS = {
    '.txt', '.rc', '.html', '.htm', '.json', '.csv', '.log', '.db', '.sqlite',
    '.lst', '.dic', '.conf', '.cfg', '.py', '.sh', '.xml', '.gnmap', '.nmap',
    '.pcap', '.cap', '.pem', '.key', '.crt', '.pub', '.md', '.yaml', '.yml',
    '.ini', '.list', '.wordlist', '.hash', '.pot', '.bin', '.elf', '.exe',
}


def looks_like_file(tok):
    """True if the token is clearly a filename (by extension)."""
    low = tok.lower()
    return any(low.endswith(ext) for ext in FILE_EXTS)


def _host_of_url(tok):
    """Return the hostname component of a URL-ish token, or None."""
    try:
        parsed = urlparse(tok if '://' in tok else '//' + tok)
        return parsed.hostname
    except ValueError:
        return None


def classify_host(tok):
    """Classify a bare host: 'ipv4', 'ipv6', 'domain', or 'invalid'."""
    try:
        ip = ipaddress.ip_address(tok)
        return 'ipv6' if ip.version == 6 else 'ipv4'
    except ValueError:
        pass
    if DOMAIN_RE.match(tok):
        return 'domain'
    return 'invalid'


def classify_range(tok):
    """Classify an IP range 'a.b.c.d-e.f.g.h' or 'a.b.c.d-N'."""
    halves = tok.split('-')
    if len(halves) != 2:
        return 'invalid'
    start, end = halves
    try:
        start_ip = ipaddress.ip_address(start)
    except ValueError:
        return 'invalid'
    try:
        ipaddress.ip_address(end)
        return 'range'
    except ValueError:
        if start_ip.version == 4 and end.isdigit() and 0 <= int(end) <= 255:
            return 'range'
    return 'invalid'


def classify_target(tok):
    """
    Classify a target token into one of:
    'ipv4', 'ipv6', 'cidr', 'range', 'domain', 'url', or 'invalid'.

    Anything containing a shell metacharacter fails SAFE_TOKEN_RE and is
    immediately 'invalid'.
    """
    if not tok or not SAFE_TOKEN_RE.match(tok):
        return 'invalid'
    if '://' in tok:
        host = _host_of_url(tok)
        if host and classify_host(host) != 'invalid':
            return 'url'
        return 'invalid'
    if '/' in tok:
        try:
            ipaddress.ip_network(tok, strict=False)
            return 'cidr'
        except ValueError:
            return 'invalid'
    if '-' in tok and not tok.startswith('-'):
        return classify_range(tok)
    return classify_host(tok)


def is_valid_target(tok):
    """True if the token is a syntactically valid, safe network target."""
    return classify_target(tok) != 'invalid'


def target_host(tok):
    """
    The host used for scope matching. For a URL this is its hostname; for a
    bare host it is the token itself (lower-cased). CIDR/range are returned
    unchanged.
    """
    if '://' in tok:
        return (_host_of_url(tok) or '').lower()
    return tok.lower()


def looks_targetish(tok):
    """
    Heuristic: does this token look like it was *meant* to be a host/URL?
    Used to distinguish an injection attempt or malformed target (block it)
    from an unrelated argument like a flag or number (ignore it).
    """
    if tok.startswith('-'):
        return False
    if looks_like_file(tok):
        return False
    return ('://' in tok) or ('.' in tok) or (':' in tok)
