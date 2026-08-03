#!/usr/bin/env python3
"""
PHANTOM ATTACK-SURFACE DISCOVERY (ASM-lite)

From just a domain name, discover the organisation's internet-facing footprint:
subdomains, the IPs they resolve to, and which are live. This produces the
"you didn't even know this was online" moment that closes assessment sales, and
it feeds discovered hosts straight into the engagement scope.

Discovery sources (passive — no traffic to the target):
  * Certificate Transparency logs via crt.sh (every TLS cert a domain issues is
    logged publicly), fetched over HTTPS.
  * DNS resolution of each candidate via the system resolver.

All network calls degrade gracefully: no internet / crt.sh down / requests not
installed → returns whatever was found (possibly just the base domain) with a
clear note, never an exception.
"""

import re
import json
import socket
import urllib.request
import urllib.error


def _fetch_crtsh(domain, timeout=20):
    """Return a set of candidate subdomain names from crt.sh (or empty)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    names = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PHANTOM-ASM"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        for row in data:
            for field in ("name_value", "common_name"):
                val = row.get(field, "")
                for line in str(val).splitlines():
                    line = line.strip().lower().lstrip("*.")
                    if line.endswith(domain) and re.match(r'^[a-z0-9._-]+$', line):
                        names.add(line)
    except (urllib.error.URLError, ValueError, OSError, TimeoutError):
        return set()
    return names


def _resolve(name):
    """Return the first IP for a hostname, or None."""
    try:
        return socket.gethostbyname(name)
    except (socket.gaierror, OSError):
        return None


def discover(domain, resolve=True, max_hosts=200):
    """
    Discover the attack surface for a domain.

    Returns:
        {
          "domain": ...,
          "assets": [ {"host":..., "ip":..., "live":bool}, ... ],
          "summary": {"subdomains":N, "live":N, "unique_ips":N},
          "source": "crt.sh" | "dns-only",
          "note": <string if degraded, else "">,
        }
    """
    domain = (domain or "").strip().lower()
    domain = re.sub(r'^\w+://', '', domain).split('/')[0].split(':')[0]

    note = ""
    candidates = _fetch_crtsh(domain)
    source = "crt.sh"
    if not candidates:
        source = "dns-only"
        note = ("Certificate-transparency lookup unavailable (offline or crt.sh "
                "unreachable) — showing the base domain only.")
        candidates = set()

    # Always include the apex and www.
    candidates.add(domain)
    candidates.add(f"www.{domain}")
    candidates = sorted(candidates)[:max_hosts]

    assets = []
    ips = set()
    for host in candidates:
        ip = _resolve(host) if resolve else None
        live = ip is not None
        if ip:
            ips.add(ip)
        assets.append({"host": host, "ip": ip or "", "live": live})

    # Live hosts first, then alphabetical.
    assets.sort(key=lambda a: (not a["live"], a["host"]))

    return {
        "domain": domain,
        "assets": assets,
        "summary": {
            "subdomains": len(assets),
            "live": sum(1 for a in assets if a["live"]),
            "unique_ips": len(ips),
        },
        "source": source,
        "note": note,
    }


def live_hosts(discovery_result):
    """Return just the resolvable hostnames — ready to add to engagement scope."""
    return [a["host"] for a in discovery_result.get("assets", []) if a["live"]]


if __name__ == "__main__":
    import sys
    dom = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(discover(dom), indent=2))
