#!/usr/bin/env python3
"""
PHANTOM KNOWLEDGE BASE
Turns raw findings (open ports, services, vulnerability classes) into a
two-layer explanation:

  * technical  — precise wording for the tester / report body
  * plain      — the same thing in everyday language for the client
  * risk       — why it matters / what an attacker could do
  * remediation— how to fix it
  * severity   — critical | high | medium | low | info

Every entry answers the user's need: "port X is open and could be used
for Y" and "these passwords are weak and easy to crack", in both registers.
"""

import re

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def severity_rank(sev):
    return SEVERITY_ORDER.get(str(sev).lower(), 0)


# ── Port / service knowledge ──────────────────────────────────────────
# severity here is the *baseline* exposure of finding the port open.
PORTS = {
    21: {
        "service": "FTP", "severity": "high",
        "technical": "FTP (File Transfer Protocol) is exposed. FTP transmits "
                     "credentials and data in cleartext and often allows "
                     "anonymous login or brute-force of accounts.",
        "plain": "A file-sharing service is open to the internet. It sends "
                 "usernames and passwords without scrambling them, so anyone "
                 "watching the network can read them.",
        "risk": "Attackers can capture credentials off the wire, log in "
                "anonymously, or brute-force weak accounts to read/replace files.",
        "remediation": "Replace FTP with SFTP/FTPS, disable anonymous login, "
                        "and restrict access by IP/VPN.",
    },
    22: {
        "service": "SSH", "severity": "medium",
        "technical": "SSH remote administration is exposed. While encrypted, "
                     "it is a prime target for credential brute-force and is "
                     "dangerous if it allows password auth or runs an old version.",
        "plain": "A remote 'control panel' for the server is reachable. It is "
                 "encrypted, but if the password is weak, attackers can keep "
                 "guessing until they get in and take over the machine.",
        "risk": "Weak or reused passwords allow full remote takeover of the host.",
        "remediation": "Require SSH keys (disable password login), enforce "
                        "fail2ban/rate-limiting, and restrict source IPs.",
    },
    23: {
        "service": "Telnet", "severity": "critical",
        "technical": "Telnet is exposed. It provides remote shell access with "
                     "no encryption whatsoever; credentials and sessions are "
                     "fully cleartext.",
        "plain": "An old remote-access service is open that sends everything — "
                 "including the password — as plain readable text. This is "
                 "considered unsafe and should never be on a modern network.",
        "risk": "Anyone on the network path can read the password and hijack "
                "the session to control the device.",
        "remediation": "Disable Telnet entirely and use SSH instead.",
    },
    25: {
        "service": "SMTP", "severity": "low",
        "technical": "SMTP mail service is exposed. May allow open relay, user "
                     "enumeration (VRFY/EXPN), or reveal server software/version.",
        "plain": "An email-sending service is reachable. If misconfigured, "
                 "spammers could abuse it to send mail as your domain.",
        "risk": "Open relay enables spam/phishing from your infrastructure; "
                "enumeration leaks valid email accounts.",
        "remediation": "Disable open relay, restrict to authenticated senders, "
                        "and turn off VRFY/EXPN.",
    },
    53: {
        "service": "DNS", "severity": "low",
        "technical": "DNS service is exposed. May permit zone transfers (AXFR) "
                     "that leak the full internal host map, or be abused for "
                     "amplification.",
        "plain": "The service that translates names to addresses is open. If "
                 "misconfigured it can hand over a full list of the "
                 "organisation's internal computers.",
        "risk": "Zone transfer discloses internal hostnames/IPs; open resolvers "
                "aid DDoS amplification.",
        "remediation": "Restrict zone transfers to trusted secondaries and "
                        "disable open recursion.",
    },
    80: {
        "service": "HTTP", "severity": "medium",
        "technical": "An unencrypted HTTP web service is exposed. Traffic is "
                     "cleartext and the application is a candidate for web "
                     "vulnerabilities (injection, XSS, misconfig).",
        "plain": "A website is running without encryption (no padlock). Data "
                 "between visitors and the site can be read or tampered with, "
                 "and the site itself should be tested for web weaknesses.",
        "risk": "Traffic interception, session theft, and any web-app flaws in "
                "the hosted application.",
        "remediation": "Redirect all traffic to HTTPS, add HSTS, and test the "
                        "web application for injection/XSS.",
    },
    110: {
        "service": "POP3", "severity": "medium",
        "technical": "POP3 mail retrieval exposed; cleartext variant transmits "
                     "credentials without encryption.",
        "plain": "An email-collection service is open that can send the mailbox "
                 "password in readable form.",
        "risk": "Mailbox credential capture over the network.",
        "remediation": "Enforce POP3S (TLS) or disable in favour of IMAPS.",
    },
    139: {
        "service": "NetBIOS/SMB", "severity": "high",
        "technical": "Legacy NetBIOS/SMB is exposed. Associated with information "
                     "disclosure and historic remote-exploit chains.",
        "plain": "An old Windows file-sharing service is reachable. It has a "
                 "long history of serious security holes.",
        "risk": "Share enumeration, credential relay, and known SMB exploits.",
        "remediation": "Block SMB at the perimeter and disable SMBv1.",
    },
    143: {
        "service": "IMAP", "severity": "medium",
        "technical": "IMAP mail service exposed; cleartext variant leaks "
                     "credentials.",
        "plain": "An email service is open that may send the password unencrypted.",
        "risk": "Mailbox credential capture.",
        "remediation": "Enforce IMAPS (TLS) only.",
    },
    161: {
        "service": "SNMP", "severity": "high",
        "technical": "SNMP is exposed. Default community strings ('public'/"
                     "'private') expose device configuration and can allow writes.",
        "plain": "A device-management service is open. It often ships with a "
                 "default 'password' that everyone knows, revealing how the "
                 "device is set up.",
        "risk": "Configuration disclosure and, with write access, device takeover.",
        "remediation": "Disable SNMP or move to SNMPv3 with strong credentials; "
                        "never use default community strings.",
    },
    445: {
        "service": "SMB", "severity": "high",
        "technical": "SMB file sharing is exposed. Target of major exploit "
                     "chains (e.g. EternalBlue) and credential-relay attacks.",
        "plain": "Windows file sharing is open to the network. This is one of "
                 "the most commonly attacked services and has caused worldwide "
                 "ransomware outbreaks.",
        "risk": "Remote code execution via known exploits, share access, and "
                "credential relay leading to domain compromise.",
        "remediation": "Never expose SMB to untrusted networks; patch, disable "
                        "SMBv1, and enforce signing.",
    },
    443: {
        "service": "HTTPS", "severity": "info",
        "technical": "HTTPS web service exposed. Encrypted, but still a target "
                     "for web-application vulnerabilities and TLS misconfiguration.",
        "plain": "A secure (padlock) website is running. Encryption is good, but "
                 "the website application itself still needs to be tested.",
        "risk": "Web-application flaws and weak TLS settings if present.",
        "remediation": "Keep TLS configuration strong and test the web app.",
    },
    1433: {
        "service": "MSSQL", "severity": "high",
        "technical": "Microsoft SQL Server is exposed. Direct database exposure "
                     "invites brute-force of 'sa' and known RCE via xp_cmdshell.",
        "plain": "A database server is reachable directly from the network. "
                 "Databases should sit behind the application, never be open.",
        "risk": "Database credential brute-force and command execution on the "
                "database host.",
        "remediation": "Firewall the database to app servers only; enforce "
                        "strong 'sa' credentials; disable xp_cmdshell.",
    },
    3306: {
        "service": "MySQL", "severity": "high",
        "technical": "MySQL/MariaDB is exposed. Direct exposure enables "
                     "credential brute-force and data theft if auth is weak.",
        "plain": "A database is open directly to the network. Databases hold "
                 "the crown jewels and should not be reachable from outside.",
        "risk": "Brute-force login and bulk data exfiltration.",
        "remediation": "Bind to localhost/app subnet only and enforce strong "
                        "credentials.",
    },
    3389: {
        "service": "RDP", "severity": "high",
        "technical": "Remote Desktop (RDP) is exposed. Heavily targeted for "
                     "brute-force and known pre-auth RCE (e.g. BlueKeep).",
        "plain": "The Windows 'remote screen' service is open to the internet. "
                 "Attackers constantly scan for this and try to guess passwords "
                 "or use known break-in bugs.",
        "risk": "Account brute-force and remote takeover; common ransomware "
                "entry point.",
        "remediation": "Put RDP behind a VPN, enforce MFA and lockout, and patch.",
    },
    5432: {
        "service": "PostgreSQL", "severity": "high",
        "technical": "PostgreSQL is exposed directly to the network.",
        "plain": "A database is reachable from outside — it should be hidden "
                 "behind the application only.",
        "risk": "Credential brute-force and data theft.",
        "remediation": "Restrict to app servers; enforce strong auth.",
    },
    5900: {
        "service": "VNC", "severity": "high",
        "technical": "VNC remote desktop exposed. Often weakly authenticated or "
                     "unauthenticated; password protocol is brute-forceable.",
        "plain": "A 'remote screen' service is open that frequently has weak or "
                 "no password, letting attackers watch and control the desktop.",
        "risk": "Unauthorized remote control of the machine.",
        "remediation": "Tunnel VNC over SSH/VPN and require strong passwords.",
    },
    6379: {
        "service": "Redis", "severity": "critical",
        "technical": "Redis is exposed. By default it has no authentication and "
                     "allows write access that can lead to remote code execution.",
        "plain": "A high-speed data store is open with, by default, no password "
                 "at all — anyone who finds it can read/change data or take over "
                 "the server.",
        "risk": "Unauthenticated data access and server takeover.",
        "remediation": "Bind to localhost, require a password, and never expose "
                        "Redis publicly.",
    },
    9200: {
        "service": "Elasticsearch", "severity": "critical",
        "technical": "Elasticsearch is exposed. Frequently unauthenticated, "
                     "exposing entire indexes of data over HTTP.",
        "plain": "A search/data service is open, often with no password, "
                 "exposing potentially huge amounts of stored data.",
        "risk": "Mass data disclosure.",
        "remediation": "Enable authentication and firewall off public access.",
    },
    27017: {
        "service": "MongoDB", "severity": "critical",
        "technical": "MongoDB is exposed. Historically ships unauthenticated, "
                     "exposing full databases.",
        "plain": "A database is open, and this type has famously been left "
                 "without a password, leaking millions of records.",
        "risk": "Full database read/write by anyone.",
        "remediation": "Enable authentication and bind to private networks only.",
    },
    111: {
        "service": "RPCbind", "severity": "medium",
        "technical": "RPCbind/portmapper is exposed, enumerating RPC services "
                     "(often NFS) and aiding amplification attacks.",
        "plain": "A 'directory' service is open that tells attackers what other "
                 "services are available to target.",
        "risk": "Service enumeration and DDoS amplification.",
        "remediation": "Firewall RPCbind from untrusted networks.",
    },
    135: {
        "service": "MSRPC", "severity": "medium",
        "technical": "Microsoft RPC endpoint mapper exposed; aids Windows "
                     "enumeration and lateral movement.",
        "plain": "A Windows management service is open that helps attackers map "
                 "out the network.",
        "risk": "Enumeration and lateral-movement footholds.",
        "remediation": "Block MSRPC at the perimeter.",
    },
    389: {
        "service": "LDAP", "severity": "medium",
        "technical": "LDAP directory service exposed; may allow anonymous binds "
                     "that leak user and group data.",
        "plain": "The company 'address book' service is open and may let anyone "
                 "read the list of users and groups.",
        "risk": "Disclosure of usernames/structure for targeted attacks.",
        "remediation": "Disable anonymous bind and require LDAPS.",
    },
    512: {
        "service": "rexec", "severity": "high",
        "technical": "Berkeley r-service (rexec) exposed; cleartext remote "
                     "execution with trivially bypassed trust.",
        "plain": "A very old remote-command service is open that is unsafe by "
                 "design and sends data in the clear.",
        "risk": "Cleartext credential capture and remote execution.",
        "remediation": "Disable all r-services; use SSH.",
    },
    2049: {
        "service": "NFS", "severity": "high",
        "technical": "NFS export exposed; world-readable/writable exports leak "
                     "or allow tampering of files.",
        "plain": "A network file share is open that may let outsiders read or "
                 "change files directly.",
        "risk": "File disclosure/modification and privilege escalation.",
        "remediation": "Restrict exports by host and use Kerberos (sec=krb5).",
    },
    2375: {
        "service": "Docker API", "severity": "critical",
        "technical": "Unencrypted Docker daemon API exposed. Grants full "
                     "container/host control to anyone who can reach it.",
        "plain": "The container engine's control port is open with no password — "
                 "whoever finds it effectively owns the server.",
        "risk": "Trivial full host takeover.",
        "remediation": "Never expose the Docker socket/API; require TLS + auth.",
    },
    5985: {
        "service": "WinRM", "severity": "high",
        "technical": "Windows Remote Management exposed; a primary vector for "
                     "credential-based remote command execution.",
        "plain": "A Windows remote-control service is open; with a valid "
                 "password an attacker can run commands on the machine.",
        "risk": "Remote command execution with valid credentials.",
        "remediation": "Restrict WinRM to management networks and use HTTPS.",
    },
    8080: {
        "service": "HTTP-alt", "severity": "medium",
        "technical": "Alternate HTTP port exposed, frequently an admin console, "
                     "proxy, or app server without TLS.",
        "plain": "A secondary website/admin panel is running without encryption.",
        "risk": "Exposed admin interfaces and web-app flaws.",
        "remediation": "Restrict/authenticate admin consoles and enforce TLS.",
    },
    8443: {
        "service": "HTTPS-alt", "severity": "low",
        "technical": "Alternate HTTPS port exposed, often an admin/management UI.",
        "plain": "A secondary secure admin panel is reachable; make sure it is "
                 "not accessible to the public.",
        "risk": "Exposed management interfaces.",
        "remediation": "Restrict management UIs to trusted networks.",
    },
    11211: {
        "service": "Memcached", "severity": "critical",
        "technical": "Memcached exposed; unauthenticated by default and a potent "
                     "UDP amplification vector.",
        "plain": "A caching service is open with no password, exposing cached "
                 "data and enabling large denial-of-service attacks.",
        "risk": "Data exposure and DDoS amplification.",
        "remediation": "Bind to localhost, disable UDP, and firewall it off.",
    },
}


def _generic_port(port, service):
    svc = service or "unknown service"
    return {
        "title": f"Open port {port}/{svc}",
        "service": svc,
        "severity": "info",
        "technical": f"Port {port} is open running '{svc}'. Each exposed "
                     f"service increases attack surface and should be validated "
                     f"for authentication, patch level, and necessity.",
        "plain": f"A service ({svc}) is reachable on port {port}. Every open "
                 f"door is one more thing an attacker can try; it should be "
                 f"closed if it isn't needed.",
        "risk": "Unnecessary or unpatched services can be probed and exploited.",
        "remediation": f"Confirm port {port} is required; if not, close it. "
                       f"Otherwise patch and restrict access.",
    }


def explain_port(port, service=None, version=None):
    """Return a two-layer explanation for an open port."""
    entry = PORTS.get(int(port)) if str(port).isdigit() else None
    if entry:
        result = dict(entry)
        svc = result.pop("service")
        result["service"] = service or svc
        result["title"] = f"Open port {port}/{svc}"
    else:
        result = _generic_port(port, service)
    if version:
        result["technical"] += f" Detected version banner: {version}."
        result["evidence"] = f"{port}/{service or ''} {version}".strip()
    else:
        result["evidence"] = f"{port}/{service or ''}".strip()
    result["port"] = port
    return result


# ── Vulnerability-class knowledge ─────────────────────────────────────
VULNS = {
    "sql_injection": {
        "title": "SQL Injection", "severity": "critical",
        "technical": "User input reaches a database query without proper "
                     "parameterisation, allowing an attacker to alter the query "
                     "logic, read, or modify data.",
        "plain": "The website lets attackers 'talk directly' to its database by "
                 "typing special text into a form or link. They could read, "
                 "change, or delete customer data.",
        "risk": "Full database disclosure, authentication bypass, and sometimes "
                "takeover of the server.",
        "remediation": "Use parameterised queries/prepared statements, validate "
                        "input, and apply least-privilege database accounts.",
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)", "severity": "high",
        "technical": "The application reflects/stores untrusted input into pages "
                     "without encoding, letting attacker-supplied script run in "
                     "victims' browsers.",
        "plain": "An attacker can plant hidden code in the website that runs "
                 "inside other visitors' browsers — enough to steal their "
                 "logins or trick them.",
        "risk": "Session/cookie theft, account takeover, and defacement.",
        "remediation": "Output-encode all user data, add a Content-Security-"
                        "Policy, and validate input.",
    },
    "weak_credentials": {
        "title": "Weak / Guessable Credentials", "severity": "high",
        "technical": "An account was accessible using weak, default, or "
                     "easily-guessed credentials via brute-force/dictionary "
                     "attack.",
        "plain": "A login was cracked because the password was too simple or a "
                 "default. In plain terms: the passwords are weak and easy to "
                 "guess, so an attacker can just walk in.",
        "risk": "Direct unauthorised access to the account and everything it "
                "can reach.",
        "remediation": "Enforce a strong password policy, change all defaults, "
                        "add account lockout, and enable multi-factor auth.",
    },
    "cleartext_protocol": {
        "title": "Cleartext / Unencrypted Protocol", "severity": "high",
        "technical": "A service transmits credentials/data without encryption, "
                     "exposing them to network interception.",
        "plain": "Information (including passwords) is sent as plain readable "
                 "text, so anyone able to watch the network can capture it.",
        "risk": "Credential and data theft via passive network sniffing.",
        "remediation": "Switch to the encrypted equivalent (SSH, HTTPS, FTPS, "
                        "IMAPS, etc.) and disable the cleartext service.",
    },
    "outdated_service": {
        "title": "Outdated / Vulnerable Software Version", "severity": "high",
        "technical": "A detected service/version maps to publicly known "
                     "vulnerabilities (CVEs) with available exploits.",
        "plain": "The software running here is an old version with publicly "
                 "known security holes — like leaving a known-broken lock on "
                 "the door.",
        "risk": "Exploitation via off-the-shelf public exploits.",
        "remediation": "Patch or upgrade to a supported, fixed version.",
    },
    "missing_security_headers": {
        "title": "Missing Security Headers", "severity": "low",
        "technical": "Responses lack hardening headers (HSTS, X-Frame-Options, "
                     "CSP, X-Content-Type-Options), weakening browser defences.",
        "plain": "The website is missing some standard safety settings that help "
                 "browsers protect visitors.",
        "risk": "Facilitates clickjacking, MIME sniffing, and downgrade attacks.",
        "remediation": "Add HSTS, CSP, X-Frame-Options, and "
                        "X-Content-Type-Options headers.",
    },
    "directory_listing": {
        "title": "Directory Listing Enabled", "severity": "medium",
        "technical": "The web server returns directory indexes, exposing file "
                     "and folder names not meant to be public.",
        "plain": "The website shows a public list of its files and folders, "
                 "which can reveal things that were meant to stay hidden.",
        "risk": "Disclosure of sensitive files, backups, or source code.",
        "remediation": "Disable auto-indexing (Options -Indexes) on the web "
                        "server.",
    },
    "info_disclosure": {
        "title": "Information Disclosure", "severity": "low",
        "technical": "The service leaks version/software/configuration details "
                     "useful for targeting further attacks.",
        "plain": "The system reveals details about itself (like what software "
                 "it runs) that help an attacker plan their next move.",
        "risk": "Aids attackers in selecting precise exploits.",
        "remediation": "Suppress version banners and verbose error messages.",
    },
    "ssl_weak_protocol": {
        "title": "Obsolete SSL/TLS Protocol Enabled", "severity": "high",
        "technical": "The server accepts deprecated protocols (SSLv2/SSLv3/"
                     "TLS 1.0/1.1) that are cryptographically broken (POODLE, "
                     "BEAST).",
        "plain": "The site still supports old, broken versions of its 'lock'. "
                 "Attackers can use known tricks to weaken or read the "
                 "encrypted traffic.",
        "risk": "Traffic decryption / downgrade attacks.",
        "remediation": "Disable SSLv2/SSLv3/TLS 1.0/1.1; allow only TLS 1.2+.",
    },
    "ssl_weak_cipher": {
        "title": "Weak TLS Cipher Suites", "severity": "medium",
        "technical": "The server negotiates weak ciphers (RC4, DES/3DES, "
                     "EXPORT, NULL, anonymous) offering little real protection.",
        "plain": "The encryption uses weak 'combinations' that are much easier "
                 "to break than modern ones.",
        "risk": "Practical decryption of intercepted traffic.",
        "remediation": "Restrict to strong AEAD ciphers (AES-GCM, ChaCha20).",
    },
    "ssl_cert_issue": {
        "title": "Certificate Problem (Expired / Self-Signed)", "severity": "medium",
        "technical": "The TLS certificate is expired, self-signed, or otherwise "
                     "untrusted, undermining authenticity guarantees.",
        "plain": "The site's security certificate is out of date or not properly "
                 "issued, so visitors can't be sure they're on the real site.",
        "risk": "Enables convincing man-in-the-middle / phishing.",
        "remediation": "Install a valid certificate from a trusted CA and "
                        "automate renewal.",
    },
    "ssl_heartbleed": {
        "title": "Heartbleed (CVE-2014-0160)", "severity": "critical",
        "technical": "A vulnerable OpenSSL version allows reading server memory "
                     "via the TLS heartbeat extension, leaking keys and secrets.",
        "plain": "A famous flaw lets attackers quietly read the server's private "
                 "memory — including passwords and encryption keys.",
        "risk": "Disclosure of private keys, credentials, and session data.",
        "remediation": "Upgrade OpenSSL immediately and rotate all keys/certs.",
    },
}


def explain_vuln(kind, evidence=None):
    """Return a two-layer explanation for a vulnerability class."""
    entry = VULNS.get(kind)
    if not entry:
        entry = {
            "title": kind.replace("_", " ").title(), "severity": "medium",
            "technical": "A potential weakness was observed and should be "
                         "manually verified.",
            "plain": "Something that may be a security weakness was spotted and "
                     "needs a closer look.",
            "risk": "Depends on confirmation.",
            "remediation": "Manually validate and remediate as appropriate.",
        }
    result = dict(entry)
    result["kind"] = kind
    if evidence:
        result["evidence"] = evidence
    return result


# ── Version-banner → known-CVE map (curated offline set) ──────────────
# Deliberately conservative: famous, banner-detectable versions only. This is
# a starting set, not a substitute for a full CVE feed. Each entry explains
# the flaw in both registers.
CVE_SIGNATURES = [
    {"re": re.compile(r'vsftpd\s*2\.3\.4', re.I), "cve": "CVE-2011-2523",
     "title": "vsftpd 2.3.4 Backdoor", "severity": "critical",
     "technical": "vsftpd 2.3.4 shipped with a malicious backdoor that opens a "
                  "root shell when a ':)' smiley is sent as the username.",
     "plain": "This exact file-server version contains a hidden backdoor that "
              "hands attackers complete control of the machine.",
     "remediation": "Upgrade vsftpd immediately and treat the host as compromised."},
    {"re": re.compile(r'ProFTPD\s*1\.3\.5(?!\.)', re.I), "cve": "CVE-2015-3306",
     "title": "ProFTPD 1.3.5 mod_copy RCE", "severity": "critical",
     "technical": "ProFTPD 1.3.5 mod_copy allows unauthenticated file copy "
                  "leading to remote code execution.",
     "plain": "This file-server version lets attackers copy files and run their "
              "own code without logging in.",
     "remediation": "Upgrade ProFTPD or disable mod_copy."},
    {"re": re.compile(r'Apache(?:\s+httpd)?/?\s*2\.4\.49', re.I), "cve": "CVE-2021-41773",
     "title": "Apache 2.4.49 Path Traversal / RCE", "severity": "critical",
     "technical": "Apache 2.4.49 is vulnerable to path traversal that can expose "
                  "files outside the web root and enable RCE when CGI is enabled.",
     "plain": "This web-server version lets attackers read files they shouldn't "
              "and can even run commands on the server.",
     "remediation": "Upgrade Apache to 2.4.51 or later."},
    {"re": re.compile(r'Apache(?:\s+httpd)?/?\s*2\.4\.50', re.I), "cve": "CVE-2021-42013",
     "title": "Apache 2.4.50 Path Traversal / RCE", "severity": "critical",
     "technical": "Apache 2.4.50 incompletely fixed CVE-2021-41773 and remains "
                  "exploitable for traversal/RCE.",
     "plain": "This web-server version still has the file-access/command-run flaw.",
     "remediation": "Upgrade Apache to 2.4.51 or later."},
    {"re": re.compile(r'Microsoft-IIS/?\s*6\.0', re.I), "cve": "CVE-2017-7269",
     "title": "Microsoft IIS 6.0 WebDAV RCE", "severity": "critical",
     "technical": "IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow allows "
                  "remote code execution.",
     "plain": "This old Windows web-server version can be taken over remotely.",
     "remediation": "Retire IIS 6.0 / Windows Server 2003; migrate to supported OS."},
    {"re": re.compile(r'UnrealIRCd\s*3\.2\.8\.1', re.I), "cve": "CVE-2010-2075",
     "title": "UnrealIRCd 3.2.8.1 Backdoor", "severity": "critical",
     "technical": "This UnrealIRCd build contains a backdoor enabling arbitrary "
                  "command execution.",
     "plain": "This chat-server version has a hidden backdoor for running commands.",
     "remediation": "Reinstall from a verified source and rotate credentials."},
    {"re": re.compile(r'Exim\s*4\.(8[7-9]|9[01])\b', re.I), "cve": "CVE-2019-10149",
     "title": "Exim RCE (The Return of the WIZard)", "severity": "critical",
     "technical": "Exim 4.87–4.91 allows remote command execution via crafted "
                  "recipient addresses.",
     "plain": "This mail-server version can be tricked into running attacker "
              "commands.",
     "remediation": "Upgrade Exim to 4.92 or later."},
    {"re": re.compile(r'nginx/?\s*1\.(4\.0|3\.9)\b', re.I), "cve": "CVE-2013-2028",
     "title": "nginx Chunked Transfer Stack Overflow", "severity": "high",
     "technical": "nginx 1.3.9–1.4.0 has a stack buffer overflow in chunked "
                  "transfer handling.",
     "plain": "This web-server version can crash or be exploited via malformed "
              "requests.",
     "remediation": "Upgrade nginx to 1.4.1 or later."},
    {"re": re.compile(r'OpenSSL/?\s*1\.0\.1[ \-]?[a-f]?\b', re.I), "cve": "CVE-2014-0160",
     "title": "OpenSSL Heartbleed", "severity": "critical",
     "technical": "OpenSSL 1.0.1–1.0.1f are vulnerable to Heartbleed, leaking "
                  "server memory including private keys.",
     "plain": "This encryption library version lets attackers read the server's "
              "private memory, including keys and passwords.",
     "remediation": "Upgrade OpenSSL and rotate all keys and certificates."},
    {"re": re.compile(r'Samba\s*3\.[0-6]\b', re.I), "cve": "CVE-2017-7494",
     "title": "Samba SambaCry RCE", "severity": "critical",
     "technical": "Samba 3.5.0 onward (through 4.6.4) allows a malicious client "
                  "to upload and execute a shared library (SambaCry).",
     "plain": "This file-sharing version can be made to run attacker-supplied "
              "code.",
     "remediation": "Upgrade Samba or set 'nt pipe support = no'."},
]


def match_cve(banner):
    """Return CVE findings for a version banner (may be empty)."""
    out = []
    if not banner:
        return out
    for sig in CVE_SIGNATURES:
        if sig["re"].search(banner):
            out.append({
                "kind": "cve",
                "cve": sig["cve"],
                "title": f"{sig['title']} ({sig['cve']})",
                "severity": sig["severity"],
                "technical": sig["technical"],
                "plain": sig["plain"],
                "risk": "A public exploit is typically available for this "
                        "version, so exploitation is low-effort.",
                "remediation": sig["remediation"],
                "evidence": banner.strip(),
            })
    return out


# ── End-of-life / outdated-version detection ──────────────────────────
# Catches software that is old / unsupported even when there is no single
# famous CVE for that exact build — the case a real assessor flags but a
# narrow CVE list misses (e.g. OpenSSH 6.6.1p1 on the scanme.nmap.org test).
# Each pattern matches a version RANGE known to be end-of-life or superseded.
EOL_SIGNATURES = [
    {"re": re.compile(r'OpenSSH[_ /]?([0-6]\.\d+|7\.[0-3])(?:\.\d+)?(?:p\d)?', re.I),
     "product": "OpenSSH (pre-7.4)", "severity": "high",
     "remediation": "Upgrade OpenSSH to a current supported release (8.x/9.x)."},
    {"re": re.compile(r'Apache(?:/| httpd/?| )?2\.2\.\d+', re.I),
     "product": "Apache httpd 2.2.x", "severity": "high",
     "remediation": "Upgrade to a supported Apache 2.4.x release."},
    {"re": re.compile(r'\bPHP/(?:[45]\.\d+|7\.[0-3])', re.I),
     "product": "PHP (5.x/7.0–7.3)", "severity": "high",
     "remediation": "Upgrade to a supported PHP 8.x release."},
    {"re": re.compile(r'Microsoft-IIS/(?:[567])\.0', re.I),
     "product": "Microsoft IIS (6.0/7.0)", "severity": "high",
     "remediation": "Migrate to a supported Windows Server / IIS version."},
    {"re": re.compile(r'nginx/1\.(?:[0-9]|1[0-3])\.\d+', re.I),
     "product": "nginx (pre-1.14)", "severity": "medium",
     "remediation": "Upgrade nginx to a current stable release."},
    {"re": re.compile(r'\bMySQL\s+5\.[0-6]\.\d+', re.I),
     "product": "MySQL (5.0–5.6)", "severity": "medium",
     "remediation": "Upgrade to MySQL 8.x or a supported MariaDB."},
    {"re": re.compile(r'OpenSSL/1\.0\.\d', re.I),
     "product": "OpenSSL 1.0.x", "severity": "high",
     "remediation": "Upgrade OpenSSL to 1.1.1+/3.x and rebuild dependent services."},
    {"re": re.compile(r'ProFTPD\s+1\.3\.[0-4]\b', re.I),
     "product": "ProFTPD (1.3.0–1.3.4)", "severity": "medium",
     "remediation": "Upgrade ProFTPD to the latest release."},
    {"re": re.compile(r'vsftpd\s+([12]\.\d+)', re.I),
     "product": "vsftpd (1.x/2.x)", "severity": "medium",
     "remediation": "Upgrade vsftpd to a current 3.x release."},
    {"re": re.compile(r'Exim\s+4\.[0-8]\d?\b', re.I),
     "product": "Exim (pre-4.90)", "severity": "high",
     "remediation": "Upgrade Exim to the latest 4.9x release."},
]


def match_eol(banner):
    """Return outdated/end-of-life findings for a version banner (may be empty)."""
    out = []
    if not banner:
        return out
    for sig in EOL_SIGNATURES:
        m = sig["re"].search(banner)
        if m:
            out.append({
                "kind": "outdated_service",
                "title": f"End-of-Life / Outdated Software: {sig['product']}",
                "severity": sig["severity"],
                "technical": f"An end-of-life / outdated version was detected "
                             f"({m.group(0)}). Unsupported software no longer "
                             f"receives security patches.",
                "plain": "Software running here is an old, unsupported version "
                         "that no longer gets security updates — the maker has "
                         "stopped fixing it, so new holes never get patched.",
                "risk": "End-of-life software steadily accumulates unpatched "
                        "vulnerabilities and is a common way attackers get in.",
                "remediation": sig["remediation"],
                "evidence": m.group(0),
            })
    return out
