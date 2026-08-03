# PHANTOM FRAMEWORK v2.0 - WORKSPACE

<!-- June 2026 current git version snapshot -->

## 📂 Folder Structure

```
PHANTOM_WORKSPACE/
├── src/                    # Main application files
│   ├── pentest_gui.py     # Main GUI
│   ├── phantom_db_engine.py
│   └── phantom_reports.py
│
├── agents/                 # AI & Intelligence
│   ├── phantom_agent.py   # Intelligent workflow agent
│   └── llama_engine.py    # Llama AI (NO QUEUE FIX)
│
├── data/                   # Tool outputs & findings
│   ├── scans.db          # SQLite database
│   └── *.json            # Raw tool outputs
│
├── workflows/            # Saved workflow states
│   └── workflow_*.json   # Phase tracking
│
├── reports/              # Generated reports
│   ├── *.json
│   ├── *.html
│   └── *.csv
│
├── logs/                 # Execution logs
│   └── *.log
│
├── configs/             # Configuration files
│   └── phantom_config.json
│
└── tests/              # Testing & validation
```

## 🚀 Quick Start

### Launch from Workspace:
```bash
cd ~/PHANTOM_WORKSPACE
python3 src/pentest_gui.py
```

### Or use alias:
```bash
phantom    # From anywhere
```

## 🎯 Target Scope (Authorization Gate)

**New in this build — scans are blocked until you approve a target.**

Open the **★ SCOPE** tab and add the hosts you are authorized to test
(domain, IP, CIDR, or URL). While enforcement is ON (the default), any tool
launched against a target outside the approved list is refused, and the output
terminal shows a `[BLOCKED]` message.

- Approved `example.com` also matches its subdomains (e.g. `api.example.com`).
- Approved `192.168.1.0/24` matches every IP inside that range.
- Untick **"Enforce scope"** to disable the gate for ad-hoc work.

This gate also rejects any target containing shell metacharacters, so a value
like `example.com; rm -rf ~` can never reach a shell — protecting the operator
from command injection. It additionally blocks **argument injection**: a target
value cannot smuggle in a file-writing or code-executing flag (e.g. an injected
`-oN /etc/cron.d/x` on nmap or `--os-shell` on sqlmap). The tools' normal
options (scan types, timing, `--script=default`, `--dump`, wordlists, etc.)
still work exactly as before. Local/auxiliary tools (hash cracking, payload
generation, listeners, installs) are not scope-restricted but are still
injection-checked.

Need a raw, unrestricted command? Use the **manual console** at the bottom of
the window — it runs what you type, so advanced/one-off invocations remain
available to the operator.

Security tests live in `tests/test_security.py`:

```bash
python3 tests/test_security.py
```

## 🤖 Intelligent Agent Features

### Automatic Workflow Guidance
The new agent **knows all tools** and provides guidance:

```
RECON Phase:
 └─> Tools: whois, nslookup, dig, theHarvester
     └─> After findings → SCANNING phase

SCANNING Phase:
 └─> Tools: nmap, nikto, dirb, gobuster
     └─> After findings → WEBAPP phase

WEBAPP Phase:
 └─> Tools: sqlmap, wapiti, whatweb
     └─> After findings → PASSWORDS phase

Etc...
```

### How to Use Agent:
1. Run tools in GUI
2. Agent **automatically** collects outputs
3. Agent **analyzes** findings
4. Agent **suggests** next phase + tools to use

### Data Flow Example:

```
WHOIS finds: example.com owner info
     ↓
THEHARVESTEER finds: emails, IPs
     ↓
NMAP finds: open ports 22, 80, 443
     ↓
Agent says: "Found HTTP(80). Try SQLMap next!"
     ↓
SQLMAP finds: SQL Injection
     ↓
Agent says: "Critical! Extract databases with SQLMap..."
```

## 🔧 Llama AI - Fixed Issues

### Old Problem:
- Queries "queuing" and hanging
- Timeout issues
- Connection pool exhausted

### New Solution:
```python
from agents.llama_engine import LlamaAIEngine

ai = LlamaAIEngine(model="llama2")

# Direct query - NO QUEUE
response = ai.query("What next for this SQL injection?")
print(response)  # Instant answer

# Streaming - real-time output
for chunk in ai.query_stream("Analyze these findings..."):
    print(chunk, end="", flush=True)
```

### Setup:
```bash
# Terminal 1: Start Ollama
ollama serve

# Terminal 2: Use PHANTOM (auto-connects)
cd ~/PHANTOM_WORKSPACE
python3 src/pentest_gui.py
```

## 📊 Data Collection Example

All tool outputs go to `data/` with `phantom_agent` parsing:

```json
{
  "tool": "nmap",
  "target": "192.168.1.1",
  "timestamp": "20260410_143022",
  "parsed": {
    "open_ports": [22, 80, 443],
    "services": {
      "22/tcp": "ssh",
      "80/tcp": "http",
      "443/tcp": "https"
    }
  }
}
```

Agent then:
1. **Saves** to database
2. **Analyzes** the findings
3. **Suggests** next phase
4. **Guides** with recommendations

## 🎯 Phase Workflow

```
1️⃣  RECON
    └─ Collect: domains, emails, IPs
    └─ Tools: whois, dig, theHarvester
    └─ Next: SCANNING

2️⃣  SCANNING
    └─ Collect: open ports, services
    └─ Tools: nmap, nikto, gobuster
    └─ Next: WEBAPP testing

3️⃣  WEBAPP
    └─ Collect: vulnerabilities, paths
    └─ Tools: sqlmap, wapiti, whatweb
    └─ Next: PASSWORD attacks

4️⃣  PASSWORDS
    └─ Collect: credentials, hashes
    └─ Tools: hydra, john, hashcat
    └─ Next: EXPLOITATION

5️⃣  EXPLOITATION
    └─ Collect: access points, shells
    └─ Tools: metasploit, searchsploit
    └─ Next: POST-EXPLOITATION

6️⃣  POST-EXPLOIT
    └─ Collect: lateral movement, persistence
    └─ Tools: mimikatz, bloodhound
    └─ Next: REPORTING

7️⃣  REPORTING
    └─ Generate: JSON, HTML, CSV, PDF reports
    └─ View: ~/PHANTOM_WORKSPACE/reports/
```

## 💾 Save Progress

Agent automatically saves workflow state:
```bash
ls ~/PHANTOM_WORKSPACE/workflows/
# workflow_recon_20260410_143022.json
# workflow_scanning_20260410_143045.json
# ...
```

Resume anytime:
```bash
cat ~/PHANTOM_WORKSPACE/workflows/*.json | jq
```

## 🔌 Git Version Control

Check version:
```bash
cd ~/PHANTOM_WORKSPACE
git log --oneline
# v2.0 (current)
# v1.1-SPRINT2
# v1.0-INITIAL
```

## ✅ Ready!

- ✓ Intelligent Agent (knows all tools)
- ✓ Data auto-collection
- ✓ Phase guidance
- ✓ Llama AI (NO QUEUE)
- ✓ Workspace organization
- ✓ Git versioning

**Start using:**
```bash
phantom
```

No more configuration needed!
