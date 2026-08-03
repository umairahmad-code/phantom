#!/usr/bin/env python3
"""
PHANTOM AI ASSESSMENT PLANNER (agentic next-step engine)

Instead of a fixed 7-phase script, this recommends the *next* actions based on
what has actually been found so far — the "state of the art" agentic behaviour.

Two engines, transparent to the caller:
  * LLM engine  — asks the local Llama model (privacy-preserving, offline) to
                  reason over the findings and propose prioritised next steps.
  * Rule engine — a deterministic fallback that works with no AI at all, so the
                  feature never depends on Ollama being installed.

`suggest_next_actions()` tries the LLM first and falls back to rules on any
failure, tagging the result with which engine produced it.
"""

try:
    import phantom_findings as findings_mod  # noqa: F401 (kept for symmetry)
except ImportError:
    from src import phantom_findings as findings_mod  # noqa: F401


# ── Rule-based planner ────────────────────────────────────────────────
def _kinds(findings):
    return {str(f.get("kind", "")).lower() for f in findings}


def _has_web(findings):
    for f in findings:
        title = str(f.get("title", "")).lower()
        if "80/" in title or "443/" in title or "http" in title:
            return True
    return "missing_security_headers" in _kinds(findings) or \
           "directory_listing" in _kinds(findings)


def rule_based_plan(findings, tools_run=None):
    """Deterministic next-step suggestions from the current findings."""
    findings = findings or []
    tools_run = {t.lower() for t in (tools_run or [])}
    kinds = _kinds(findings)
    steps = []

    def add(action, why, priority="medium"):
        steps.append({"action": action, "why": why, "priority": priority})

    # 1. Nothing yet → start with recon.
    if not findings and not tools_run:
        add("Run reconnaissance (whois, dig, theHarvester)",
            "No data collected yet — map the target's footprint first.", "high")
        add("Discover the attack surface (subdomains & live hosts)",
            "Find everything exposed before scanning.", "high")
        return {"engine": "rules", "steps": steps}

    # 2. Ports found but no version scan → deepen.
    open_ports = [f for f in findings if str(f.get("kind", "")) == "" and
                  "open port" in str(f.get("title", "")).lower()]
    if open_ports and "nmap" not in tools_run:
        add("Run a service/version scan (nmap -sV) on the open ports",
            "Open ports were found; identify versions to match known CVEs.", "high")

    # 3. Web service present but not web-scanned.
    if _has_web(findings) and not ({"nikto", "whatweb", "wapiti"} & tools_run):
        add("Run web checks (nikto, whatweb) on the web service",
            "A web server is exposed — check for misconfig and known issues.", "high")

    # 4. Web + no SQLi test yet.
    if _has_web(findings) and "sqlmap" not in tools_run:
        add("Test input fields for SQL injection (sqlmap)",
            "Web app present; SQL injection is a critical, common flaw.", "medium")

    # 5. CVEs / outdated software → prioritise patching guidance + exploit check.
    if "cve" in kinds or "outdated_service" in kinds:
        add("Confirm the version-based CVEs and check exploit availability "
            "(searchsploit)", "Known-vulnerable versions were detected.", "high")

    # 6. Cleartext / weak creds → access hardening.
    if "weak_credentials" in kinds:
        add("Document the credential weakness and recommend MFA + lockout",
            "Guessable credentials were found — highest-impact fix.", "high")
    if "cleartext_protocol" in kinds:
        add("Flag cleartext services for migration to encrypted equivalents",
            "Credentials are exposed on the wire.", "medium")

    # 7. Email spoofing not yet checked.
    if not ({"email", "dmarc", "spf"} & tools_run):
        add("Run the email/domain spoofing check (SPF/DMARC/DKIM)",
            "Phishing is the top SMB risk; verify the domain can't be spoofed.",
            "medium")

    # 8. Always finish with reporting.
    add("Generate the client report (Cyber Essentials readiness)",
        "Turn the findings into the client deliverable.", "low")

    # De-duplicate while preserving order and rank by priority.
    order = {"high": 0, "medium": 1, "low": 2}
    seen, uniq = set(), []
    for s in steps:
        if s["action"] in seen:
            continue
        seen.add(s["action"])
        uniq.append(s)
    uniq.sort(key=lambda s: order.get(s["priority"], 1))
    return {"engine": "rules", "steps": uniq}


# ── LLM planner ───────────────────────────────────────────────────────
def _findings_brief(findings, limit=15):
    lines = []
    for f in (findings or [])[:limit]:
        lines.append(f"- [{f.get('severity', 'info')}] {f.get('title', '')}"
                     f" ({f.get('evidence', '')})")
    return "\n".join(lines) or "- (no findings yet)"


def llm_plan(findings, tools_run=None, engine=None):
    """
    Ask the local Llama model for prioritised next steps.
    Raises on any failure so the caller can fall back to rules.
    """
    if engine is None:
        try:
            from llama_engine import LlamaAIEngine
        except ImportError:
            from agents.llama_engine import LlamaAIEngine
        engine = LlamaAIEngine()

    # Only use the LLM if the model is actually reachable.
    if hasattr(engine, "check_model") and not engine.check_model():
        raise RuntimeError("Local model not available")

    prompt = (
        "You are a penetration-testing assistant. Based on the findings so far, "
        "suggest the 3 most useful NEXT actions, most important first. Be concrete "
        "and safe (assessment only, authorised scope). For each: one short action "
        "line, then 'why:' one sentence.\n\n"
        f"Tools already run: {', '.join(sorted(tools_run or [])) or 'none'}\n"
        f"Findings so far:\n{_findings_brief(findings)}\n\n"
        "Answer as a numbered list."
    )
    text = engine.query(prompt)
    if not text or not str(text).strip():
        raise RuntimeError("Empty LLM response")

    steps = _parse_llm_steps(str(text))
    if not steps:
        raise RuntimeError("Could not parse LLM response")
    return {"engine": "llm", "steps": steps, "raw": text}


def _parse_llm_steps(text):
    """Best-effort parse of a numbered/bulleted LLM answer into steps."""
    steps = []
    action, why = None, ""
    import re
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r'^(?:\d+[.)]|[-*])\s*(.+)', line)
        if m:
            if action:
                steps.append({"action": action, "why": why.strip(),
                              "priority": "medium"})
            action, why = m.group(1).strip(), ""
        elif line.lower().startswith("why:"):
            why = line[4:].strip()
        elif action and not why:
            why = line
    if action:
        steps.append({"action": action, "why": why.strip(), "priority": "medium"})
    return steps[:5]


def suggest_next_actions(findings, tools_run=None, use_ai=True, engine=None):
    """
    Main entry point. Returns {"engine": "llm"|"rules", "steps":[...], ...}.
    Tries the local AI first (if use_ai), falls back to deterministic rules.
    """
    if use_ai:
        try:
            return llm_plan(findings, tools_run, engine=engine)
        except Exception:
            pass  # fall through to rules — feature must never hard-fail
    return rule_based_plan(findings, tools_run)


if __name__ == "__main__":
    demo = [{"title": "Open port 80/http", "severity": "info", "kind": "",
             "evidence": "80/http"},
            {"title": "Outdated / Vulnerable Software Version",
             "severity": "high", "kind": "outdated_service", "evidence": "Apache 2.4.49"}]
    import json
    print(json.dumps(suggest_next_actions(demo, tools_run=["nmap"], use_ai=False), indent=2))
