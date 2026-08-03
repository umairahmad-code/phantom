#!/usr/bin/env python3
"""
PHANTOM INTELLIGENT AGENT - v2.0
Smart workflow automation and guidance system
Collects tool data, analyzes findings, guides next phases
"""

import json
import os
import datetime
from pathlib import Path
from typing import Dict, List, Tuple

# ─── TOOL DEPENDENCY GRAPH ───────────────────────────
TOOL_WORKFLOWS = {
    "recon": {
        "tools": ["whois", "nslookup", "dig", "theHarvester", "traceroute", "host"],
        "outputs": ["domain_info", "ip_addresses", "emails", "nameservers", "dns_records"],
        "next_phase": "scanning",
        "next_tools": ["nmap", "nikto"],
    },
    
    "scanning": {
        "tools": ["nmap", "nikto", "dirb", "gobuster", "masscan"],
        "outputs": ["open_ports", "services", "versions", "web_dirs"],
        "next_phase": "webapp",
        "next_tools": ["sqlmap", "wapiti", "whatweb"],
    },
    
    "webapp": {
        "tools": ["sqlmap", "wapiti", "whatweb", "curl", "burpsuite"],
        "outputs": ["sql_injection", "xss", "paths", "technologies"],
        "next_phase": "passwords",
        "next_tools": ["hydra", "john", "hashcat"],
    },
    
    "passwords": {
        "tools": ["hydra", "john", "hashcat"],
        "outputs": ["credentials", "hashes_cracked", "wordlists_used"],
        "next_phase": "exploitation",
        "next_tools": ["metasploit", "msfvenom"],
    },
    
    "exploitation": {
        "tools": ["metasploit", "msfvenom", "searchsploit"],
        "outputs": ["exploits_found", "payloads", "shells", "access_gained"],
        "next_phase": "post_exploit",
        "next_tools": ["privilege_escalation", "persistence"],
    },
    
    "post_exploit": {
        "tools": ["mimikatz", "responder", "bloodhound"],
        "outputs": ["credentials", "hashes", "domain_info", "high_value_targets"],
        "next_phase": "reporting",
        "next_tools": ["report_generation"],
    },
}

# ─── VULNERABILITY MAPPING ───────────────────────────
VULN_TO_EXPLOIT = {
    "sql_injection": {
        "severity": "critical",
        "tools": ["sqlmap"],
        "exploit_types": ["database_access", "file_read", "command_execution"],
    },
    "rce": {
        "severity": "critical",
        "tools": ["metasploit", "searchsploit"],
        "exploit_types": ["reverse_shell", "bind_shell", "web_shell"],
    },
    "xss": {
        "severity": "high",
        "tools": ["wapiti", "whatweb"],
        "exploit_types": ["cookie_stealing", "session_hijacking", "malware_injection"],
    },
    "weak_authentication": {
        "severity": "high",
        "tools": ["hydra", "john"],
        "exploit_types": ["brute_force", "dictionary_attack", "credential_reuse"],
    },
    "unpatched_service": {
        "severity": "high",
        "tools": ["metasploit", "searchsploit"],
        "exploit_types": ["known_exploit", "version_specific_attack"],
    },
}


class PhantomAgent:
    """Intelligent agent for PHANTOM Framework"""
    
    def __init__(self, workspace_path=None):
        self.workspace = workspace_path or os.path.expanduser("~/PHANTOM_WORKSPACE")
        self.data_dir = os.path.join(self.workspace, "data")
        self.workflows_dir = os.path.join(self.workspace, "workflows")
        
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.workflows_dir, exist_ok=True)
        
        self.current_phase = "recon"
        self.findings = {}
        self.recommendations = []
        
    def collect_tool_output(self, tool_name: str, output: str, target: str = ""):
        """Collect and parse tool output"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("_") or "target"
        
        # Store raw output
        output_file = os.path.join(
            self.data_dir,
            f"{tool_name}_{safe_target}_{timestamp}.json"
        )
        
        parsed_data = self._parse_tool_output(tool_name, output)
        
        with open(output_file, "w") as f:
            json.dump({
                "tool": tool_name,
                "target": target,
                "timestamp": timestamp,
                "raw_output": output,
                "parsed": parsed_data,
            }, f, indent=2)
        
        # Update findings
        if tool_name not in self.findings:
            self.findings[tool_name] = []
        self.findings[tool_name].append(parsed_data)
        
        return parsed_data
    
    def _parse_tool_output(self, tool_name: str, output: str) -> Dict:
        """Parse tool output for key information"""
        parsed = {}
        
        if tool_name == "nmap":
            parsed["open_ports"] = self._extract_open_ports(output)
            parsed["services"] = self._extract_services(output)
        
        elif tool_name == "sqlmap":
            if "injectable" in output.lower():
                parsed["sql_injection_found"] = True
                parsed["databases"] = self._extract_databases(output)
            else:
                parsed["sql_injection_found"] = False
        
        elif tool_name == "whois":
            parsed["domain_info"] = self._extract_domain_info(output)
            parsed["registrar"] = self._extract_registrar(output)
        
        elif tool_name == "theHarvester":
            parsed["emails"] = self._extract_emails(output)
            parsed["ips"] = self._extract_ips(output)
        
        elif tool_name == "hydra":
            parsed["credentials"] = self._extract_credentials(output)
        
        return parsed
    
    def _extract_open_ports(self, output: str) -> List[int]:
        """Extract open ports from nmap output"""
        ports = []
        for line in output.split("\n"):
            if "/tcp" in line or "/udp" in line:
                try:
                    port = int(line.split()[0].split("/")[0])
                    ports.append(port)
                except (ValueError, IndexError):
                    pass
        return ports
    
    def _extract_services(self, output: str) -> Dict:
        """Extract service versions from nmap output"""
        services = {}
        for line in output.split("\n"):
            if "open" in line and "/" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    services[port] = service
        return services
    
    def _extract_emails(self, output: str) -> List[str]:
        """Extract emails from theHarvester output"""
        emails = []
        for line in output.split("\n"):
            if "@" in line:
                email = line.strip().split()[-1] if line.strip() else ""
                if "@" in email and "." in email:
                    emails.append(email)
        return list(set(emails))
    
    def _extract_ips(self, output: str) -> List[str]:
        """Extract IPs from tool output"""
        ips = []
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for match in re.finditer(ip_pattern, output):
            ips.append(match.group())
        return list(set(ips))
    
    def _extract_credentials(self, output: str) -> List[Dict]:
        """Extract credentials from Hydra output"""
        creds = []
        for line in output.split("\n"):
            if "[+]" in line or "password:" in line.lower():
                creds.append({"raw": line.strip()})
        return creds
    
    def _extract_domain_info(self, output: str) -> Dict:
        """Extract domain info from WHOIS"""
        return {"raw": output[:200]}
    
    def _extract_registrar(self, output: str) -> str:
        """Extract registrar from WHOIS"""
        for line in output.split("\n"):
            if "registrar" in line.lower():
                return line.split(":", 1)[-1].strip()
        return "unknown"
    
    def _extract_databases(self, output: str) -> List[str]:
        """Extract databases from SQLMap output"""
        databases = []
        for line in output.split("\n"):
            if "database" in line.lower():
                databases.append(line.strip())
        return databases
    
    def analyze_findings(self) -> Dict:
        """Analyze all findings and generate recommendations"""
        analysis = {
            "phase": self.current_phase,
            "findings_summary": {},
            "vulnerabilities": [],
            "next_actions": [],
            "recommended_tools": [],
        }
        
        # Summarize findings
        for tool, data_list in self.findings.items():
            if data_list:
                analysis["findings_summary"][tool] = len(data_list)
        
        # Detect vulnerabilities
        if "nmap" in self.findings:
            open_ports = []
            for data in self.findings.get("nmap", []):
                open_ports.extend(data.get("open_ports", []))
            
            analysis["vulnerabilities"].append({
                "type": "open_ports",
                "severity": "high",
                "count": len(set(open_ports)),
                "ports": sorted(set(open_ports))
            })
        
        if "sqlmap" in self.findings:
            for data in self.findings.get("sqlmap", []):
                if data.get("sql_injection_found"):
                    analysis["vulnerabilities"].append({
                        "type": "sql_injection",
                        "severity": "critical",
                        "databases": data.get("databases", [])
                    })
        
        # Recommend next phase
        if self.current_phase in TOOL_WORKFLOWS:
            workflow = TOOL_WORKFLOWS[self.current_phase]
            analysis["next_phase"] = workflow["next_phase"]
            analysis["recommended_tools"] = workflow["next_tools"]
            
            analysis["next_actions"] = [
                f"✓ Move to {workflow['next_phase'].upper()} phase",
                f"✓ Use these tools: {', '.join(workflow['next_tools'])}",
                f"✓ Focus on: {', '.join(workflow['outputs'])}",
            ]
        
        self.recommendations = analysis["next_actions"]
        return analysis
    
    def get_next_steps(self) -> str:
        """Get formatted guidance for next phase"""
        analysis = self.analyze_findings()
        
        guidance = f"""
╔════════════════════════════════════════════════════════════╗
║          PHANTOM INTELLIGENT AGENT - NEXT STEPS            ║
╚════════════════════════════════════════════════════════════╝

📊 CURRENT PHASE: {analysis['phase'].upper()}

🔍 FINDINGS:
"""
        
        for vuln in analysis["vulnerabilities"]:
            guidance += f"\n  • [{vuln['severity'].upper()}] {vuln['type']}"
            if "count" in vuln:
                guidance += f" ({vuln['count']} found)"
        
        if not analysis["vulnerabilities"]:
            guidance += "\n  • No critical vulnerabilities detected yet"
        
        guidance += f"\n\n→ NEXT PHASE: {analysis.get('next_phase', 'unknown').upper()}\n"
        guidance += f"\n🎯 RECOMMENDED TOOLS:"
        for tool in analysis.get("recommended_tools", []):
            guidance += f"\n  • {tool}"
        
        guidance += f"\n\n✅ ACTION ITEMS:"
        for action in analysis.get("next_actions", []):
            guidance += f"\n  {action}"
        
        guidance += "\n\n════════════════════════════════════════════════════════════\n"
        
        return guidance
    
    def save_workflow_state(self, state_name: str = ""):
        """Save current workflow state"""
        if not state_name:
            state_name = f"workflow_{self.current_phase}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        state_file = os.path.join(self.workflows_dir, f"{state_name}.json")
        
        state_data = {
            "phase": self.current_phase,
            "timestamp": datetime.datetime.now().isoformat(),
            "findings": self.findings,
            "recommendations": self.recommendations,
        }
        
        with open(state_file, "w") as f:
            json.dump(state_data, f, indent=2)
        
        return state_file
    
    def advance_phase(self) -> str:
        """Move to next phase in workflow"""
        workflow = TOOL_WORKFLOWS.get(self.current_phase, {})
        next_phase = workflow.get("next_phase", "unknown")
        
        if next_phase != "unknown":
            self.current_phase = next_phase
            self.save_workflow_state()
            return f"✓ Advanced to {next_phase.upper()} phase"
        
        return "✗ Cannot advance further"


if __name__ == "__main__":
    agent = PhantomAgent()
    print("✓ PHANTOM Intelligent Agent initialized")
