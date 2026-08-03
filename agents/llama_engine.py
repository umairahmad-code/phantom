#!/usr/bin/env python3
"""
PHANTOM LLAMA AI ENGINE - v2.0
Fixed: No more queuing, async streaming, proper connection management
"""

import os
import sys
import requests
import json
import subprocess
import time
import threading
from typing import Generator, Optional

# Make the shared src/ modules importable regardless of how this file is loaded.
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

try:
    import phantom_config as config
    from phantom_logging import get_logger
    log = get_logger("phantom.ai")
except Exception:  # pragma: no cover - fall back to stdlib logging
    import logging
    config = None
    log = logging.getLogger("phantom.ai")


class LlamaAIEngine:
    """Local Llama AI - NO QUEUING, automatic service management"""
    
    def __init__(self, model=None, host=None, port=None):
        ai = config.ai_settings() if config else {}
        self.model = model or ai.get("model", "llama2")
        self.host = host or ai.get("host", "127.0.0.1")
        self.port = port or ai.get("port", 11434)
        self.api_url = f"http://{self.host}:{self.port}"
        self.timeout = 300
        self.session = requests.Session()
        self._ensure_ollama_running()

    def _ensure_ollama_running(self):
        """Auto-start Ollama if not running"""
        try:
            requests.get(f"{self.api_url}/api/tags", timeout=2)
            log.info("Ollama running")
        except requests.exceptions.RequestException:
            log.info("Starting Ollama...")
            try:
                subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(3)
            except (OSError, FileNotFoundError) as exc:
                log.error(f"Could not start Ollama: {exc}")

    def check_model(self) -> bool:
        """Check if model is available"""
        try:
            response = requests.get(f"{self.api_url}/api/tags", timeout=5)
            models = [m["name"] for m in response.json().get("models", [])]
            return any(self.model in m for m in models)
        except (requests.exceptions.RequestException, ValueError, KeyError):
            return False

    def pull_model(self):
        """Download model if needed"""
        log.info(f"Pulling model '{self.model}'...")
        subprocess.run(["ollama", "pull", self.model], timeout=600)
        log.info("Model ready")
    
    def query(self, prompt: str, temperature: float = 0.7) -> str:
        """Direct query - NO QUEUE"""
        try:
            response = requests.post(
                f"{self.api_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": temperature,
                },
                timeout=self.timeout,
            )
            
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                return f"❌ Error: {response.status_code}"
        except requests.exceptions.Timeout:
            return "❌ Timeout - try again"
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def query_stream(self, prompt: str) -> Generator[str, None, None]:
        """Streaming response - real-time output"""
        try:
            response = requests.post(
                f"{self.api_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": True,
                },
                stream=True,
                timeout=self.timeout,
            )
            
            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    chunk = data.get("response", "")
                    if chunk:
                        yield chunk
        except Exception as e:
            yield f"❌ Error: {str(e)}"
    
    def analyze_findings(self, findings: dict) -> str:
        """Analyze findings - NO QUEUE"""
        findings_text = json.dumps(findings, indent=2)
        
        prompt = f"""PHANTOM Agent: Analyze these penetration test findings:

{findings_text}

Provide:
1. Key discoveries
2. Severity levels
3. Next recommended phase
4. Tools to use next

Be technical and concise."""
        
        return self.query(prompt, temperature=0.3)
    
    def suggest_exploits(self, vulnerability: str) -> str:
        """Get exploit suggestions"""
        prompt = f"""Suggest exploits for: {vulnerability}

Include:
- Exploit names
- Tools needed
- Risk level
- Example commands

Technical details only."""
        
        return self.query(prompt)
    
    def chat(self, message: str) -> str:
        """Interactive chat with agent"""
        prompt = f"""You are PHANTOM, an intelligent penetration testing agent.
You know: nmap, sqlmap, metasploit, hydra, john, wapiti, burpsuite, and more.

User: {message}

Respond technical and specific."""
        
        return self.query(prompt)


if __name__ == "__main__":
    engine = LlamaAIEngine(model="llama2")
    if engine.check_model():
        print("✓ Llama AI ready")
    else:
        engine.pull_model()
