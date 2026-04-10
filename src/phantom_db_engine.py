#!/usr/bin/env python3
"""
PHANTOM DATABASE ENGINE - SQLite3 Database Management
Stores scan results, vulnerabilities, and team findings
"""

import sqlite3
import os
import json
import datetime
from pathlib import Path

# ─── DATABASE INITIALIZATION ─────────────────────
DB_PATH = os.path.expanduser("~/.phantom/scans.db")
DB_DIR = os.path.dirname(DB_PATH)

if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR, exist_ok=True)


class PhantomDatabase:
    """Main database handler for PHANTOM framework"""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.conn = None
        self.init_db()

    def connect(self):
        """Connect to database"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

    def init_db(self):
        """Initialize database tables if they don't exist"""
        if not self.connect():
            return False

        cursor = self.conn.cursor()

        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE,
                target TEXT,
                scan_type TEXT,
                timestamp DATETIME,
                status TEXT,
                risk_level TEXT,
                notes TEXT,
                team_member TEXT
            )
        """)

        # Results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                tool_name TEXT,
                tool_output TEXT,
                timestamp DATETIME,
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
            )
        """)

        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                vuln_type TEXT,
                description TEXT,
                severity TEXT,
                confidence INTEGER,
                remediation TEXT,
                cve_id TEXT,
                timestamp DATETIME,
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
            )
        """)

        # Hosts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                ip_address TEXT,
                hostname TEXT,
                os TEXT,
                open_ports TEXT,
                services TEXT,
                timestamp DATETIME,
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
            )
        """)

        # Team collaboration table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS team_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                team_member TEXT,
                finding TEXT,
                severity TEXT,
                timestamp DATETIME,
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
            )
        """)

        # Exploit candidates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                vulnerability TEXT,
                exploit_name TEXT,
                searchsploit_id TEXT,
                metasploit_module TEXT,
                cvss_score REAL,
                timestamp DATETIME,
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
            )
        """)

        # Audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                user TEXT,
                timestamp DATETIME,
                details TEXT
            )
        """)

        self.conn.commit()
        self.close()
        return True

    def create_scan(self, target, scan_type, team_member="admin"):
        """Create a new scan record"""
        if not self.connect():
            return None

        scan_id = f"scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO scans (scan_id, target, scan_type, timestamp, status, risk_level, team_member)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, target, scan_type, datetime.datetime.now(), "ongoing", "unknown", team_member))
            self.conn.commit()
            self._audit_log("CREATE_SCAN", team_member, f"Started scan: {scan_id} on {target}")
            return scan_id
        except Exception as e:
            print(f"❌ Error creating scan: {e}")
            return None
        finally:
            self.close()

    def save_result(self, scan_id, tool_name, tool_output):
        """Save tool output to results table"""
        if not self.connect():
            return False

        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO results (scan_id, tool_name, tool_output, timestamp)
                VALUES (?, ?, ?, ?)
            """, (scan_id, tool_name, tool_output, datetime.datetime.now()))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"❌ Error saving result: {e}")
            return False
        finally:
            self.close()

    def save_vulnerability(self, scan_id, vuln_type, description, severity, cve_id="", remediation=""):
        """Save vulnerability finding"""
        if not self.connect():
            return False

        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO vulnerabilities (scan_id, vuln_type, description, severity, cve_id, remediation, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, vuln_type, description, severity, cve_id, remediation, datetime.datetime.now()))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"❌ Error saving vulnerability: {e}")
            return False
        finally:
            self.close()

    def save_host(self, scan_id, ip_address, hostname="", os="", open_ports="", services=""):
        """Save discovered host information"""
        if not self.connect():
            return False

        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO hosts (scan_id, ip_address, hostname, os, open_ports, services, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, ip_address, hostname, os, open_ports, services, datetime.datetime.now()))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"❌ Error saving host: {e}")
            return False
        finally:
            self.close()

    def suggest_exploits(self, scan_id, vulnerability, cvss_threshold=7.0):
        """Suggest exploits based on vulnerability"""
        # This is a placeholder - full exploit database would be integrated
        exploit_db = {
            "SQL Injection": [
                {"name": "SQLMap", "module": "auxiliary/scanner/http/sql_injection", "cvss": 9.8},
            ],
            "Remote Code Execution": [
                {"name": "Metasploit RCE", "module": "exploit/multi/handler", "cvss": 10.0},
            ],
            "Cross-Site Scripting": [
                {"name": "BeEF XSS", "module": "auxiliary/scanner/http/xss", "cvss": 6.1},
            ],
        }

        exploits = exploit_db.get(vulnerability, [])
        if not self.connect():
            return []

        cursor = self.conn.cursor()

        for exploit in exploits:
            if exploit.get("cvss", 0) >= cvss_threshold:
                try:
                    cursor.execute("""
                        INSERT INTO exploits (scan_id, vulnerability, exploit_name, cvss_score, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """, (scan_id, vulnerability, exploit["name"], exploit.get("cvss", 0), datetime.datetime.now()))
                except Exception as e:
                    print(f"❌ Error suggesting exploit: {e}")

        self.conn.commit()
        self.close()
        return exploits

    def get_scan_summary(self, scan_id):
        """Get summary of a scan"""
        if not self.connect():
            return None

        cursor = self.conn.cursor()

        try:
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            scan = cursor.fetchone()

            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
            vuln_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM hosts WHERE scan_id = ?", (scan_id,))
            host_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM results WHERE scan_id = ?", (scan_id,))
            result_count = cursor.fetchone()[0]

            return {
                "scan": dict(scan) if scan else None,
                "vulns": vuln_count,
                "hosts": host_count,
                "results": result_count,
            }
        except Exception as e:
            print(f"❌ Error getting summary: {e}")
            return None
        finally:
            self.close()

    def get_scan_details_full(self, scan_id):
        """Get full details of a scan including actual data (for reports)"""
        if not self.connect():
            return None

        cursor = self.conn.cursor()

        try:
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            scan = cursor.fetchone()

            cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC", (scan_id,))
            vulns = [dict(row) for row in cursor.fetchall()]

            cursor.execute("SELECT * FROM hosts WHERE scan_id = ?", (scan_id,))
            hosts = [dict(row) for row in cursor.fetchall()]

            cursor.execute("SELECT * FROM exploits WHERE scan_id = ?", (scan_id,))
            exploits = [dict(row) for row in cursor.fetchall()]

            return {
                "scan": dict(scan) if scan else None,
                "vulnerabilities": vulns,
                "hosts": hosts,
                "exploits": exploits,
            }
        except Exception as e:
            print(f"❌ Error getting details: {e}")
            return None
        finally:
            self.close()

    def get_all_scans(self):
        """Get all scans"""
        if not self.connect():
            return []

        cursor = self.conn.cursor()

        try:
            cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 50")
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Error getting scans: {e}")
            return []
        finally:
            self.close()

    def update_scan_status(self, scan_id, status, risk_level=""):
        """Update scan status"""
        if not self.connect():
            return False

        cursor = self.conn.cursor()

        try:
            if risk_level:
                cursor.execute("""
                    UPDATE scans SET status = ?, risk_level = ? WHERE scan_id = ?
                """, (status, risk_level, scan_id))
            else:
                cursor.execute("""
                    UPDATE scans SET status = ? WHERE scan_id = ?
                """, (status, scan_id))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"❌ Error updating scan: {e}")
            return False
        finally:
            self.close()

    def add_team_finding(self, scan_id, team_member, finding, severity="medium"):
        """Add team collaboration finding"""
        if not self.connect():
            return False

        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO team_findings (scan_id, team_member, finding, severity, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, team_member, finding, severity, datetime.datetime.now()))
            self.conn.commit()
            self._audit_log("ADD_FINDING", team_member, f"Added finding to {scan_id}")
            return True
        except Exception as e:
            print(f"❌ Error adding finding: {e}")
            return False
        finally:
            self.close()

    def get_team_findings(self, scan_id):
        """Get team findings for a scan"""
        if not self.connect():
            return []

        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                SELECT * FROM team_findings WHERE scan_id = ? ORDER BY timestamp DESC
            """, (scan_id,))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Error getting findings: {e}")
            return []
        finally:
            self.close()

    def _audit_log(self, action, user, details=""):
        """Internal audit logging"""
        if not self.conn:
            return

        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO audit_log (action, user, timestamp, details)
                VALUES (?, ?, ?, ?)
            """, (action, user, datetime.datetime.now(), details))
            self.conn.commit()
        except Exception as e:
            print(f"❌ Audit log error: {e}")


# ─── HELPER FUNCTIONS ───────────────────────────

def init_phantom_db():
    """Initialize database"""
    db = PhantomDatabase()
    return db


if __name__ == "__main__":
    # Test database
    db = PhantomDatabase()
    print("✓ Database initialized at:", DB_PATH)
    print("✓ All tables created successfully")
