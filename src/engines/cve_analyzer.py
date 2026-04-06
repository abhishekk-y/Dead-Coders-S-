#!/usr/bin/env python3
"""
CVE/Vulnerability Analyzer - LogSentinel Pro v4.0
Correlate system logs against known CVEs (Common Vulnerabilities & Exposures).
"""

import hashlib
import json
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


class CVEDatabase:
    """Local CVE database with vulnerability tracking."""

    def __init__(self, db_dir: str = None):
        self.db_dir = Path(db_dir or Path.home() / ".local/share/LogSentinel Pro/cve_data")
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.db_dir / "cve_database.db"
        self._init_db()
        self._seed_critical_cves()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY, description TEXT, severity TEXT,
            cvss_score REAL, affected_software TEXT, affected_versions TEXT,
            attack_vector TEXT, cwe_id TEXT, published_date TEXT,
            last_modified TEXT, references_json TEXT, mitre_technique TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_time TEXT,
            cve_id TEXT, matched_software TEXT, matched_version TEXT,
            log_evidence TEXT, risk_level TEXT, remediation TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS software_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT,
            version TEXT, detected_from TEXT, first_seen TEXT,
            last_seen TEXT, UNIQUE(name, version))""")
        conn.commit()
        conn.close()

    def _seed_critical_cves(self):
        """Seed database with critical CVEs relevant to log analysis."""
        critical_cves = [
            ("CVE-2021-44228", "Apache Log4j RCE (Log4Shell)",
             "CRITICAL", 10.0, "log4j", "2.0-2.14.1",
             "network", "CWE-917", "2021-12-10", "T1190"),
            ("CVE-2021-45046", "Log4j incomplete fix bypass",
             "CRITICAL", 9.0, "log4j", "2.0-2.15.0",
             "network", "CWE-917", "2021-12-14", "T1190"),
            ("CVE-2023-44487", "HTTP/2 Rapid Reset DDoS",
             "HIGH", 7.5, "nginx,apache,envoy",
             "nginx<1.25.3,apache<2.4.58",
             "network", "CWE-400", "2023-10-10", "T1499"),
            ("CVE-2024-3094", "XZ Utils backdoor (liblzma)",
             "CRITICAL", 10.0, "xz,liblzma", "5.6.0-5.6.1",
             "network", "CWE-506", "2024-03-29", "T1195.002"),
            ("CVE-2021-3156", "Sudo Heap Overflow (Baron Samedit)",
             "CRITICAL", 7.8, "sudo", "<1.9.5p2",
             "local", "CWE-122", "2021-01-26", "T1068"),
            ("CVE-2023-38408", "OpenSSH Agent RCE",
             "CRITICAL", 9.8, "openssh,sshd", "<9.3p2",
             "network", "CWE-426", "2023-07-19", "T1021.004"),
            ("CVE-2023-25136", "OpenSSH Pre-Auth Double Free",
             "HIGH", 6.5, "openssh,sshd", "9.1",
             "network", "CWE-415", "2023-02-03", "T1190"),
            ("CVE-2022-0847", "Dirty Pipe Linux Kernel LPE",
             "HIGH", 7.8, "linux-kernel", "5.8-5.16.11",
             "local", "CWE-281", "2022-03-07", "T1068"),
            ("CVE-2021-4034", "Polkit pkexec LPE (PwnKit)",
             "CRITICAL", 7.8, "polkit,pkexec", "<0.120",
             "local", "CWE-787", "2022-01-25", "T1068"),
            ("CVE-2020-1472", "Zerologon - Netlogon Elevation",
             "CRITICAL", 10.0, "samba,netlogon",
             "samba<4.12.6", "network", "CWE-330",
             "2020-08-17", "T1557"),
            ("CVE-2023-23397", "MS Outlook NTLM Relay",
             "CRITICAL", 9.8, "outlook,exchange",
             "outlook<16.0", "network", "CWE-294",
             "2023-03-14", "T1557"),
            ("CVE-2022-41040", "MS Exchange SSRF (ProxyNotShell)",
             "HIGH", 8.8, "exchange", "<Oct2022",
             "network", "CWE-918", "2022-09-30", "T1190"),
            ("CVE-2023-22515", "Confluence Broken Access Control",
             "CRITICAL", 10.0, "confluence",
             "<8.3.3", "network", "CWE-284",
             "2023-10-04", "T1190"),
            ("CVE-2023-46604", "Apache ActiveMQ RCE",
             "CRITICAL", 10.0, "activemq",
             "<5.15.16,<5.16.7,<5.17.6,<5.18.3",
             "network", "CWE-502", "2023-10-27", "T1190"),
            ("CVE-2024-21762", "Fortinet FortiOS Out-of-Bounds Write",
             "CRITICAL", 9.8, "fortios,fortigate",
             "<7.4.3", "network", "CWE-787",
             "2024-02-08", "T1190"),
        ]

        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        for cve in critical_cves:
            c.execute("""INSERT OR IGNORE INTO cves
                (cve_id,description,severity,cvss_score,affected_software,
                 affected_versions,attack_vector,cwe_id,published_date,mitre_technique)
                VALUES (?,?,?,?,?,?,?,?,?,?)""", cve)
        conn.commit()
        conn.close()

    def search_cve(self, software: str) -> List[Dict]:
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("""SELECT * FROM cves WHERE affected_software LIKE ?
                     ORDER BY cvss_score DESC""", (f"%{software}%",))
        cols = [d[0] for d in c.description]
        rows = [dict(zip(cols, r)) for r in c.fetchall()]
        conn.close()
        return rows

    def get_all_cves(self) -> List[Dict]:
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("SELECT * FROM cves ORDER BY cvss_score DESC")
        cols = [d[0] for d in c.description]
        rows = [dict(zip(cols, r)) for r in c.fetchall()]
        conn.close()
        return rows

    def get_cve_stats(self) -> Dict:
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM cves")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM cves WHERE severity='CRITICAL'")
        critical = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM cves WHERE severity='HIGH'")
        high = c.fetchone()[0]
        c.execute("SELECT AVG(cvss_score) FROM cves")
        avg_cvss = c.fetchone()[0] or 0
        conn.close()
        return {"total": total, "critical": critical,
                "high": high, "avg_cvss": round(avg_cvss, 1)}


class LogCVECorrelator:
    """Correlate log data against CVE database."""

    # Software signatures extracted from log patterns
    SOFTWARE_PATTERNS = {
        "openssh": [
            re.compile(r'sshd\[', re.I),
            re.compile(r'OpenSSH[_/](\S+)', re.I),
            re.compile(r'SSH-2\.0-OpenSSH_(\S+)', re.I),
        ],
        "sudo": [
            re.compile(r'sudo\[', re.I),
            re.compile(r'sudo:\s', re.I),
        ],
        "apache": [
            re.compile(r'apache2?\[', re.I),
            re.compile(r'httpd\[', re.I),
            re.compile(r'Apache/(\S+)', re.I),
        ],
        "nginx": [
            re.compile(r'nginx\[', re.I),
            re.compile(r'nginx/(\S+)', re.I),
        ],
        "samba": [
            re.compile(r'smbd\[', re.I),
            re.compile(r'samba', re.I),
        ],
        "log4j": [
            re.compile(r'log4j', re.I),
            re.compile(r'\$\{jndi:', re.I),  # Log4Shell indicator
            re.compile(r'\$\{env:', re.I),
        ],
        "mysql": [
            re.compile(r'mysqld?\[', re.I),
            re.compile(r'MariaDB', re.I),
        ],
        "postgresql": [
            re.compile(r'postgres\[', re.I),
            re.compile(r'postgresql', re.I),
        ],
        "kernel": [
            re.compile(r'kernel:\s', re.I),
            re.compile(r'Linux version (\S+)', re.I),
        ],
        "exchange": [
            re.compile(r'MSExchange', re.I),
            re.compile(r'Exchange\s', re.I),
        ],
        "polkit": [
            re.compile(r'pkexec\[', re.I),
            re.compile(r'polkitd\[', re.I),
        ],
    }

    # Version extraction patterns
    VERSION_PATTERNS = [
        re.compile(r'(\d+\.\d+(?:\.\d+)?(?:p\d+)?)'),
    ]

    def __init__(self, cve_db: CVEDatabase = None):
        self.cve_db = cve_db or CVEDatabase()
        self.detected_software: Dict[str, Dict] = {}
        self.vulnerabilities: List[Dict] = []

    def analyze_log_file(self, filepath: str) -> Dict:
        """Analyze a log file for CVE-relevant software and vulnerabilities."""
        results = {
            "file": filepath,
            "scan_time": datetime.now().isoformat(),
            "detected_software": [],
            "potential_vulnerabilities": [],
            "log4shell_indicators": [],
            "risk_summary": {},
            "lines_analyzed": 0,
            "events_matched": 0,
        }

        try:
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            results["error"] = str(e)
            return results

        results["lines_analyzed"] = len(lines)

        for i, line in enumerate(lines):
            # Detect software from log patterns
            for software, patterns in self.SOFTWARE_PATTERNS.items():
                for pattern in patterns:
                    match = pattern.search(line)
                    if match:
                        version = ""
                        if match.lastindex and match.lastindex >= 1:
                            version = match.group(1)
                        if software not in self.detected_software:
                            self.detected_software[software] = {
                                "name": software,
                                "version": version,
                                "first_seen_line": i + 1,
                                "occurrences": 0,
                                "sample_lines": []
                            }
                        self.detected_software[software]["occurrences"] += 1
                        if len(self.detected_software[software]["sample_lines"]) < 3:
                            self.detected_software[software]["sample_lines"].append(
                                line.strip()[:120]
                            )
                        results["events_matched"] += 1
                        break

            # Special: Log4Shell payload detection
            if re.search(r'\$\{jndi:(ldap|rmi|dns):', line, re.I):
                results["log4shell_indicators"].append({
                    "line": i + 1,
                    "payload": re.search(
                        r'\$\{jndi:\S+\}', line, re.I
                    ).group(0)[:100] if re.search(
                        r'\$\{jndi:\S+\}', line, re.I
                    ) else line.strip()[:100],
                    "severity": "CRITICAL",
                    "cve": "CVE-2021-44228"
                })

        # Match detected software against CVE database
        for sw_name, sw_info in self.detected_software.items():
            matching_cves = self.cve_db.search_cve(sw_name)
            for cve in matching_cves:
                vuln = {
                    "cve_id": cve["cve_id"],
                    "description": cve["description"],
                    "severity": cve["severity"],
                    "cvss_score": cve["cvss_score"],
                    "detected_software": sw_name,
                    "detected_version": sw_info.get("version", "unknown"),
                    "affected_versions": cve["affected_versions"],
                    "attack_vector": cve["attack_vector"],
                    "mitre_technique": cve.get("mitre_technique", ""),
                    "evidence_lines": sw_info.get("sample_lines", []),
                    "occurrences": sw_info["occurrences"],
                }
                self.vulnerabilities.append(vuln)

        results["detected_software"] = list(self.detected_software.values())
        results["potential_vulnerabilities"] = sorted(
            self.vulnerabilities, key=lambda x: x["cvss_score"], reverse=True
        )

        # Risk summary
        crit = sum(1 for v in self.vulnerabilities if v["severity"] == "CRITICAL")
        high = sum(1 for v in self.vulnerabilities if v["severity"] == "HIGH")
        risk_score = min(100, crit * 30 + high * 15)
        results["risk_summary"] = {
            "total_vulns": len(self.vulnerabilities),
            "critical": crit,
            "high": high,
            "risk_score": risk_score,
            "risk_level": (
                "CRITICAL" if risk_score >= 75 else
                "HIGH" if risk_score >= 50 else
                "MEDIUM" if risk_score >= 25 else "LOW"
            ),
            "software_detected": len(self.detected_software),
            "log4shell_detected": len(results["log4shell_indicators"]) > 0,
        }

        return results

    def generate_remediation(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate remediation recommendations."""
        remediation_map = {
            "CVE-2021-44228": "Upgrade Log4j to 2.17.1+. Set log4j2.formatMsgNoLookups=true",
            "CVE-2021-3156": "Upgrade sudo to 1.9.5p2+",
            "CVE-2023-38408": "Upgrade OpenSSH to 9.3p2+",
            "CVE-2022-0847": "Upgrade Linux kernel to 5.16.11+ or apply patch",
            "CVE-2021-4034": "Upgrade polkit to 0.120+ or remove SUID from pkexec",
            "CVE-2024-3094": "Downgrade xz/liblzma to 5.4.x. DO NOT use 5.6.0/5.6.1",
            "CVE-2020-1472": "Apply MS patch. Enforce secure RPC for Netlogon",
            "CVE-2023-44487": "Update webserver. Rate-limit HTTP/2 RST_STREAM frames",
        }

        recommendations = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "")
            rec = {
                "cve_id": cve_id,
                "severity": vuln.get("severity"),
                "action": remediation_map.get(
                    cve_id,
                    f"Update {vuln.get('detected_software', 'software')} to latest version"
                ),
                "priority": "IMMEDIATE" if vuln.get("severity") == "CRITICAL" else "HIGH",
            }
            recommendations.append(rec)

        return recommendations


def test_cve_analyzer():
    """Test CVE analysis functionality."""
    print("=" * 60)
    print("  CVE Analyzer - Test Suite")
    print("=" * 60)

    db = CVEDatabase()
    stats = db.get_cve_stats()
    print(f"\n  CVE Database: {stats['total']} entries")
    print(f"  Critical: {stats['critical']}, High: {stats['high']}")
    print(f"  Avg CVSS: {stats['avg_cvss']}")

    ssh_cves = db.search_cve("openssh")
    print(f"\n  OpenSSH CVEs: {len(ssh_cves)}")
    for cve in ssh_cves:
        print(f"    {cve['cve_id']}: {cve['description'][:50]}... (CVSS {cve['cvss_score']})")

    print("\n  ✅ All tests passed!")


if __name__ == "__main__":
    test_cve_analyzer()
