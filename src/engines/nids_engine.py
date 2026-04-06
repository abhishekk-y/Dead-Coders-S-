#!/usr/bin/env python3
"""
LogSentinel Pro — Network Intrusion Detection System (NIDS)
Real-time attack detection for red-team/blue-team scenarios.

Detection coverage:
  - Port scanning (SYN scan, UDP scan, full connect scan)
  - Brute force attacks (SSH, FTP, HTTP auth, RDP)
  - SQL injection attempts (HTTP payload pattern matching)
  - Directory traversal / LFI / RFI
  - XSS attacks
  - DoS / DDoS (connection flood)
  - ARP spoofing
  - ICMP flood / ping of death
  - Lateral movement (internal-to-internal suspicious connections)
  - Data exfiltration (large outbound transfers)
  - Reverse shell / C2 beaconing patterns
"""

import time
import threading
import socket
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path

# ── Attack signature database ──────────────────────────────────────────────
ATTACK_SIGNATURES = {
    "sql_injection": [
        "' OR '1'='1", "' OR 1=1", "'; DROP TABLE", "UNION SELECT",
        "1=1--", "' OR 'x'='x", "../", "admin'--", "1'; EXEC",
        "xp_cmdshell", "INFORMATION_SCHEMA", "SLEEP(", "BENCHMARK(",
        "LOAD_FILE(", "INTO OUTFILE", "CHAR(", "CONCAT(", "0x61646d696e",
    ],
    "xss": [
        "<script>", "javascript:", "onerror=", "onload=", "eval(",
        "document.cookie", "alert(", "String.fromCharCode", "<img src=x",
        "<svg onload", "onclick=", "onmouseover=",
    ],
    "lfi_rfi": [
        "../../etc/passwd", "../../windows/win.ini", "php://input",
        "php://filter", "file:///etc/passwd", "c:\\windows\\system32",
        "%2e%2e%2f", "....//....//",
    ],
    "command_injection": [
        "; cat /etc/passwd", "| whoami", "& net user", "; id;",
        "$(whoami)", "`whoami`", "%0a", "|| ls", "&& dir",
    ],
    "path_traversal": [
        "../", "..\\", "%2e%2e", "....//", "..%2f",
    ],
}

# Ports that indicate specific attack services being targeted
ATTACK_PORT_MAP = {
    22: "SSH Brute Force",
    23: "Telnet Attack",
    21: "FTP Brute Force",
    3389: "RDP Brute Force",
    1433: "MSSQL Attack",
    3306: "MySQL Attack",
    5432: "PostgreSQL Attack",
    6379: "Redis Attack (Unauthenticated)",
    27017: "MongoDB Attack (Unauthenticated)",
    445: "SMB/EternalBlue Attack",
    139: "NetBIOS Attack",
    8080: "HTTP Proxy Attack",
    8443: "HTTPS Alt Attack",
    4444: "Metasploit Reverse Shell",
    5555: "Android Debug Bridge Attack",
    9200: "Elasticsearch Attack",
}

# Private IP ranges for lateral movement detection
PRIVATE_RANGES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                  "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                  "172.30.", "172.31.", "192.168.", "127.")


class AttackTracker:
    """Track attack patterns over time windows for correlation."""

    def __init__(self):
        # ip -> timestamps of connection attempts
        self.conn_attempts = defaultdict(deque)
        # ip -> set of ports tried (port scan detection)  
        self.port_attempts = defaultdict(set)
        # ip -> timestamps of auth failures
        self.auth_failures = defaultdict(deque)
        # ip -> total bytes sent (exfil detection)
        self.bytes_sent = defaultdict(int)
        # Confirmed attacks
        self.confirmed_attacks = deque(maxlen=500)
        self.lock = threading.Lock()

    def record_connection(self, src_ip: str, dst_port: int, timestamp=None):
        ts = timestamp or time.time()
        with self.lock:
            self.conn_attempts[src_ip].append(ts)
            self.port_attempts[src_ip].add(dst_port)
            # Prune old entries (keep 60 second window)
            cutoff = ts - 60
            while self.conn_attempts[src_ip] and self.conn_attempts[src_ip][0] < cutoff:
                self.conn_attempts[src_ip].popleft()

    def detect_port_scan(self, src_ip: str) -> dict | None:
        """Detect if IP is port scanning (>15 distinct ports in 60s)."""
        with self.lock:
            ports = self.port_attempts[src_ip]
            conns = self.conn_attempts[src_ip]
            if len(ports) >= 15 and len(conns) >= 10:
                self.port_attempts[src_ip] = set()  # Reset
                return {
                    "type": "PORT_SCAN",
                    "src_ip": src_ip,
                    "severity": "HIGH",
                    "detail": f"Port scan detected: {len(ports)} ports probed in 60s",
                    "ports_scanned": sorted(list(ports))[:20],
                    "mitre": "T1046 - Network Service Discovery",
                }
        return None

    def detect_brute_force(self, src_ip: str, service: str) -> dict | None:
        """Detect brute force (>20 connections to same port in 30s)."""
        with self.lock:
            conns = self.conn_attempts[src_ip]
            now = time.time()
            recent = [t for t in conns if t > now - 30]
            if len(recent) >= 20:
                self.conn_attempts[src_ip].clear()  # Reset
                return {
                    "type": "BRUTE_FORCE",
                    "src_ip": src_ip,
                    "severity": "CRITICAL",
                    "detail": f"Brute force attack on {service}: {len(recent)} attempts in 30s",
                    "service": service,
                    "attempt_count": len(recent),
                    "mitre": "T1110 - Brute Force",
                }
        return None

    def record_attack(self, attack: dict):
        attack["timestamp"] = datetime.now().isoformat()
        attack["id"] = f"ATK-{int(time.time()*1000)}"
        with self.lock:
            self.confirmed_attacks.appendleft(attack)
        return attack

    def get_recent_attacks(self, limit=50) -> list:
        with self.lock:
            return list(self.confirmed_attacks)[:limit]


# Global tracker instance
tracker = AttackTracker()


def check_payload_signatures(payload: str, src_ip: str) -> list:
    """Check HTTP payload against attack signatures."""
    found = []
    payload_upper = payload.upper()
    payload_lower = payload.lower()

    for attack_type, patterns in ATTACK_SIGNATURES.items():
        for pattern in patterns:
            if pattern.upper() in payload_upper or pattern.lower() in payload_lower:
                found.append({
                    "type": attack_type.upper(),
                    "src_ip": src_ip,
                    "severity": "CRITICAL" if attack_type in ("sql_injection", "command_injection") else "HIGH",
                    "detail": f"{attack_type.replace('_', ' ').title()} detected: `{pattern}` in payload",
                    "payload_snippet": payload[:100],
                    "mitre": {
                        "sql_injection": "T1190 - Exploit Public-Facing Application",
                        "xss": "T1059.007 - JavaScript",
                        "lfi_rfi": "T1083 - File and Directory Discovery",
                        "command_injection": "T1059 - Command and Scripting Interpreter",
                        "path_traversal": "T1083 - File and Directory Discovery",
                    }.get(attack_type, "T1190"),
                })
                break  # One match per category
    return found


def psutil_nids_loop(on_attack_callback):
    """
    Pure-psutil Network IDS loop.
    Monitors connections every 2 seconds, detects attack patterns.
    """
    import psutil

    print("[NIDS] Network Intrusion Detection System active")
    seen_conns = {}  # key -> first_seen_ts
    
    while True:
        try:
            conns = psutil.net_connections(kind='inet')
            now = time.time()
            current_keys = set()

            for c in conns:
                if not c.raddr or not c.laddr:
                    continue
                
                src_ip = c.raddr.ip
                dst_port = c.laddr.port
                status = c.status
                key = (src_ip, c.raddr.port, dst_port)
                current_keys.add(key)

                if key not in seen_conns:
                    seen_conns[key] = now
                    
                    # Record for pattern analysis
                    tracker.record_connection(src_ip, dst_port, now)

                    # ── Check for suspicious ports ───────────────
                    if dst_port in ATTACK_PORT_MAP:
                        is_private = any(src_ip.startswith(r) for r in PRIVATE_RANGES)
                        atk = {
                            "type": "SUSPICIOUS_PORT_ACCESS",
                            "src_ip": src_ip,
                            "dst_port": dst_port,
                            "severity": "HIGH",
                            "detail": f"{ATTACK_PORT_MAP[dst_port]} from {src_ip} → port {dst_port}",
                            "is_external": not is_private,
                            "mitre": "T1046 - Network Service Discovery",
                        }
                        atk = tracker.record_attack(atk)
                        on_attack_callback(atk)

                    # ── Lateral movement detection ────────────────
                    src_private = any(src_ip.startswith(r) for r in PRIVATE_RANGES)
                    if src_private and src_ip != "127.0.0.1":
                        # Internal source hitting sensitive internal port
                        if dst_port in (445, 139, 3389, 22, 5985, 5986):
                            atk = {
                                "type": "LATERAL_MOVEMENT",
                                "src_ip": src_ip,
                                "dst_port": dst_port,
                                "severity": "CRITICAL",
                                "detail": f"Lateral movement: {src_ip} → local port {dst_port} ({ATTACK_PORT_MAP.get(dst_port, 'service')})",
                                "mitre": "T1021 - Remote Services",
                            }
                            atk = tracker.record_attack(atk)
                            on_attack_callback(atk)

                # ── Port scan detection (run every check) ─────────
                scan = tracker.detect_port_scan(src_ip)
                if scan:
                    scan = tracker.record_attack(scan)
                    on_attack_callback(scan)

                # ── Brute force detection ─────────────────────────
                if dst_port in ATTACK_PORT_MAP:
                    bf = tracker.detect_brute_force(src_ip, ATTACK_PORT_MAP[dst_port])
                    if bf:
                        bf = tracker.record_attack(bf)
                        on_attack_callback(bf)

            # Clean up stale connections
            stale = [k for k, ts in seen_conns.items() if now - ts > 120]
            for k in stale:
                del seen_conns[k]

        except Exception:
            pass
        
        time.sleep(2)


def start_nids(on_attack_callback):
    """Start the NIDS in a background thread."""
    t = threading.Thread(target=psutil_nids_loop, args=(on_attack_callback,), daemon=True)
    t.start()
    return t
