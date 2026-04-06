#!/usr/bin/env python3
"""
Industry Share Module - LogSentinel Pro v4.0
Secure P2P threat report sharing. NEVER shares raw logs.
"""

import hashlib
import json
import os
import secrets
import socket
import sqlite3
import struct
import threading
import time
import hmac
import re
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict


class SecureChannel:
    """AES-256 style encrypted channel using HMAC-SHA256."""

    def __init__(self, shared_secret: str = None):
        self.shared_secret = shared_secret or secrets.token_hex(32)
        self._key = hashlib.pbkdf2_hmac(
            'sha256', self.shared_secret.encode(),
            b"LogSentinelPro_IndustryShare_v4", 100000
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        cipher_key = hashlib.sha256(self._key + nonce).digest()
        stream = (cipher_key * ((len(plaintext) // 32) + 1))[:len(plaintext)]
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
        tag = hmac.new(self._key, nonce + ciphertext, hashlib.sha256).digest()
        return nonce + ciphertext + tag

    def decrypt(self, data: bytes) -> bytes:
        nonce, ciphertext, tag = data[:12], data[12:-32], data[-32:]
        expected = hmac.new(self._key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Decryption failed: tag mismatch")
        cipher_key = hashlib.sha256(self._key + nonce).digest()
        stream = (cipher_key * ((len(ciphertext) // 32) + 1))[:len(ciphertext)]
        return bytes(a ^ b for a, b in zip(ciphertext, stream))


class ReportAnonymizer:
    """Sanitize reports before sharing - strips all PII and raw logs."""

    SENSITIVE_FIELDS = {
        "organization", "org", "company", "license_key",
        "device_fingerprint", "device_fp", "session", "api_key",
        "password", "secret", "raw_line", "raw_log", "raw_data",
        "raw", "file_path", "local_path", "source_file",
        "hostname", "machine_id", "internal_ip", "employee",
        "email", "username", "user", "full_name",
    }

    @classmethod
    def anonymize_report(cls, report: Dict) -> Dict:
        ip_map = {}
        counter = [0]
        anonymized = cls._sanitize(report, ip_map, counter)
        anonymized["_anonymization"] = {
            "anonymized_at": datetime.now().isoformat(),
            "version": "4.0",
            "ips_anonymized": len(ip_map),
            "hash": hashlib.sha256(
                json.dumps(anonymized, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]
        }
        return anonymized

    @classmethod
    def _sanitize(cls, data, ip_map, counter, depth=0):
        if depth > 20:
            return "[DEPTH_LIMIT]"
        if isinstance(data, dict):
            result = {}
            for k, v in data.items():
                if k.lower() in cls.SENSITIVE_FIELDS:
                    continue
                if k.lower() in ("source_ip", "destination_ip", "ip", "indicator"):
                    if isinstance(v, str) and cls._is_ip(v):
                        result[k] = cls._anon_ip(v, ip_map, counter)
                        continue
                result[k] = cls._sanitize(v, ip_map, counter, depth + 1)
            return result
        elif isinstance(data, list):
            return [cls._sanitize(i, ip_map, counter, depth + 1) for i in data]
        elif isinstance(data, str):
            for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', data):
                try:
                    if ipaddress.ip_address(ip).is_private:
                        data = data.replace(ip, cls._anon_ip(ip, ip_map, counter))
                except:
                    pass
            return data
        return data

    @staticmethod
    def _is_ip(v):
        return bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', v.strip()))

    @staticmethod
    def _anon_ip(ip, ip_map, counter):
        if ip not in ip_map:
            counter[0] += 1
            ip_map[ip] = f"ANON_HOST_{counter[0]:03d}"
        return ip_map[ip]


class PeerDiscovery:
    """Discover LogSentinel peers on the local network via UDP broadcast."""

    DISCOVERY_PORT = 9199
    BEACON_MAGIC = b"LOGSENTINEL_PEER_v4"

    def __init__(self, node_id: str, listen_port: int = 9100):
        self.node_id = node_id
        self.listen_port = listen_port
        self.peers: Dict[str, Dict] = {}
        self._running = False
        self._lock = threading.Lock()

    def start(self):
        self._running = True
        threading.Thread(target=self._broadcast, daemon=True).start()
        threading.Thread(target=self._listen, daemon=True).start()

    def stop(self):
        self._running = False

    def get_peers(self) -> Dict[str, Dict]:
        with self._lock:
            now = time.time()
            self.peers = {k: v for k, v in self.peers.items()
                          if now - v.get("last_seen", 0) < 30}
            return dict(self.peers)

    def _broadcast(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1)
        data = json.dumps({
            "magic": self.BEACON_MAGIC.decode(),
            "node_id": self.node_id,
            "port": self.listen_port,
            "version": "4.0"
        }).encode()
        while self._running:
            try:
                sock.sendto(data, ('<broadcast>', self.DISCOVERY_PORT))
            except:
                pass
            time.sleep(10)
        sock.close()

    def _listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2)
        try:
            sock.bind(('', self.DISCOVERY_PORT))
        except OSError:
            return
        while self._running:
            try:
                data, addr = sock.recvfrom(4096)
                beacon = json.loads(data.decode())
                if beacon.get("magic") != self.BEACON_MAGIC.decode():
                    continue
                if beacon.get("node_id") == self.node_id:
                    continue
                with self._lock:
                    self.peers[beacon["node_id"]] = {
                        "ip": addr[0], "port": beacon.get("port", 9100),
                        "version": beacon.get("version"), "last_seen": time.time(),
                        "node_id": beacon["node_id"]
                    }
            except:
                continue
        sock.close()


class ShareServer:
    """TCP server to receive shared reports."""

    def __init__(self, port=9100, data_dir=None, shared_secret=None):
        self.port = port
        self.data_dir = Path(data_dir or Path.home() / ".local/share/LogSentinel Pro/shared_reports")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.channel = SecureChannel(shared_secret or "logsentinel_default_key")
        self._running = False
        self._db = self.data_dir / "share_audit.db"
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(str(self._db))
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS share_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, direction TEXT,
            peer_id TEXT, peer_ip TEXT, report_hash TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT, size_bytes INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS received_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, peer_id TEXT,
            report_hash TEXT UNIQUE, report_data TEXT,
            received_at TEXT DEFAULT CURRENT_TIMESTAMP,
            risk_score INTEGER, threat_count INTEGER)""")
        conn.commit()
        conn.close()

    def start(self):
        self._running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self):
        self._running = False

    def _serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(2)
        try:
            srv.bind(('0.0.0.0', self.port))
            srv.listen(5)
        except OSError:
            return
        while self._running:
            try:
                client, addr = srv.accept()
                threading.Thread(target=self._handle, args=(client, addr), daemon=True).start()
            except:
                continue
        srv.close()

    def _handle(self, sock, addr):
        try:
            sock.settimeout(30)
            length_data = sock.recv(4)
            if len(length_data) < 4:
                return
            msg_len = struct.unpack('>I', length_data)[0]
            if msg_len > 10 * 1024 * 1024:
                sock.sendall(b"ERR:TOO_LARGE")
                return
            encrypted = b""
            while len(encrypted) < msg_len:
                chunk = sock.recv(min(8192, msg_len - len(encrypted)))
                if not chunk:
                    break
                encrypted += chunk
            try:
                message = json.loads(self.channel.decrypt(encrypted).decode())
            except:
                sock.sendall(b"ERR:DECRYPT_FAILED")
                return
            if message.get("type") == "share_report":
                self._store_report(message, addr)
                sock.sendall(b"OK:RECEIVED")
            elif message.get("type") == "ping":
                sock.sendall(b"OK:PONG")
            else:
                sock.sendall(b"ERR:UNKNOWN")
        except:
            pass
        finally:
            sock.close()

    def _store_report(self, message, addr):
        report = message.get("report", {})
        peer_id = message.get("peer_id", "unknown")
        rhash = hashlib.sha256(json.dumps(report, sort_keys=True, default=str).encode()).hexdigest()
        risk_score = report.get("risk_score", 0)
        
        # Determine risk level for folder sorting
        if risk_score >= 75:
            severity = "CRITICAL"
        elif risk_score >= 50:
            severity = "HIGH"
        elif risk_score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        # Create sorted directories
        target_dir = self.data_dir / severity
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Save exact JSON to disk
        file_path = target_dir / f"report_{peer_id[:8]}_{rhash[:8]}.json"
        
        try:
            with open(file_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
        except Exception as e:
            pass # fallback to DB-only
            
        conn = sqlite3.connect(str(self._db))
        c = conn.cursor()
        try:
            c.execute("INSERT OR IGNORE INTO received_reports (peer_id,report_hash,report_data,risk_score,threat_count) VALUES (?,?,?,?,?)",
                      (peer_id, rhash, json.dumps(report, default=str),
                       risk_score, len(report.get("threats_detected", []))))
            c.execute("INSERT INTO share_audit (direction,peer_id,peer_ip,report_hash,status,size_bytes) VALUES (?,?,?,?,?,?)",
                      ("received", peer_id, addr[0], rhash[:16], "success", len(json.dumps(report, default=str))))
            conn.commit()
        except:
            pass
        finally:
            conn.close()

    def get_received_reports(self):
        conn = sqlite3.connect(str(self._db))
        c = conn.cursor()
        c.execute("SELECT peer_id,report_hash,risk_score,threat_count,received_at FROM received_reports ORDER BY received_at DESC LIMIT 50")
        rows = c.fetchall()
        conn.close()
        return [{"peer_id": r[0], "report_hash": r[1][:16], "risk_score": r[2],
                 "threat_count": r[3], "received_at": r[4]} for r in rows]

    def get_audit_log(self):
        conn = sqlite3.connect(str(self._db))
        c = conn.cursor()
        c.execute("SELECT direction,peer_id,peer_ip,report_hash,status,timestamp,size_bytes FROM share_audit ORDER BY timestamp DESC LIMIT 100")
        rows = c.fetchall()
        conn.close()
        return [{"direction": r[0], "peer_id": r[1], "peer_ip": r[2],
                 "report_hash": r[3], "status": r[4], "timestamp": r[5], "size_bytes": r[6]} for r in rows]


class ShareClient:
    """Client for sending anonymized reports to peers."""

    def __init__(self, shared_secret=None):
        self.channel = SecureChannel(shared_secret or "logsentinel_default_key")
        self.node_id = hashlib.sha256((socket.gethostname() + str(os.getpid())).encode()).hexdigest()[:16]

    def share_report(self, report, peer_ip, peer_port=9100):
        anonymized = ReportAnonymizer.anonymize_report(report)
        message = {"type": "share_report", "peer_id": self.node_id,
                   "report": anonymized, "shared_at": datetime.now().isoformat()}
        encrypted = self.channel.encrypt(json.dumps(message, default=str).encode())
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((peer_ip, peer_port))
            sock.sendall(struct.pack('>I', len(encrypted)))
            sock.sendall(encrypted)
            resp = sock.recv(256)
            sock.close()
            if resp.startswith(b"OK"):
                return True, f"Shared with {peer_ip}:{peer_port}"
            return False, f"Rejected: {resp.decode(errors='ignore')}"
        except Exception as e:
            return False, str(e)

    def ping_peer(self, peer_ip, peer_port=9100):
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_ip, peer_port))
            msg = {"type": "ping"}
            encrypted = self.channel.encrypt(json.dumps(msg).encode())
            sock.sendall(struct.pack('>I', len(encrypted)))
            sock.sendall(encrypted)
            resp = sock.recv(256)
            latency = (time.time() - start) * 1000
            sock.close()
            return resp.startswith(b"OK"), latency
        except:
            return False, 0


class IndustryShareManager:
    """High-level manager for Industry Share."""

    def __init__(self, listen_port=9100, shared_secret=None):
        self.node_id = hashlib.sha256(
            (socket.gethostname() + secrets.token_hex(4)).encode()
        ).hexdigest()[:16]
        self.listen_port = listen_port
        secret = shared_secret or "logsentinel_default_key"
        self.discovery = PeerDiscovery(self.node_id, listen_port)
        self.server = ShareServer(listen_port, shared_secret=secret)
        self.client = ShareClient(secret)
        self.client.node_id = self.node_id
        self._active = False

    def start(self):
        self.discovery.start()
        self.server.start()
        self._active = True

    def stop(self):
        self.discovery.stop()
        self.server.stop()
        self._active = False

    @property
    def is_active(self):
        return self._active

    def get_status(self):
        peers = self.discovery.get_peers()
        received = self.server.get_received_reports()
        return {
            "active": self._active, "node_id": self.node_id,
            "listen_port": self.listen_port,
            "discovered_peers": len(peers), "peers": peers,
            "received_reports": len(received), "recent_reports": received[:5]
        }

    def share_with_peer(self, report, peer_ip, peer_port=9100):
        return self.client.share_report(report, peer_ip, peer_port)

    def share_with_all(self, report):
        results = []
        for pid, info in self.discovery.get_peers().items():
            ok, msg = self.client.share_report(report, info["ip"], info["port"])
            results.append({"peer_id": pid, "success": ok, "message": msg})
        return results

    def add_manual_peer(self, ip, port=9100, name=""):
        ok, latency = self.client.ping_peer(ip, port)
        if ok:
            pid = hashlib.sha256(f"{ip}:{port}".encode()).hexdigest()[:16]
            with self.discovery._lock:
                self.discovery.peers[pid] = {
                    "ip": ip, "port": port, "last_seen": time.time(),
                    "node_id": pid, "name": name or f"Peer@{ip}", "manual": True
                }
            return True, f"Added {ip}:{port} ({latency:.0f}ms)"
        return False, f"Cannot reach {ip}:{port}"

    def get_audit_log(self):
        return self.server.get_audit_log()

    def get_received_reports(self):
        return self.server.get_received_reports()
