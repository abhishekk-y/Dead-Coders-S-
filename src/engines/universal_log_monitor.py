#!/usr/bin/env python3
"""
Universal Real-Time Log Monitor & Network Intrusion Detection
Monitors system, network, and security events - works on any OS
"""

import os
import json
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Optional
from collections import defaultdict
import socket
import subprocess
from pathlib import Path


class UniversalLogMonitor:
    """Universal log monitoring for all platforms (Windows, Linux, macOS)"""
    
    def __init__(self, update_interval: int = 1):
        self.update_interval = update_interval
        self.is_monitoring = False
        self.monitoring_thread = None
        self.event_callbacks = []
        self.events = []
        self.max_events = 10000
        
    def add_callback(self, callback: Callable):
        """Register callback for new events"""
        self.event_callbacks.append(callback)
    
    def start_monitoring(self):
        """Start universal log monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        print("[+] Universal log monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        print("[+] Log monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Collect various log sources
                self._collect_system_logs()
                self._collect_network_logs()
                self._collect_security_logs()
                self._collect_process_logs()
                
                time.sleep(self.update_interval)
            except Exception as e:
                print(f"[!] Monitoring error: {e}")
    
    def _collect_system_logs(self):
        """Collect system performance logs"""
        try:
            import psutil
            
            event = {
                'timestamp': datetime.now().isoformat(),
                'source': 'system',
                'type': 'performance',
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
            }
            
            # Alert on high resource usage
            if event['cpu_percent'] > 80:
                event['severity'] = 'HIGH'
                event['alert'] = f"High CPU usage: {event['cpu_percent']}%"
            elif event['memory_percent'] > 85:
                event['severity'] = 'HIGH'
                event['alert'] = f"High memory usage: {event['memory_percent']}%"
            else:
                event['severity'] = 'LOW'
            
            self._emit_event(event)
        except:
            pass
    
    def _collect_network_logs(self):
        """Collect network connection logs"""
        try:
            import psutil
            
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'source': 'network',
                        'type': 'connection',
                        'status': conn.status,
                        'local_ip': conn.laddr.ip if conn.laddr else None,
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_ip': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'pid': conn.pid,
                    }
                    
                    # Check for suspicious patterns
                    if event['remote_port'] in [22, 23, 3389, 3306, 5432]:
                        event['severity'] = 'MEDIUM'
                        event['alert'] = f"Connection to sensitive port {event['remote_port']}"
                    else:
                        event['severity'] = 'LOW'
                    
                    self._emit_event(event)
        except:
            pass
    
    def _collect_security_logs(self):
        """Collect security-related logs"""
        try:
            # Implementation varies by OS
            # This is a placeholder for security event collection
            pass
        except:
            pass
    
    def _collect_process_logs(self):
        """Collect process creation/termination logs"""
        try:
            import psutil
            
            current_pids = {p.pid for p in psutil.process_iter()}
            
            if not hasattr(self, '_last_pids'):
                self._last_pids = set()
            
            # New processes
            new_processes = current_pids - self._last_pids
            for pid in new_processes:
                try:
                    p = psutil.Process(pid)
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'source': 'process',
                        'type': 'created',
                        'pid': pid,
                        'name': p.name(),
                        'cmdline': ' '.join(p.cmdline()),
                        'severity': 'LOW'
                    }
                    self._emit_event(event)
                except:
                    pass
            
            self._last_pids = current_pids
        except:
            pass
    
    def _emit_event(self, event: Dict):
        """Emit event to callbacks"""
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)
        
        for callback in self.event_callbacks:
            try:
                callback(event)
            except:
                pass
    
    def get_events(self, limit: int = 100) -> List[Dict]:
        """Get recent events"""
        return self.events[-limit:]
    
    def get_events_by_severity(self, severity: str) -> List[Dict]:
        """Get events by severity"""
        return [e for e in self.events if e.get('severity') == severity]


class NetworkIntrusionDetector:
    """Detects network-based attacks"""
    
    def __init__(self):
        self.detected_attacks = []
        self.ip_reputation = defaultdict(int)
        self.port_scan_tracker = defaultdict(list)
        self.connection_tracker = defaultdict(list)
        
    def analyze_connections(self, connections: List[Dict]) -> List[Dict]:
        """Analyze for intrusion patterns"""
        attacks = []
        
        # Detect port scans
        for conn in connections:
            remote_ip = conn.get('remote_ip')
            remote_port = conn.get('remote_port')
            
            if remote_ip:
                self.port_scan_tracker[remote_ip].append(remote_port)
        
        # Check for port scanning behavior
        for ip, ports in self.port_scan_tracker.items():
            if len(set(ports)) > 10:  # Multiple different ports
                attacks.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'PORT_SCAN',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'ports_scanned': len(set(ports)),
                    'description': f'Possible port scan from {ip}'
                })
                self.ip_reputation[ip] += 5
        
        return attacks
    
    def detect_brute_force(self, failed_logins: List[Dict]) -> List[Dict]:
        """Detect brute force attempts"""
        attacks = []
        ip_attempts = defaultdict(int)
        
        for login in failed_logins:
            ip = login.get('source_ip')
            ip_attempts[ip] += 1
        
        for ip, count in ip_attempts.items():
            if count > 5:  # More than 5 failed attempts
                attacks.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'BRUTE_FORCE',
                    'severity': 'CRITICAL' if count > 20 else 'HIGH',
                    'source_ip': ip,
                    'failed_attempts': count,
                    'description': f'Brute force attack from {ip}'
                })
                self.ip_reputation[ip] += 10
        
        return attacks
    
    def detect_sql_injection(self, requests: List[Dict]) -> List[Dict]:
        """Detect SQL injection patterns"""
        sql_indicators = ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "exec(", "eval("]
        attacks = []
        
        for req in requests:
            payload = req.get('payload', '')
            if any(indicator in payload for indicator in sql_indicators):
                attacks.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'SQL_INJECTION',
                    'severity': 'CRITICAL',
                    'source_ip': req.get('source_ip'),
                    'payload': payload[:100],
                    'description': 'SQL injection attempt detected'
                })
        
        return attacks
    
    def detect_ddos(self, traffic_spike: int, normal_traffic: int) -> Optional[Dict]:
        """Detect DDoS patterns"""
        if traffic_spike > normal_traffic * 10:  # 10x increase
            return {
                'timestamp': datetime.now().isoformat(),
                'type': 'DDOS',
                'severity': 'CRITICAL',
                'traffic_spike': traffic_spike,
                'normal_traffic': normal_traffic,
                'description': f'DDoS attack detected - {traffic_spike}x normal traffic'
            }
        return None


class AttackCorrelator:
    """Correlates multiple attack events to identify coordinated attacks"""
    
    def __init__(self):
        self.event_window = timedelta(minutes=5)
        self.attack_chains = []
    
    def correlate_attacks(self, attacks: List[Dict]) -> List[Dict]:
        """Find correlated attacks"""
        correlated = []
        
        # Group by source IP
        by_source = defaultdict(list)
        for attack in attacks:
            source = attack.get('source_ip')
            if source:
                by_source[source].append(attack)
        
        # Identify attack chains
        for source, source_attacks in by_source.items():
            if len(source_attacks) > 1:
                # Multiple attack types from same source
                attack_types = set(a.get('type') for a in source_attacks)
                if len(attack_types) > 1:
                    correlated.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'COORDINATED_ATTACK',
                        'severity': 'CRITICAL',
                        'source_ip': source,
                        'attack_types': list(attack_types),
                        'attack_count': len(source_attacks),
                        'description': f'Coordinated attack from {source}: {", ".join(attack_types)}'
                    })
        
        self.attack_chains.extend(correlated)
        return correlated
    
    def get_attack_summary(self) -> Dict:
        """Get overall attack summary"""
        return {
            'total_chains': len(self.attack_chains),
            'chains': self.attack_chains[-10:],  # Last 10
        }


# Install required package if needed
def ensure_psutil():
    """Ensure psutil is installed"""
    try:
        import psutil
    except ImportError:
        print("[*] Installing psutil...")
        import subprocess
        subprocess.check_call(['pip', 'install', 'psutil'])


if __name__ == '__main__':
    ensure_psutil()
    
    # Demo
    monitor = UniversalLogMonitor()
    
    def on_event(event):
        if event.get('severity') in ['HIGH', 'CRITICAL']:
            print(f"⚠️  {event['type']}: {event.get('alert', event.get('description', 'Event'))}")
    
    monitor.add_callback(on_event)
    monitor.start_monitoring()
    
    try:
        print("[+] Monitoring logs (press Ctrl+C to stop)...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Stopping...")
        monitor.stop_monitoring()
