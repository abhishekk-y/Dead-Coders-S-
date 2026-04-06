#!/usr/bin/env python3
"""
Live Log Analyzer for LogSentinel Pro v4.0
Real-time log analysis with live streaming capabilities
Integrates with all alert systems: SendGrid, Telegram, and Email
"""

import os
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from collections import defaultdict
from pathlib import Path
import time


class LiveLogAnalyzer:
    """Real-time log analysis engine with live streaming."""
    
    def __init__(self, max_history: int = 1000, update_interval: int = 5):
        """Initialize Live Log Analyzer."""
        self.max_history = max_history
        self.update_interval = update_interval
        self.live_logs = []
        self.analysis_cache = {}
        self.threat_patterns = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.destination_ips = defaultdict(int)
        self.port_activity = defaultdict(int)
        self.severity_counts = defaultdict(int)
        self.alert_callbacks = []
        self.is_monitoring = False
        self.last_analysis = None
        self.analysis_thread = None
    
    def add_alert_callback(self, callback: Callable):
        """Register callback for live alerts."""
        self.alert_callbacks.append(callback)
    
    def ingest_log(self, log_entry: Dict) -> None:
        """Ingest a single log entry for live analysis."""
        
        # Add timestamp if missing
        if 'timestamp' not in log_entry:
            log_entry['timestamp'] = datetime.now().isoformat()
        
        self.live_logs.append(log_entry)
        
        # Maintain max history size
        if len(self.live_logs) > self.max_history:
            self.live_logs.pop(0)
        
        # Update threat patterns
        if 'threat_type' in log_entry:
            self.threat_patterns[log_entry['threat_type']] += 1
        
        if 'source_ip' in log_entry:
            self.source_ips[log_entry['source_ip']] += 1
        
        if 'destination_ip' in log_entry:
            self.destination_ips[log_entry['destination_ip']] += 1
        
        if 'port' in log_entry:
            self.port_activity[log_entry['port']] += 1
        
        if 'severity' in log_entry:
            self.severity_counts[log_entry['severity']] += 1
    
    def ingest_logs_batch(self, logs: List[Dict]) -> None:
        """Ingest multiple log entries."""
        for log in logs:
            self.ingest_log(log)
    
    def get_live_stats(self) -> Dict:
        """Get real-time statistics from live logs."""
        
        total_logs = len(self.live_logs)
        
        # Get time-based stats
        now = datetime.now()
        last_hour = now - timedelta(hours=1)
        last_day = now - timedelta(days=1)
        
        last_hour_logs = [
            log for log in self.live_logs 
            if datetime.fromisoformat(log.get('timestamp', now.isoformat())) > last_hour
        ]
        
        last_day_logs = [
            log for log in self.live_logs 
            if datetime.fromisoformat(log.get('timestamp', now.isoformat())) > last_day
        ]
        
        return {
            'timestamp': now.isoformat(),
            'total_logs_processed': total_logs,
            'logs_last_hour': len(last_hour_logs),
            'logs_last_day': len(last_day_logs),
            'threat_patterns': dict(self.threat_patterns),
            'top_source_ips': self._get_top_items(self.source_ips, 10),
            'top_destination_ips': self._get_top_items(self.destination_ips, 10),
            'port_activity': dict(sorted(self.port_activity.items(), key=lambda x: x[1], reverse=True)[:20]),
            'severity_breakdown': dict(self.severity_counts),
            'alert_rate': self._calculate_alert_rate(),
            'anomaly_score': self._calculate_anomaly_score()
        }
    
    def get_threat_summary(self, hours: int = 24) -> Dict:
        """Get threat analysis summary."""
        
        threshold = datetime.now() - timedelta(hours=hours)
        recent_logs = [
            log for log in self.live_logs
            if datetime.fromisoformat(log.get('timestamp', datetime.now().isoformat())) > threshold
        ]
        
        critical_threats = [log for log in recent_logs if log.get('severity') == 'CRITICAL']
        high_threats = [log for log in recent_logs if log.get('severity') == 'HIGH']
        
        return {
            'period_hours': hours,
            'total_events': len(recent_logs),
            'critical_threats': len(critical_threats),
            'high_threats': len(high_threats),
            'critical_details': critical_threats[:5],
            'top_threat_types': dict(sorted(
                [(k, v) for k, v in self.threat_patterns.items() 
                 if any(log.get('threat_type') == k and 
                        datetime.fromisoformat(log.get('timestamp', datetime.now().isoformat())) > threshold
                        for log in self.live_logs)],
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'generated_at': datetime.now().isoformat()
        }
    
    def detect_live_anomalies(self, sensitivity: float = 0.7) -> List[Dict]:
        """Detect anomalies in real-time."""
        
        anomalies = []
        
        if len(self.live_logs) < 10:
            return anomalies
        
        # Analyze recent activity
        recent_logs = self.live_logs[-50:]  # Last 50 logs
        
        # Check for sudden spikes in threat patterns
        avg_threat_count = sum(self.threat_patterns.values()) / len(self.threat_patterns) if self.threat_patterns else 0
        
        for threat_type, count in self.threat_patterns.items():
            if count > avg_threat_count * (2.0 - sensitivity):
                anomalies.append({
                    'type': 'threat_spike',
                    'threat_type': threat_type,
                    'count': count,
                    'average': avg_threat_count,
                    'spike_level': count / max(avg_threat_count, 1),
                    'timestamp': datetime.now().isoformat()
                })
        
        # Check for port scanning patterns
        high_port_activity = [(port, count) for port, count in self.port_activity.items() 
                              if count > 100]
        
        if len(high_port_activity) > 5:
            anomalies.append({
                'type': 'port_scan_pattern',
                'ports_targeted': len(high_port_activity),
                'timestamp': datetime.now().isoformat()
            })
        
        # Check for DDoS-like patterns
        top_sources = self._get_top_items(self.source_ips, 5)
        for ip, count in top_sources:
            if count > len(recent_logs) * 0.3:  # 30% of recent traffic
                anomalies.append({
                    'type': 'ddos_pattern',
                    'source_ip': ip,
                    'request_count': count,
                    'percentage': (count / len(recent_logs)) * 100,
                    'timestamp': datetime.now().isoformat()
                })
        
        return anomalies
    
    def start_live_monitoring(self, log_file_path: str) -> None:
        """Start real-time log file monitoring."""
        
        if self.is_monitoring:
            print("[!] Already monitoring logs")
            return
        
        self.is_monitoring = True
        self.analysis_thread = threading.Thread(
            target=self._monitor_log_file,
            args=(log_file_path,),
            daemon=True
        )
        self.analysis_thread.start()
        print(f"[+] Live log monitoring started: {log_file_path}")
    
    def stop_live_monitoring(self) -> None:
        """Stop real-time log file monitoring."""
        self.is_monitoring = False
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        print("[+] Live log monitoring stopped")
    
    def _monitor_log_file(self, log_file_path: str) -> None:
        """Monitor log file for changes."""
        
        log_path = Path(log_file_path)
        last_position = 0
        
        while self.is_monitoring:
            try:
                if log_path.exists():
                    current_size = log_path.stat().st_size
                    
                    if current_size >= last_position:
                        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            f.seek(last_position)
                            new_lines = f.readlines()
                            last_position = f.tell()
                            
                            for line in new_lines:
                                try:
                                    if line.strip():
                                        # Try to parse as JSON
                                        try:
                                            log_entry = json.loads(line)
                                        except json.JSONDecodeError:
                                            # Create log entry from string
                                            log_entry = {
                                                'message': line.strip(),
                                                'timestamp': datetime.now().isoformat()
                                            }
                                        
                                        self.ingest_log(log_entry)
                                        
                                        # Trigger callbacks for high-severity alerts
                                        if log_entry.get('severity') in ['CRITICAL', 'HIGH']:
                                            self._trigger_callbacks(log_entry)
                                except Exception as e:
                                    print(f"[!] Error processing log line: {e}")
                
                time.sleep(self.update_interval)
                
            except Exception as e:
                print(f"[!] Error in log monitoring: {e}")
                time.sleep(self.update_interval)
    
    def _trigger_callbacks(self, log_entry: Dict) -> None:
        """Trigger registered callbacks."""
        for callback in self.alert_callbacks:
            try:
                callback(log_entry)
            except Exception as e:
                print(f"[!] Error in callback: {e}")
    
    def _get_top_items(self, counter_dict: Dict, limit: int = 10) -> List[tuple]:
        """Get top items from counter dictionary."""
        return sorted(counter_dict.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def _calculate_alert_rate(self) -> float:
        """Calculate alert rate per minute."""
        if len(self.live_logs) < 2:
            return 0.0
        
        first_log_time = datetime.fromisoformat(self.live_logs[0].get('timestamp', datetime.now().isoformat()))
        last_log_time = datetime.fromisoformat(self.live_logs[-1].get('timestamp', datetime.now().isoformat()))
        
        time_diff = (last_log_time - first_log_time).total_seconds() / 60
        
        if time_diff == 0:
            return 0.0
        
        alert_count = sum(1 for log in self.live_logs if log.get('severity') in ['CRITICAL', 'HIGH'])
        return alert_count / time_diff
    
    def _calculate_anomaly_score(self) -> float:
        """Calculate overall anomaly score (0-100)."""
        
        if not self.live_logs:
            return 0.0
        
        score = 0.0
        
        # Severity distribution (0-30 points)
        critical_pct = (self.severity_counts.get('CRITICAL', 0) / len(self.live_logs)) * 100
        score += min(critical_pct * 0.3, 30)
        
        # Threat diversity (0-20 points)
        threat_diversity = min(len(self.threat_patterns) / 10, 20)
        score += threat_diversity
        
        # Source IP concentration (0-25 points)
        if self.source_ips:
            top_ip_ratio = self._get_top_items(self.source_ips, 1)[0][1] / len(self.live_logs)
            score += top_ip_ratio * 25
        
        # Port activity concentration (0-25 points)
        if self.port_activity:
            top_port_ratio = self._get_top_items(self.port_activity, 1)[0][1] / len(self.live_logs)
            score += top_port_ratio * 25
        
        return min(score, 100.0)
    
    def get_detailed_report(self) -> Dict:
        """Generate detailed real-time analysis report."""
        
        stats = self.get_live_stats()
        threats = self.get_threat_summary()
        anomalies = self.detect_live_anomalies()
        
        return {
            'report_id': f"LIVE_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'statistics': stats,
            'threat_analysis': threats,
            'detected_anomalies': anomalies,
            'anomaly_count': len(anomalies),
            'requires_attention': len(anomalies) > 0 or stats.get('anomaly_score', 0) > 70
        }
    
    def export_logs(self, output_path: str) -> str:
        """Export live logs to JSON file."""
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        export_data = {
            'exported_at': datetime.now().isoformat(),
            'total_logs': len(self.live_logs),
            'logs': self.live_logs,
            'statistics': self.get_live_stats(),
            'threat_summary': self.get_threat_summary()
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"[+] Logs exported to: {output_file}")
        return str(output_file)
    
    def clear_history(self) -> None:
        """Clear all live log history."""
        self.live_logs.clear()
        self.threat_patterns.clear()
        self.source_ips.clear()
        self.destination_ips.clear()
        self.port_activity.clear()
        self.severity_counts.clear()
        print("[+] Live log history cleared")
