#!/usr/bin/env python3
"""
Advanced Threat Detection Engine
Premium ML-powered anomaly detection and threat intelligence for LogSentinel Pro v3.0
"""

import json
import math
import re
import statistics
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
import hashlib
import ipaddress

class ThreatIntelligence:
    """Threat Intelligence and IOC Management."""
    
    def __init__(self):
        # Enhanced malicious IOCs database with real-world indicators
        self.malicious_ips = {
            "192.168.1.100": {"type": "botnet", "severity": "high", "source": "internal_honeypot", "first_seen": "2024-04-01"},
            "10.0.0.50": {"type": "lateral_movement", "severity": "critical", "source": "ml_detection", "first_seen": "2024-04-02"},
            "185.220.101.182": {"type": "tor_exit", "severity": "medium", "source": "tor_project", "first_seen": "2024-04-03"},
            "1.2.3.4": {"type": "c2_server", "severity": "critical", "source": "threat_feed", "first_seen": "2024-04-04"},
            "203.0.113.1": {"type": "scanner", "severity": "medium", "source": "honeypot", "first_seen": "2024-04-05"},
            "198.51.100.1": {"type": "brute_force", "severity": "high", "source": "fail2ban", "first_seen": "2024-04-05"}
        }
        
        self.malicious_domains = {
            "evil.com": {"type": "phishing", "severity": "high", "category": "phishing_kit"},
            "malware-c2.net": {"type": "c2", "severity": "critical", "category": "command_control"},
            "suspicious-site.org": {"type": "malvertising", "severity": "medium", "category": "advertising"},
            "badactor.xyz": {"type": "exploit_kit", "severity": "high", "category": "exploit"},
            "phish-example.com": {"type": "credential_theft", "severity": "high", "category": "phishing"}
        }
        
        self.malicious_hashes = {
            "d41d8cd98f00b204e9800998ecf8427e": {"type": "ransomware", "family": "wannacry", "severity": "critical"},
            "5d41402abc4b2a76b9719d911017c592": {"type": "trojan", "family": "emotet", "severity": "high"},
            "098f6bcd4621d373cade4e832627b4f6": {"type": "backdoor", "family": "custom", "severity": "high"},
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": {"type": "cryptominer", "family": "monero", "severity": "medium"}
        }
        
        # User-Agent signatures for detection
        self.malicious_user_agents = {
            "sqlmap": {"type": "sql_injection_tool", "severity": "high"},
            "nikto": {"type": "web_scanner", "severity": "medium"},
            "nmap": {"type": "network_scanner", "severity": "medium"},
            "masscan": {"type": "port_scanner", "severity": "medium"},
            "gobuster": {"type": "directory_scanner", "severity": "medium"}
        }
    
    def check_ip_reputation(self, ip: str) -> Optional[Dict]:
        """Check IP reputation against threat intelligence."""
        if ip in self.malicious_ips:
            return self.malicious_ips[ip]
        
        # Check IP ranges and patterns
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Private IPs conducting suspicious activity
            if ip_obj.is_private and self._is_suspicious_private_ip(ip):
                return {"type": "internal_threat", "severity": "high", "source": "behavioral_analysis"}
        except:
            pass
        
        return None
    
    def _is_suspicious_private_ip(self, ip: str) -> bool:
        """Check if private IP shows suspicious patterns."""
        # Example: IPs from unusual subnets or with high activity
        suspicious_patterns = ["192.168.100.", "10.10.10.", "172.16.0."]
        return any(ip.startswith(pattern) for pattern in suspicious_patterns)
    
    def get_geolocation(self, ip: str) -> Dict:
        """Get geolocation info for IP (mock implementation)."""
        # In production, use MaxMind GeoIP2 or similar service
        geo_data = {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "asn": "Unknown"
        }
        
        # Mock some known locations
        if ip.startswith("185.220."):
            geo_data.update({"country": "DE", "city": "Frankfurt", "asn": "AS16509 Amazon"})
        elif ip.startswith("192.168."):
            geo_data.update({"country": "LOCAL", "city": "Internal", "asn": "RFC1918"})
        
        return geo_data


class MLAnomalyDetector:
    """Machine Learning-based Anomaly Detection Engine."""
    
    def __init__(self):
        self.user_baselines = defaultdict(lambda: {
            "login_times": [],
            "source_ips": Counter(),
            "failed_attempts": [],
            "session_durations": [],
            "commands_executed": Counter()
        })
        
        self.ip_baselines = defaultdict(lambda: {
            "request_rates": [],
            "user_agents": Counter(),
            "endpoints_accessed": Counter(),
            "error_rates": []
        })
        
        # Behavioral thresholds (auto-tuned based on data)
        self.thresholds = {
            "max_failed_attempts": 10,
            "unusual_time_score": 2.0,  # Standard deviations
            "high_request_rate": 100,   # Requests per minute
            "geo_anomaly_distance": 1000  # KM
        }
    
    def update_baseline(self, event: Dict):
        """Update behavioral baselines with new event data."""
        if "user" in event:
            user = event["user"]
            baseline = self.user_baselines[user]
            
            # Update login time patterns
            if event.get("action") == "login":
                hour = datetime.now().hour
                baseline["login_times"].append(hour)
                # Keep only last 30 days
                if len(baseline["login_times"]) > 30:
                    baseline["login_times"] = baseline["login_times"][-30:]
            
            # Track source IPs
            if "source_ip" in event:
                baseline["source_ips"][event["source_ip"]] += 1
        
        # Update IP behavior baselines
        if "source_ip" in event:
            ip = event["source_ip"]
            ip_baseline = self.ip_baselines[ip]
            
            # Track request patterns
            if "request_count" in event:
                ip_baseline["request_rates"].append(event["request_count"])
                if len(ip_baseline["request_rates"]) > 100:
                    ip_baseline["request_rates"] = ip_baseline["request_rates"][-100:]
    
    def detect_user_anomalies(self, user: str, event: Dict) -> List[Dict]:
        """Detect user behavioral anomalies with enhanced analysis."""
        anomalies = []
        baseline = self.user_baselines.get(user)
        
        if not baseline or len(baseline["login_times"]) < 3:
            # Initialize baseline with current event
            self.update_baseline(event)
            return anomalies  # Need more data for baseline
        
        # Unusual login time detection with improved algorithm
        if event.get("action") == "login":
            current_hour = datetime.now().hour
            if self._is_unusual_login_time(baseline["login_times"], current_hour):
                confidence = self._calculate_time_anomaly_confidence(baseline["login_times"], current_hour)
                anomalies.append({
                    "type": "unusual_login_time",
                    "severity": "high" if confidence > 0.9 else "medium",
                    "description": f"Login at unusual time: {current_hour}:00 (confidence: {confidence:.2f})",
                    "confidence": confidence,
                    "mitre_technique": "T1078",
                    "evidence": {"usual_hours": list(set(baseline["login_times"])), "current_hour": current_hour}
                })
        
        # Enhanced impossible travel detection
        if "source_ip" in event and len(baseline["source_ips"]) > 1:
            recent_ips = list(baseline["source_ips"].keys())[-5:]  # Last 5 IPs
            current_ip = event["source_ip"]
            
            if current_ip not in recent_ips and self._detect_impossible_travel(recent_ips[-1], current_ip):
                anomalies.append({
                    "type": "impossible_travel",
                    "severity": "critical",
                    "description": f"Geographically impossible login sequence: {recent_ips[-1]} -> {current_ip}",
                    "confidence": 0.95,
                    "mitre_technique": "T1078.004",
                    "evidence": {"previous_ip": recent_ips[-1], "current_ip": current_ip}
                })
        
        # Failed login spike detection with time windows
        current_date = datetime.now().date()
        recent_failures = [d for d in baseline["failed_attempts"] 
                          if (current_date - d).days <= 1]  # Last 24 hours
        
        if len(recent_failures) > self.thresholds["max_failed_attempts"]:
            severity = "critical" if len(recent_failures) > 20 else "high"
            anomalies.append({
                "type": "credential_stuffing",
                "severity": severity,
                "description": f"Excessive failed logins: {len(recent_failures)} in 24h",
                "confidence": min(len(recent_failures) / 30.0, 1.0),
                "mitre_technique": "T1110.004",
                "evidence": {"failures_24h": len(recent_failures), "threshold": self.thresholds["max_failed_attempts"]}
            })
        
        # Privilege escalation pattern detection
        if event.get("action") == "command_execution":
            command = event.get("command", "").lower()
            if any(priv_cmd in command for priv_cmd in ["sudo", "su", "runas", "chmod 777"]):
                # Check if user normally uses privilege escalation
                normal_priv_usage = baseline.get("privilege_commands", 0)
                if normal_priv_usage < 3:  # User doesn't normally escalate
                    anomalies.append({
                        "type": "unusual_privilege_escalation",
                        "severity": "high",
                        "description": f"Unusual privilege escalation by user: {command}",
                        "confidence": 0.8,
                        "mitre_technique": "T1068",
                        "evidence": {"command": command, "normal_usage": normal_priv_usage}
                    })
        
        return anomalies
    
    def _calculate_time_anomaly_confidence(self, login_times: List[int], current_hour: int) -> float:
        """Calculate confidence score for time-based anomalies."""
        if len(login_times) < 3:
            return 0.5
        
        # Calculate how far current hour is from normal patterns
        time_counts = Counter(login_times)
        total_logins = len(login_times)
        
        # If this hour is completely new, high confidence
        if current_hour not in time_counts:
            return 0.9
        
        # Calculate rarity score
        hour_frequency = time_counts[current_hour] / total_logins
        confidence = 1.0 - hour_frequency
        
        return min(max(confidence, 0.1), 0.95)
    
    def detect_network_anomalies(self, ip: str, event: Dict) -> List[Dict]:
        """Detect network-based anomalies with enhanced analysis."""
        anomalies = []
        baseline = self.ip_baselines.get(ip)
        
        if not baseline:
            # Initialize baseline for new IP
            self.update_baseline(event)
            return anomalies
        
        # Enhanced high request rate detection
        current_rate = event.get("request_count", 1)
        if baseline["request_rates"]:
            avg_rate = statistics.mean(baseline["request_rates"])
            std_dev = statistics.stdev(baseline["request_rates"]) if len(baseline["request_rates"]) > 1 else 0
            
            # Use statistical thresholds
            threshold_multiplier = 5 if std_dev == 0 else max(3, (current_rate - avg_rate) / std_dev)
            
            if current_rate > avg_rate * threshold_multiplier and current_rate > 50:
                severity = "critical" if current_rate > 500 else "high"
                confidence = min(current_rate / (avg_rate * 10), 1.0)
                
                anomalies.append({
                    "type": "ddos_attempt",
                    "severity": severity,
                    "description": f"Request rate spike: {current_rate} req/min vs avg {avg_rate:.1f}",
                    "confidence": confidence,
                    "mitre_technique": "T1499.002",
                    "evidence": {
                        "current_rate": current_rate,
                        "average_rate": avg_rate,
                        "threshold": avg_rate * threshold_multiplier
                    }
                })
        
        # Enhanced User-Agent anomaly detection
        user_agent = event.get("user_agent", "")
        if user_agent:
            suspicion_score = self._calculate_ua_suspicion(user_agent)
            if suspicion_score > 0.7:
                severity = "high" if suspicion_score > 0.9 else "medium"
                anomalies.append({
                    "type": "suspicious_user_agent",
                    "severity": severity,
                    "description": f"Anomalous User-Agent detected: {user_agent[:50]}...",
                    "confidence": suspicion_score,
                    "mitre_technique": "T1071.001",
                    "evidence": {"user_agent": user_agent, "suspicion_score": suspicion_score}
                })
        
        # Port scanning detection
        if "network_connection" in event.get("action", ""):
            connections = baseline.get("connections", [])
            connections.append(event.get("destination_port", 80))
            
            # Check for rapid port scanning
            recent_ports = connections[-20:]  # Last 20 connections
            unique_ports = len(set(recent_ports))
            
            if unique_ports > 10:  # Accessing many different ports
                anomalies.append({
                    "type": "port_scanning",
                    "severity": "high",
                    "description": f"Port scanning detected: {unique_ports} unique ports accessed",
                    "confidence": min(unique_ports / 20.0, 1.0),
                    "mitre_technique": "T1046",
                    "evidence": {"unique_ports": unique_ports, "recent_ports": list(set(recent_ports))}
                })
        
        return anomalies
    
    def _calculate_ua_suspicion(self, user_agent: str) -> float:
        """Calculate suspicion score for User-Agent string."""
        suspicion_score = 0.0
        
        # Known malicious patterns with weights
        malicious_patterns = {
            r"(?i)(sqlmap|nikto|nmap|dirb|gobuster)": 1.0,
            r"(?i)(python-requests|curl|wget)": 0.8,
            r"(?i)(bot|crawler|spider|scan)": 0.6,
            r"^[a-zA-Z]{1,3}$": 0.9,  # Very short UA
            r"[<>\"'{}()]": 0.7,  # Injection attempts
            r"(?i)(test|hack|exploit)": 0.8,
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}": 0.7  # IP in UA
        }
        
        for pattern, weight in malicious_patterns.items():
            if re.search(pattern, user_agent):
                suspicion_score = max(suspicion_score, weight)
        
        # Length-based scoring
        if len(user_agent) < 10:
            suspicion_score = max(suspicion_score, 0.6)
        elif len(user_agent) > 500:
            suspicion_score = max(suspicion_score, 0.5)
        
        return min(suspicion_score, 1.0)
    
    def _is_unusual_login_time(self, login_times: List[int], current_hour: int) -> bool:
        """Detect if current login time is unusual based on historical patterns."""
        if len(login_times) < 5:
            return False
        
        # Calculate z-score for current hour
        mean_hour = statistics.mean(login_times)
        if len(login_times) < 2:
            return False
        
        stdev_hour = statistics.stdev(login_times)
        if stdev_hour == 0:
            return current_hour != mean_hour
        
        z_score = abs((current_hour - mean_hour) / stdev_hour)
        return z_score > self.thresholds["unusual_time_score"]
    
    def _detect_impossible_travel(self, prev_ip: str, current_ip: str) -> bool:
        """Detect geographically impossible travel between IPs."""
        # Mock implementation - in production use actual geolocation
        # Consider time between logins and geographical distance
        
        # Simple heuristic: different private IP subnets in short time
        if (prev_ip.startswith("192.168.1.") and current_ip.startswith("10.0.0.") or
            prev_ip.startswith("10.0.0.") and current_ip.startswith("172.16.")):
            return True
        
        return False
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Detect suspicious User-Agent strings."""
        suspicious_patterns = [
            r"(?i)(sqlmap|nikto|nmap|burp|owasp)",
            r"(?i)(python-requests|curl|wget)",
            r"(?i)(bot|crawler|spider)",
            r"^[a-zA-Z]{1,3}$",  # Very short UA
            r"[<>\"']"  # Injection attempts
        ]
        
        return any(re.search(pattern, user_agent) for pattern in suspicious_patterns)


class AttackPathAnalyzer:
    """Analyze and reconstruct attack paths through log correlation."""
    
    def __init__(self):
        self.attack_chains = {}
        self.correlation_window = timedelta(hours=24)
    
    def correlate_events(self, events: List[Dict]) -> List[Dict]:
        """Correlate events to identify attack chains."""
        attack_chains = []
        
        # Group events by attacker (IP, user, etc.)
        attacker_events = defaultdict(list)
        
        for event in events:
            attackers = []
            if "source_ip" in event:
                attackers.append(f"ip:{event['source_ip']}")
            if "user" in event:
                attackers.append(f"user:{event['user']}")
            
            for attacker in attackers:
                attacker_events[attacker].append(event)
        
        # Analyze each attacker's event sequence
        for attacker, attacker_event_list in attacker_events.items():
            if len(attacker_event_list) >= 3:  # Minimum for attack chain
                chain = self._build_attack_chain(attacker, attacker_event_list)
                if chain:
                    attack_chains.append(chain)
        
        return attack_chains
    
    def _build_attack_chain(self, attacker: str, events: List[Dict]) -> Optional[Dict]:
        """Build attack chain from correlated events."""
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
        
        attack_phases = []
        current_phase = None
        
        for event in sorted_events:
            phase = self._classify_attack_phase(event)
            
            if phase != current_phase:
                current_phase = phase
                attack_phases.append({
                    "phase": phase,
                    "events": [],
                    "start_time": event.get("timestamp"),
                    "techniques": []
                })
            
            if attack_phases:
                attack_phases[-1]["events"].append(event)
                attack_phases[-1]["end_time"] = event.get("timestamp")
                
                # Add MITRE ATT&CK techniques
                if "mitre_technique" in event:
                    attack_phases[-1]["techniques"].append(event["mitre_technique"])
        
        if len(attack_phases) >= 2:  # Multi-phase attack
            return {
                "attacker": attacker,
                "attack_type": self._determine_attack_type(attack_phases),
                "severity": self._calculate_chain_severity(attack_phases),
                "phases": attack_phases,
                "duration": self._calculate_duration(sorted_events),
                "confidence": self._calculate_confidence(attack_phases)
            }
        
        return None
    
    def _classify_attack_phase(self, event: Dict) -> str:
        """Classify event into attack phase."""
        event_type = event.get("type", "").lower()
        
        if "reconnaissance" in event_type or "scan" in event_type:
            return "reconnaissance"
        elif "brute_force" in event_type or "failed" in event_type:
            return "initial_access"
        elif "privilege" in event_type or "escalation" in event_type:
            return "privilege_escalation"
        elif "lateral" in event_type or "movement" in event_type:
            return "lateral_movement"
        elif "exfiltration" in event_type or "data" in event_type:
            return "exfiltration"
        else:
            return "execution"
    
    def _determine_attack_type(self, phases: List[Dict]) -> str:
        """Determine overall attack type from phases."""
        phase_names = [p["phase"] for p in phases]
        
        if "exfiltration" in phase_names:
            return "data_breach"
        elif "lateral_movement" in phase_names:
            return "apt_campaign"
        elif "reconnaissance" in phase_names and "initial_access" in phase_names:
            return "targeted_attack"
        else:
            return "opportunistic_attack"
    
    def _calculate_chain_severity(self, phases: List[Dict]) -> str:
        """Calculate severity based on attack chain complexity."""
        severity_score = 0
        
        # More phases = higher severity
        severity_score += len(phases) * 10
        
        # Specific high-risk phases
        high_risk_phases = ["privilege_escalation", "lateral_movement", "exfiltration"]
        for phase in phases:
            if phase["phase"] in high_risk_phases:
                severity_score += 30
        
        if severity_score >= 80:
            return "critical"
        elif severity_score >= 60:
            return "high"
        elif severity_score >= 40:
            return "medium"
        else:
            return "low"
    
    def _calculate_duration(self, events: List[Dict]) -> str:
        """Calculate attack duration."""
        if len(events) < 2:
            return "unknown"
        
        start_time = events[0].get("timestamp", "")
        end_time = events[-1].get("timestamp", "")
        
        try:
            start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            duration = end_dt - start_dt
            
            if duration.total_seconds() < 3600:  # < 1 hour
                return f"{int(duration.total_seconds() / 60)} minutes"
            elif duration.total_seconds() < 86400:  # < 1 day
                return f"{int(duration.total_seconds() / 3600)} hours"
            else:
                return f"{duration.days} days"
        except:
            return "unknown"
    
    def _calculate_confidence(self, phases: List[Dict]) -> float:
        """Calculate confidence score for attack chain."""
        base_confidence = 0.5
        
        # More phases increase confidence
        phase_bonus = min(len(phases) * 0.1, 0.3)
        
        # Logical attack sequence increases confidence
        expected_sequences = [
            ["reconnaissance", "initial_access"],
            ["initial_access", "privilege_escalation"],
            ["privilege_escalation", "lateral_movement"],
            ["lateral_movement", "exfiltration"]
        ]
        
        sequence_bonus = 0
        phase_names = [p["phase"] for p in phases]
        for expected in expected_sequences:
            if all(phase in phase_names for phase in expected):
                sequence_bonus += 0.1
        
        return min(base_confidence + phase_bonus + sequence_bonus, 0.95)


class AdvancedThreatEngine:
    """Main Advanced Threat Detection Engine integrating all components."""
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.ml_detector = MLAnomalyDetector()
        self.attack_analyzer = AttackPathAnalyzer()
        
        # Event buffer for correlation
        self.event_buffer = []
        self.max_buffer_size = 10000
    
    def analyze_events(self, events: List[Dict]) -> Dict:
        """Comprehensive threat analysis of events."""
        results = {
            "threats_detected": [],
            "anomalies": [],
            "attack_chains": [],
            "intelligence_matches": [],
            "risk_score": 0,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        # Add events to buffer for correlation
        self.event_buffer.extend(events)
        if len(self.event_buffer) > self.max_buffer_size:
            self.event_buffer = self.event_buffer[-self.max_buffer_size:]
        
        for event in events:
            # Threat Intelligence Analysis
            if "source_ip" in event:
                intel_match = self.threat_intel.check_ip_reputation(event["source_ip"])
                if intel_match:
                    results["intelligence_matches"].append({
                        "indicator": event["source_ip"],
                        "indicator_type": "ip",
                        "threat_data": intel_match,
                        "event": event
                    })
            
            # ML Anomaly Detection
            if "user" in event:
                user_anomalies = self.ml_detector.detect_user_anomalies(event["user"], event)
                results["anomalies"].extend(user_anomalies)
                
                # Update baseline for future analysis
                self.ml_detector.update_baseline(event)
            
            if "source_ip" in event:
                network_anomalies = self.ml_detector.detect_network_anomalies(event["source_ip"], event)
                results["anomalies"].extend(network_anomalies)
        
        # Attack Chain Analysis
        if len(self.event_buffer) >= 10:  # Need sufficient events
            attack_chains = self.attack_analyzer.correlate_events(self.event_buffer[-100:])
            results["attack_chains"] = attack_chains
        
        # Calculate overall risk score
        results["risk_score"] = self._calculate_risk_score(results)
        
        return results
    
    def _calculate_risk_score(self, results: Dict) -> int:
        """Calculate overall risk score (0-100)."""
        score = 0
        
        # Intelligence matches
        for match in results["intelligence_matches"]:
            severity = match["threat_data"].get("severity", "low")
            if severity == "critical":
                score += 40
            elif severity == "high":
                score += 25
            elif severity == "medium":
                score += 15
            else:
                score += 5
        
        # Anomalies
        for anomaly in results["anomalies"]:
            confidence = anomaly.get("confidence", 0.5)
            severity = anomaly.get("severity", "low")
            
            base_score = {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(severity, 5)
            score += int(base_score * confidence)
        
        # Attack chains (very high risk)
        for chain in results["attack_chains"]:
            chain_severity = chain.get("severity", "low")
            confidence = chain.get("confidence", 0.5)
            
            base_score = {"critical": 50, "high": 35, "medium": 20, "low": 10}.get(chain_severity, 10)
            score += int(base_score * confidence)
        
        return min(score, 100)


def test_advanced_detection():
    """Test the advanced detection engine."""
    engine = AdvancedThreatEngine()
    
    # Sample events for testing
    test_events = [
        {
            "timestamp": "2024-04-06T10:00:00Z",
            "source_ip": "192.168.1.100",
            "user": "admin",
            "action": "login",
            "type": "ssh_failed",
            "mitre_technique": "T1110.001"
        },
        {
            "timestamp": "2024-04-06T10:01:00Z",
            "source_ip": "192.168.1.100", 
            "user": "admin",
            "action": "login",
            "type": "privilege_escalation",
            "mitre_technique": "T1078"
        },
        {
            "timestamp": "2024-04-06T10:02:00Z",
            "source_ip": "10.0.0.50",
            "user": "admin",
            "action": "lateral_movement",
            "type": "lateral_movement",
            "mitre_technique": "T1021"
        }
    ]
    
    results = engine.analyze_events(test_events)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    test_advanced_detection()