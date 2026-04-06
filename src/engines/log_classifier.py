#!/usr/bin/env python3
"""
Log Classification Engine for LogSentinel Pro v3.0
Classifies logs by type, severity, and risk level
"""

import json
import re
from enum import Enum
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path


class LogType(Enum):
    """Log type categories."""
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    SYSTEM = "system"
    APPLICATION = "application"
    DATABASE = "database"
    SECURITY = "security"
    WEB_SERVER = "web_server"
    FIREWALL = "firewall"
    DNS = "dns"
    AUDIT = "audit"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk severity levels."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class LogClassifier:
    """Intelligent log entry classifier with pattern recognition."""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.classification_cache = {}
        self.total_classified = 0
        self.risk_distribution = {level.name: 0 for level in RiskLevel}
        
    def _initialize_patterns(self) -> Dict[LogType, Dict]:
        """Initialize detection patterns for different log types."""
        return {
            LogType.AUTHENTICATION: {
                "keywords": ["authentication", "login", "logout", "failed", "denied", "user", "password", 
                            "ssh", "sshd", "sudo", "su", "auth"],
                "patterns": [
                    r"(?i)(failed|invalid|denied).*password",
                    r"(?i)authentication\s+(failed|error|denied)",
                    r"(?i)(ssh|sshd).*(?:failed|invalid|refused)",
                    r"(?i)login\s+(failed|denied|invalid)",
                    r"(?i)account.*locked",
                ]
            },
            LogType.NETWORK: {
                "keywords": ["connection", "port", "tcp", "udp", "ip", "socket", "packet", "dropped", 
                            "firewall", "denied"],
                "patterns": [
                    r"(?i)(connection|connected|connecting)\s+(from|to)",
                    r"(?i)(port|src|dst)\s+\d+",
                    r"(?i)(tcp|udp|icmp)\s+\d+\.\d+",
                    r"(?i)firewall.*(?:blocked|dropped|denied)",
                ]
            },
            LogType.SYSTEM: {
                "keywords": ["kernel", "system", "error", "warning", "process", "crash", "panic", "core",
                            "memory", "cpu", "disk"],
                "patterns": [
                    r"(?i)kernel:\s+(panic|error|oops)",
                    r"(?i)segmentation\s+fault",
                    r"(?i)out\s+of\s+memory",
                    r"(?i)disk\s+full",
                    r"(?i)driver\s+error",
                ]
            },
            LogType.SECURITY: {
                "keywords": ["attack", "threat", "malware", "exploit", "injection", "xss", "sql", 
                            "brute", "scan", "intrusion"],
                "patterns": [
                    r"(?i)(sql\s*)?injection",
                    r"(?i)cross[\s-]*site.*script(?:ing)?",
                    r"(?i)brute\s+force",
                    r"(?i)malware|trojan|backdoor|rootkit",
                    r"(?i)privilege\s+escalation",
                ]
            },
            LogType.WEB_SERVER: {
                "keywords": ["http", "request", "response", "404", "500", "apache", "nginx", "web",
                            "get", "post", "status"],
                "patterns": [
                    r"(?i)(get|post|put|delete|patch)\s+\/\S+\s+HTTP",
                    r"HTTP/[\d\.]+\s+\d{3}",
                    r"(?i)apache|nginx.*not\s+found",
                    r"(?i)(404|500|503|403)\s+error",
                ]
            },
            LogType.DATABASE: {
                "keywords": ["database", "sql", "query", "db", "table", "mysql", "postgres", "oracle",
                            "transaction", "commit"],
                "patterns": [
                    r"(?i)sql.*error",
                    r"(?i)(select|insert|update|delete).*from",
                    r"(?i)database\s+error",
                    r"(?i)(mysql|postgres|oracle).*connection",
                ]
            },
            LogType.FIREWALL: {
                "keywords": ["firewall", "iptables", "pf", "ufw", "blocked", "dropped", "denied",
                            "accepted", "rejected"],
                "patterns": [
                    r"(?i)firewall.*(?:drop|reject|accept|block)",
                    r"(?i)iptables.*(?:DROP|REJECT|ACCEPT)",
                    r"(?i)(blocked|dropped)\s+(?:from|to)",
                ]
            },
            LogType.DNS: {
                "keywords": ["dns", "query", "resolve", "domain", "lookup", "nameserver", "a record",
                            "ns_name"],
                "patterns": [
                    r"(?i)dns.*query",
                    r"(?i)resolv(?:ing|ed).*(?:\d+\.\d+\.\d+\.\d+|[a-z0-9.-]+)",
                    r"(?i)nameserver.*error",
                ]
            },
            LogType.AUDIT: {
                "keywords": ["audit", "auditd", "compliance", "policy", "violation", "event"],
                "patterns": [
                    r"(?i)audit.*(?:type|event|record)",
                    r"(?i)auditd.*message",
                ]
            }
        }
    
    def classify_log(self, log_entry: str) -> Dict:
        """
        Classify a single log entry.
        
        Returns:
            Dict with keys: log_type, risk_level, confidence, risk_factors, timestamp
        """
        log_entry_lower = log_entry.lower()
        timestamp = datetime.now().isoformat()
        
        classification = {
            "original_log": log_entry,
            "timestamp": timestamp,
            "log_type": LogType.UNKNOWN.name,
            "risk_level": RiskLevel.INFO.name,
            "confidence": 0.0,
            "risk_factors": [],
            "risk_score": 0,
            "categorized": False
        }
        
        # Try to match patterns
        max_confidence = 0
        best_match = None
        
        for log_type, pattern_data in self.patterns.items():
            confidence = self._calculate_confidence(log_entry_lower, pattern_data)
            
            if confidence > max_confidence:
                max_confidence = confidence
                best_match = log_type
        
        if best_match and max_confidence > 0.3:
            classification["log_type"] = best_match.name
            classification["confidence"] = max_confidence
            classification["categorized"] = True
            
            # Assess risk level
            risk_level, risk_factors = self._assess_risk(log_entry, best_match)
            classification["risk_level"] = risk_level.name
            classification["risk_factors"] = risk_factors
            classification["risk_score"] = risk_level.value
        
        self.total_classified += 1
        self.risk_distribution[classification["risk_level"]] += 1
        
        return classification
    
    def classify_batch(self, log_entries: List[str]) -> List[Dict]:
        """Classify multiple log entries."""
        return [self.classify_log(entry) for entry in log_entries]
    
    def _calculate_confidence(self, log_entry: str, pattern_data: Dict) -> float:
        """Calculate confidence score for a log type."""
        score = 0.0
        
        # Check keywords
        keyword_matches = sum(1 for kw in pattern_data["keywords"] if kw in log_entry)
        keyword_score = min(keyword_matches / len(pattern_data["keywords"]) * 0.6, 0.6)
        
        # Check patterns
        pattern_matches = sum(1 for pattern in pattern_data["patterns"] 
                             if re.search(pattern, log_entry))
        pattern_score = min(pattern_matches / len(pattern_data["patterns"]) * 0.4, 0.4)
        
        return keyword_score + pattern_score
    
    def _assess_risk(self, log_entry: str, log_type: LogType) -> Tuple[RiskLevel, List[str]]:
        """Assess risk level and identify risk factors."""
        risk_factors = []
        risk_level = RiskLevel.INFO
        
        log_lower = log_entry.lower()
        
        # Authentication risks
        if log_type == LogType.AUTHENTICATION:
            if "failed" in log_lower:
                risk_factors.append("Failed login attempt")
                risk_level = max(risk_level, RiskLevel.MEDIUM)
            if "brute" in log_lower:
                risk_factors.append("Brute force attack detected")
                risk_level = max(risk_level, RiskLevel.CRITICAL)
            if "root" in log_lower and "failed" in log_lower:
                risk_factors.append("Root login attempt failed")
                risk_level = max(risk_level, RiskLevel.HIGH)
        
        # Security risks
        elif log_type == LogType.SECURITY:
            critical_keywords = ["sql injection", "xss", "exploit", "backdoor", "malware", 
                               "ransomware", "privilege escalation"]
            for keyword in critical_keywords:
                if keyword in log_lower:
                    risk_factors.append(keyword.title())
                    risk_level = RiskLevel.CRITICAL
                    break
            
            if "attack" in log_lower and "scan" not in log_lower:
                risk_level = max(risk_level, RiskLevel.HIGH)
        
        # Network risks
        elif log_type == LogType.NETWORK:
            if "dropped" in log_lower or "denied" in log_lower:
                risk_factors.append("Connection blocked")
                risk_level = max(risk_level, RiskLevel.LOW)
            if "multiple" in log_lower or "flood" in log_lower:
                risk_factors.append("Potential DoS attack")
                risk_level = max(risk_level, RiskLevel.HIGH)
        
        # System risks
        elif log_type == LogType.SYSTEM:
            critical_errors = ["panic", "core dump", "segmentation fault", "out of memory"]
            for error in critical_errors:
                if error in log_lower:
                    risk_factors.append(error.title())
                    risk_level = max(risk_level, RiskLevel.HIGH)
        
        # Firewall risks
        elif log_type == LogType.FIREWALL:
            if "blocked" in log_lower or "dropped" in log_lower:
                risk_factors.append("Traffic blocked by firewall")
                if "multiple" in log_lower or "repeated" in log_lower:
                    risk_level = max(risk_level, RiskLevel.MEDIUM)
                else:
                    risk_level = max(risk_level, RiskLevel.LOW)
        
        return risk_level, risk_factors
    
    def get_statistics(self) -> Dict:
        """Get classification statistics."""
        return {
            "total_classified": self.total_classified,
            "risk_distribution": self.risk_distribution,
            "average_risk": sum(int(level.split("_")[-1]) for level in self.risk_distribution) / max(1, self.total_classified)
        }
    
    def export_classifications(self, classifications: List[Dict], format: str = "json") -> str:
        """Export classifications in different formats."""
        if format == "json":
            return json.dumps(classifications, indent=2)
        elif format == "csv":
            # Simple CSV export
            lines = ["timestamp,log_type,risk_level,risk_score,confidence,risk_factors"]
            for c in classifications:
                factors = "|".join(c["risk_factors"]) if c["risk_factors"] else "None"
                lines.append(f'{c["timestamp"]},{c["log_type"]},{c["risk_level"]},{c["risk_score"]},{c["confidence"]:.2f},{factors}')
            return "\n".join(lines)
        else:
            return str(classifications)
