#!/usr/bin/env python3
"""
Configuration Management System for LogSentinel Pro v3.0
Manage detection rules, thresholds, settings, and system configuration
"""

import json
import os
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import hashlib


class ConfigurationManager:
    """Centralized configuration management for LogSentinel Pro."""
    
    def __init__(self, config_dir: str = None):
        self.config_dir = Path(config_dir or Path.home() / ".local/share/LogSentinel Pro/config")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration files
        self.detection_rules_file = self.config_dir / "detection_rules.yaml"
        self.thresholds_file = self.config_dir / "thresholds.json"
        self.settings_file = self.config_dir / "settings.json"
        self.custom_iocs_file = self.config_dir / "custom_iocs.json"
        self.alert_config_file = self.config_dir / "alert_config.yaml"
        
        # Load configurations
        self.detection_rules = self._load_detection_rules()
        self.thresholds = self._load_thresholds()
        self.settings = self._load_settings()
        self.custom_iocs = self._load_custom_iocs()
        self.alert_config = self._load_alert_config()
    
    def _load_detection_rules(self) -> Dict:
        """Load custom detection rules."""
        default_rules = {
            "authentication": {
                "failed_login_threshold": 5,
                "failed_login_window_minutes": 15,
                "unusual_time_threshold_hours": [22, 6],  # 10 PM to 6 AM
                "geo_anomaly_distance_km": 500,
                "concurrent_sessions_limit": 3
            },
            "network": {
                "high_request_rate_threshold": 100,
                "request_rate_window_minutes": 5,
                "suspicious_user_agents": [
                    "sqlmap", "nikto", "nmap", "burp", "owasp",
                    "python-requests", "curl", "wget"
                ],
                "blocked_file_extensions": [
                    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"
                ]
            },
            "system": {
                "privilege_escalation_commands": [
                    "sudo", "su", "runas", "net user", "net localgroup",
                    "usermod", "chmod 777", "chown root"
                ],
                "suspicious_processes": [
                    "powershell.exe -enc", "cmd.exe /c", "wscript.exe",
                    "cscript.exe", "regsvr32.exe", "rundll32.exe"
                ],
                "critical_file_access": [
                    "/etc/passwd", "/etc/shadow", "SAM", "SYSTEM",
                    "SECURITY", "ntds.dit", "id_rsa", "id_dsa"
                ]
            },
            "data": {
                "large_transfer_threshold_mb": 100,
                "unusual_access_patterns": [
                    "bulk_download", "after_hours_access", "external_transfer"
                ],
                "sensitive_data_keywords": [
                    "password", "ssn", "credit_card", "api_key",
                    "secret", "token", "confidential"
                ]
            },
            "mitre_mappings": {
                "T1078": {"name": "Valid Accounts", "severity": "high"},
                "T1110": {"name": "Brute Force", "severity": "high"},
                "T1021": {"name": "Remote Services", "severity": "medium"},
                "T1071": {"name": "Application Layer Protocol", "severity": "medium"},
                "T1499": {"name": "Endpoint Denial of Service", "severity": "high"},
                "T1068": {"name": "Exploitation for Privilege Escalation", "severity": "critical"},
                "T1005": {"name": "Data from Local System", "severity": "medium"},
                "T1041": {"name": "Exfiltration Over C2 Channel", "severity": "high"}
            }
        }
        
        if self.detection_rules_file.exists():
            try:
                with open(self.detection_rules_file, 'r') as f:
                    loaded_rules = yaml.safe_load(f)
                    # Merge with defaults
                    for category, rules in default_rules.items():
                        if category in loaded_rules:
                            rules.update(loaded_rules[category])
                        loaded_rules.setdefault(category, rules)
                    return loaded_rules
            except Exception as e:
                print(f"Error loading detection rules: {e}")
        
        # Save default rules
        self._save_detection_rules(default_rules)
        return default_rules
    
    def _load_thresholds(self) -> Dict:
        """Load detection thresholds."""
        default_thresholds = {
            "risk_score": {
                "low": 20,
                "medium": 40,
                "high": 60,
                "critical": 80
            },
            "confidence": {
                "minimum_alert": 0.7,
                "auto_block": 0.9,
                "false_positive_threshold": 0.3
            },
            "performance": {
                "max_events_per_second": 1000,
                "correlation_window_hours": 24,
                "max_memory_usage_mb": 512,
                "log_retention_days": 90
            },
            "alerting": {
                "rate_limit_per_hour": 100,
                "duplicate_suppression_minutes": 15,
                "escalation_threshold": 5
            }
        }
        
        if self.thresholds_file.exists():
            try:
                with open(self.thresholds_file, 'r') as f:
                    loaded_thresholds = json.load(f)
                    # Merge with defaults
                    for category, thresholds in default_thresholds.items():
                        if category in loaded_thresholds:
                            thresholds.update(loaded_thresholds[category])
                        loaded_thresholds.setdefault(category, thresholds)
                    return loaded_thresholds
            except Exception as e:
                print(f"Error loading thresholds: {e}")
        
        # Save default thresholds
        self._save_thresholds(default_thresholds)
        return default_thresholds
    
    def _load_settings(self) -> Dict:
        """Load system settings."""
        default_settings = {
            "general": {
                "organization_name": "Your Organization",
                "timezone": "UTC",
                "log_level": "INFO",
                "enable_rich_output": True,
                "auto_update_iocs": True
            },
            "scanning": {
                "enable_real_time": False,
                "scan_depth": "standard",  # minimal, standard, deep
                "parallel_processing": True,
                "max_file_size_mb": 100,
                "excluded_directories": [
                    "/proc", "/sys", "/dev", "/tmp", 
                    "node_modules", ".git", "__pycache__"
                ]
            },
            "blockchain": {
                "enabled": True,
                "difficulty": 4,
                "auto_record": False,
                "backup_chain": True
            },
            "reporting": {
                "format": "pdf",  # pdf, json, txt
                "include_charts": True,
                "executive_summary": True,
                "compliance_frameworks": ["SOX", "PCI-DSS"],
                "auto_generate": False
            },
            "integrations": {
                "syslog_server": None,
                "webhook_url": None,
                "email_notifications": False,
                "slack_webhook": None,
                "splunk_hec": None
            }
        }
        
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                    # Merge with defaults
                    for category, settings in default_settings.items():
                        if category in loaded_settings:
                            if isinstance(settings, dict):
                                settings.update(loaded_settings[category])
                            else:
                                settings = loaded_settings[category]
                        loaded_settings.setdefault(category, settings)
                    return loaded_settings
            except Exception as e:
                print(f"Error loading settings: {e}")
        
        # Save default settings
        self._save_settings(default_settings)
        return default_settings
    
    def _load_custom_iocs(self) -> Dict:
        """Load custom IOCs (Indicators of Compromise)."""
        default_iocs = {
            "ips": {},
            "domains": {},
            "hashes": {},
            "urls": {},
            "email_addresses": {},
            "file_paths": {},
            "registry_keys": {},
            "last_updated": datetime.now().isoformat()
        }
        
        if self.custom_iocs_file.exists():
            try:
                with open(self.custom_iocs_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading custom IOCs: {e}")
        
        # Save default IOCs
        self._save_custom_iocs(default_iocs)
        return default_iocs
    
    def _load_alert_config(self) -> Dict:
        """Load alerting configuration."""
        default_alert_config = {
            "channels": {
                "email": {
                    "enabled": False,
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "recipients": []
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": "",
                    "channel": "#security-alerts",
                    "username": "LogSentinel"
                },
                "syslog": {
                    "enabled": False,
                    "server": "127.0.0.1",
                    "port": 514,
                    "facility": "local0"
                },
                "webhook": {
                    "enabled": False,
                    "url": "",
                    "headers": {},
                    "timeout": 30
                }
            },
            "rules": {
                "critical_alerts": {
                    "min_risk_score": 80,
                    "channels": ["email", "slack", "syslog"],
                    "immediate": True
                },
                "high_alerts": {
                    "min_risk_score": 60,
                    "channels": ["slack", "syslog"],
                    "immediate": False
                },
                "medium_alerts": {
                    "min_risk_score": 40,
                    "channels": ["syslog"],
                    "immediate": False
                },
                "attack_chain_alerts": {
                    "enabled": True,
                    "channels": ["email", "slack"],
                    "immediate": True
                }
            },
            "templates": {
                "critical": {
                    "subject": "🚨 CRITICAL: Security Threat Detected",
                    "body": "LogSentinel has detected a critical security threat requiring immediate attention.\n\nRisk Score: {risk_score}/100\nThreat Type: {threat_type}\nTimestamp: {timestamp}\n\nImmediate investigation required."
                },
                "high": {
                    "subject": "⚠️ HIGH: Security Alert",
                    "body": "LogSentinel has detected a high-priority security event.\n\nRisk Score: {risk_score}/100\nEvent Type: {event_type}\nTimestamp: {timestamp}\n\nPlease investigate within 4 hours."
                }
            }
        }
        
        if self.alert_config_file.exists():
            try:
                with open(self.alert_config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    # Merge with defaults
                    for category, config in default_alert_config.items():
                        if category in loaded_config:
                            if isinstance(config, dict):
                                self._deep_update(config, loaded_config[category])
                            else:
                                config = loaded_config[category]
                        loaded_config.setdefault(category, config)
                    return loaded_config
            except Exception as e:
                print(f"Error loading alert config: {e}")
        
        # Save default alert config
        self._save_alert_config(default_alert_config)
        return default_alert_config
    
    def _deep_update(self, base_dict: Dict, update_dict: Dict):
        """Deep update dictionary."""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def _save_detection_rules(self, rules: Dict):
        """Save detection rules to file."""
        try:
            with open(self.detection_rules_file, 'w') as f:
                yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
        except Exception as e:
            print(f"Error saving detection rules: {e}")
    
    def _save_thresholds(self, thresholds: Dict):
        """Save thresholds to file."""
        try:
            with open(self.thresholds_file, 'w') as f:
                json.dump(thresholds, f, indent=2)
        except Exception as e:
            print(f"Error saving thresholds: {e}")
    
    def _save_settings(self, settings: Dict):
        """Save settings to file."""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            print(f"Error saving settings: {e}")
    
    def _save_custom_iocs(self, iocs: Dict):
        """Save custom IOCs to file."""
        iocs["last_updated"] = datetime.now().isoformat()
        try:
            with open(self.custom_iocs_file, 'w') as f:
                json.dump(iocs, f, indent=2)
        except Exception as e:
            print(f"Error saving custom IOCs: {e}")
    
    def _save_alert_config(self, config: Dict):
        """Save alert config to file."""
        try:
            with open(self.alert_config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        except Exception as e:
            print(f"Error saving alert config: {e}")
    
    def update_detection_rule(self, category: str, rule_name: str, value: Any):
        """Update a specific detection rule."""
        if category in self.detection_rules:
            self.detection_rules[category][rule_name] = value
            self._save_detection_rules(self.detection_rules)
            return True
        return False
    
    def add_custom_ioc(self, ioc_type: str, indicator: str, metadata: Dict):
        """Add custom IOC."""
        if ioc_type in self.custom_iocs:
            self.custom_iocs[ioc_type][indicator] = {
                "added_date": datetime.now().isoformat(),
                "metadata": metadata,
                "active": True
            }
            self._save_custom_iocs(self.custom_iocs)
            return True
        return False
    
    def remove_custom_ioc(self, ioc_type: str, indicator: str):
        """Remove custom IOC."""
        if ioc_type in self.custom_iocs and indicator in self.custom_iocs[ioc_type]:
            del self.custom_iocs[ioc_type][indicator]
            self._save_custom_iocs(self.custom_iocs)
            return True
        return False
    
    def get_threshold(self, category: str, threshold_name: str) -> Any:
        """Get specific threshold value."""
        return self.thresholds.get(category, {}).get(threshold_name)
    
    def set_threshold(self, category: str, threshold_name: str, value: Any):
        """Set specific threshold value."""
        if category not in self.thresholds:
            self.thresholds[category] = {}
        self.thresholds[category][threshold_name] = value
        self._save_thresholds(self.thresholds)
    
    def get_setting(self, category: str, setting_name: str) -> Any:
        """Get specific setting value."""
        return self.settings.get(category, {}).get(setting_name)
    
    def set_setting(self, category: str, setting_name: str, value: Any):
        """Set specific setting value."""
        if category not in self.settings:
            self.settings[category] = {}
        self.settings[category][setting_name] = value
        self._save_settings(self.settings)
    
    def export_configuration(self, export_path: str) -> str:
        """Export all configuration to a single file."""
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "version": "3.0",
            "detection_rules": self.detection_rules,
            "thresholds": self.thresholds,
            "settings": self.settings,
            "custom_iocs": self.custom_iocs,
            "alert_config": self.alert_config
        }
        
        # Add checksum for integrity verification
        export_str = json.dumps(export_data, sort_keys=True)
        checksum = hashlib.sha256(export_str.encode()).hexdigest()
        export_data["checksum"] = checksum
        
        try:
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            return export_path
        except Exception as e:
            raise Exception(f"Failed to export configuration: {e}")
    
    def import_configuration(self, import_path: str, verify_checksum: bool = True) -> bool:
        """Import configuration from exported file."""
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            # Verify checksum if requested
            if verify_checksum and "checksum" in import_data:
                expected_checksum = import_data.pop("checksum")
                actual_str = json.dumps(import_data, sort_keys=True)
                actual_checksum = hashlib.sha256(actual_str.encode()).hexdigest()
                
                if expected_checksum != actual_checksum:
                    raise Exception("Configuration file integrity check failed")
            
            # Import each section
            if "detection_rules" in import_data:
                self.detection_rules = import_data["detection_rules"]
                self._save_detection_rules(self.detection_rules)
            
            if "thresholds" in import_data:
                self.thresholds = import_data["thresholds"]
                self._save_thresholds(self.thresholds)
            
            if "settings" in import_data:
                self.settings = import_data["settings"]
                self._save_settings(self.settings)
            
            if "custom_iocs" in import_data:
                self.custom_iocs = import_data["custom_iocs"]
                self._save_custom_iocs(self.custom_iocs)
            
            if "alert_config" in import_data:
                self.alert_config = import_data["alert_config"]
                self._save_alert_config(self.alert_config)
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to import configuration: {e}")
    
    def validate_configuration(self) -> List[str]:
        """Validate current configuration and return list of issues."""
        issues = []
        
        # Validate thresholds
        risk_thresholds = self.thresholds.get("risk_score", {})
        if not all(key in risk_thresholds for key in ["low", "medium", "high", "critical"]):
            issues.append("Missing risk score thresholds")
        
        # Validate detection rules
        if not self.detection_rules.get("authentication"):
            issues.append("Missing authentication rules")
        
        if not self.detection_rules.get("network"):
            issues.append("Missing network rules")
        
        # Validate alert configuration
        channels = self.alert_config.get("channels", {})
        enabled_channels = [name for name, config in channels.items() if config.get("enabled")]
        
        if not enabled_channels:
            issues.append("No alert channels configured")
        
        # Validate settings
        if not self.settings.get("general", {}).get("organization_name"):
            issues.append("Organization name not configured")
        
        return issues
    
    def get_configuration_summary(self) -> Dict:
        """Get summary of current configuration."""
        return {
            "detection_rules": {
                "categories": len(self.detection_rules),
                "total_rules": sum(len(rules) for rules in self.detection_rules.values() if isinstance(rules, dict))
            },
            "custom_iocs": {
                "total": sum(len(iocs) for iocs in self.custom_iocs.values() if isinstance(iocs, dict)),
                "by_type": {k: len(v) for k, v in self.custom_iocs.items() if isinstance(v, dict)}
            },
            "thresholds": {
                "categories": len(self.thresholds)
            },
            "alert_channels": {
                "configured": len(self.alert_config.get("channels", {})),
                "enabled": len([c for c in self.alert_config.get("channels", {}).values() if c.get("enabled")])
            },
            "last_modified": max([
                os.path.getmtime(f) for f in [
                    self.detection_rules_file,
                    self.thresholds_file,
                    self.settings_file,
                    self.custom_iocs_file,
                    self.alert_config_file
                ] if f.exists()
            ], default=0)
        }


class RuleEngine:
    """Rule engine for custom detection logic."""
    
    def __init__(self, config_manager: ConfigurationManager):
        self.config = config_manager
    
    def evaluate_event(self, event: Dict) -> List[Dict]:
        """Evaluate event against custom rules."""
        alerts = []
        
        # Authentication rules
        if event.get("category") == "authentication":
            alerts.extend(self._evaluate_auth_rules(event))
        
        # Network rules
        elif event.get("category") == "network":
            alerts.extend(self._evaluate_network_rules(event))
        
        # System rules
        elif event.get("category") == "system":
            alerts.extend(self._evaluate_system_rules(event))
        
        # Data access rules
        elif event.get("category") == "data":
            alerts.extend(self._evaluate_data_rules(event))
        
        return alerts
    
    def _evaluate_auth_rules(self, event: Dict) -> List[Dict]:
        """Evaluate authentication-specific rules."""
        alerts = []
        auth_rules = self.config.detection_rules.get("authentication", {})
        
        # Failed login threshold
        if event.get("action") == "failed_login":
            threshold = auth_rules.get("failed_login_threshold", 5)
            count = event.get("failed_count", 1)
            
            if count >= threshold:
                alerts.append({
                    "rule": "failed_login_threshold",
                    "severity": "high",
                    "description": f"Failed login threshold exceeded: {count} attempts",
                    "confidence": min(count / (threshold * 2), 1.0),
                    "mitre_technique": "T1110.001"
                })
        
        # Unusual time login
        if event.get("action") == "login":
            unusual_hours = auth_rules.get("unusual_time_threshold_hours", [22, 6])
            current_hour = datetime.now().hour
            
            if unusual_hours[0] <= current_hour or current_hour <= unusual_hours[1]:
                alerts.append({
                    "rule": "unusual_time_login",
                    "severity": "medium",
                    "description": f"Login during unusual hours: {current_hour}:00",
                    "confidence": 0.7,
                    "mitre_technique": "T1078"
                })
        
        return alerts
    
    def _evaluate_network_rules(self, event: Dict) -> List[Dict]:
        """Evaluate network-specific rules."""
        alerts = []
        network_rules = self.config.detection_rules.get("network", {})
        
        # High request rate
        request_rate = event.get("request_rate", 0)
        threshold = network_rules.get("high_request_rate_threshold", 100)
        
        if request_rate > threshold:
            alerts.append({
                "rule": "high_request_rate",
                "severity": "high",
                "description": f"High request rate detected: {request_rate} req/min",
                "confidence": min(request_rate / (threshold * 2), 1.0),
                "mitre_technique": "T1499.002"
            })
        
        # Suspicious user agent
        user_agent = event.get("user_agent", "")
        suspicious_agents = network_rules.get("suspicious_user_agents", [])
        
        for agent in suspicious_agents:
            if agent.lower() in user_agent.lower():
                alerts.append({
                    "rule": "suspicious_user_agent",
                    "severity": "medium",
                    "description": f"Suspicious User-Agent detected: {agent}",
                    "confidence": 0.8,
                    "mitre_technique": "T1071.001"
                })
                break
        
        return alerts
    
    def _evaluate_system_rules(self, event: Dict) -> List[Dict]:
        """Evaluate system-specific rules."""
        alerts = []
        system_rules = self.config.detection_rules.get("system", {})
        
        # Privilege escalation commands
        command = event.get("command", "")
        priv_commands = system_rules.get("privilege_escalation_commands", [])
        
        for priv_cmd in priv_commands:
            if priv_cmd.lower() in command.lower():
                alerts.append({
                    "rule": "privilege_escalation_command",
                    "severity": "high",
                    "description": f"Privilege escalation command detected: {priv_cmd}",
                    "confidence": 0.9,
                    "mitre_technique": "T1068"
                })
                break
        
        # Suspicious processes
        process = event.get("process_name", "")
        suspicious_processes = system_rules.get("suspicious_processes", [])
        
        for sus_proc in suspicious_processes:
            if sus_proc.lower() in process.lower():
                alerts.append({
                    "rule": "suspicious_process",
                    "severity": "medium",
                    "description": f"Suspicious process detected: {sus_proc}",
                    "confidence": 0.8,
                    "mitre_technique": "T1059"
                })
                break
        
        return alerts
    
    def _evaluate_data_rules(self, event: Dict) -> List[Dict]:
        """Evaluate data access rules."""
        alerts = []
        data_rules = self.config.detection_rules.get("data", {})
        
        # Large data transfer
        transfer_size = event.get("transfer_size_mb", 0)
        threshold = data_rules.get("large_transfer_threshold_mb", 100)
        
        if transfer_size > threshold:
            alerts.append({
                "rule": "large_data_transfer",
                "severity": "medium",
                "description": f"Large data transfer detected: {transfer_size}MB",
                "confidence": min(transfer_size / (threshold * 2), 1.0),
                "mitre_technique": "T1041"
            })
        
        # Sensitive data access
        file_path = event.get("file_path", "")
        keywords = data_rules.get("sensitive_data_keywords", [])
        
        for keyword in keywords:
            if keyword.lower() in file_path.lower():
                alerts.append({
                    "rule": "sensitive_data_access",
                    "severity": "high",
                    "description": f"Access to sensitive data: {keyword}",
                    "confidence": 0.8,
                    "mitre_technique": "T1005"
                })
                break
        
        return alerts


def create_sample_configuration():
    """Create sample configuration for testing."""
    config_manager = ConfigurationManager()
    
    # Add sample custom IOCs
    config_manager.add_custom_ioc("ips", "192.168.100.50", {
        "type": "internal_threat",
        "severity": "high",
        "description": "Compromised internal host",
        "source": "incident_response"
    })
    
    config_manager.add_custom_ioc("domains", "malicious-site.example.com", {
        "type": "c2_domain",
        "severity": "critical",
        "description": "Known C2 infrastructure",
        "source": "threat_intelligence"
    })
    
    # Update some settings
    config_manager.set_setting("general", "organization_name", "Acme Corporation")
    config_manager.set_setting("scanning", "enable_real_time", True)
    config_manager.set_threshold("risk_score", "critical", 85)
    
    print("Sample configuration created successfully!")
    print("\nConfiguration Summary:")
    summary = config_manager.get_configuration_summary()
    for key, value in summary.items():
        print(f"  {key}: {value}")
    
    # Validate configuration
    issues = config_manager.validate_configuration()
    if issues:
        print(f"\nConfiguration Issues Found:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("\nConfiguration validation passed!")
    
    return config_manager


if __name__ == "__main__":
    # Test configuration management
    config = create_sample_configuration()
    
    # Test rule engine
    rule_engine = RuleEngine(config)
    
    # Test event evaluation
    test_event = {
        "category": "authentication",
        "action": "failed_login",
        "failed_count": 8,
        "timestamp": datetime.now().isoformat()
    }
    
    alerts = rule_engine.evaluate_event(test_event)
    print(f"\nTest Event Alerts: {len(alerts)}")
    for alert in alerts:
        print(f"  - {alert['rule']}: {alert['description']} ({alert['severity']})")