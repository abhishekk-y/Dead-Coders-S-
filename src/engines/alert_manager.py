#!/usr/bin/env python3
"""
Alert Management System for LogSentinel Pro v3.0
Real-time alerts and notifications for critical events
"""

import json
import uuid
from enum import Enum
from typing import Dict, List, Callable, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
import threading


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertStatus(Enum):
    """Alert status."""
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"
    SUPPRESSED = "SUPPRESSED"


@dataclass
class Alert:
    """Alert data structure."""
    alert_id: str
    timestamp: str
    severity: str
    title: str
    description: str
    source: str
    affected_host: Optional[str]
    risk_factors: List[str]
    status: str = AlertStatus.NEW.name
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    context: Dict = None
    
    def to_dict(self) -> Dict:
        """Convert alert to dictionary."""
        return asdict(self)


class AlertManager:
    """Manage alerts and notifications."""
    
    def __init__(self, max_alerts: int = 10000, alert_retention_hours: int = 72):
        self.alerts: Dict[str, Alert] = {}
        self.max_alerts = max_alerts
        self.alert_retention_hours = alert_retention_hours
        self.alert_listeners: List[Callable] = []
        self.alert_rules: Dict = self._initialize_alert_rules()
        self.suppressed_alerts: Dict = {}
        self.alert_lock = threading.Lock()
        
    def _initialize_alert_rules(self) -> Dict:
        """Initialize alert suppression and escalation rules."""
        return {
            "suppression_rules": [
                {
                    "name": "repeated_low_severity",
                    "condition": "severity == LOW and count > 5 in 5m",
                    "action": "suppress",
                    "duration_minutes": 30
                },
                {
                    "name": "duplicate_alerts",
                    "condition": "same_title and same_host in 1m",
                    "action": "deduplicate",
                    "duration_minutes": 5
                }
            ],
            "escalation_rules": [
                {
                    "name": "critical_attack",
                    "condition": "severity == CRITICAL",
                    "action": "escalate",
                    "escalate_to": ["SOC", "admin", "ciso"]
                },
                {
                    "name": "multiple_high_severity",
                    "condition": "count(severity == HIGH) > 3 in 10m",
                    "action": "escalate",
                    "escalate_to": ["SOC"]
                }
            ],
            "correlation_rules": [
                {
                    "name": "coordinated_attack",
                    "events": ["failed_login", "sql_injection", "privilege_escalation"],
                    "time_window_minutes": 5,
                    "severity": AlertSeverity.CRITICAL.name
                }
            ]
        }
    
    def create_alert(self, 
                    severity: AlertSeverity,
                    title: str,
                    description: str,
                    source: str,
                    affected_host: Optional[str] = None,
                    risk_factors: Optional[List[str]] = None,
                    context: Optional[Dict] = None) -> Alert:
        """Create and register a new alert."""
        
        alert_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        alert = Alert(
            alert_id=alert_id,
            timestamp=timestamp,
            severity=severity.name,
            title=title,
            description=description,
            source=source,
            affected_host=affected_host,
            risk_factors=risk_factors or [],
            status=AlertStatus.NEW.name,
            context=context or {}
        )
        
        with self.alert_lock:
            self.alerts[alert_id] = alert
        
        # Check for suppression
        if not self._should_suppress_alert(alert):
            # Notify listeners
            self._notify_listeners(alert)
        else:
            with self.alert_lock:
                alert.status = AlertStatus.SUPPRESSED.name
                self.alerts[alert_id] = alert
        
        return alert
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = "system") -> bool:
        """Acknowledge an alert."""
        with self.alert_lock:
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                alert.status = AlertStatus.ACKNOWLEDGED.name
                alert.acknowledged_by = acknowledged_by
                alert.acknowledged_at = datetime.now().isoformat()
                return True
        return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Mark alert as resolved."""
        with self.alert_lock:
            if alert_id in self.alerts:
                self.alerts[alert_id].status = AlertStatus.RESOLVED.name
                return True
        return False
    
    def escalate_alert(self, alert_id: str) -> bool:
        """Escalate an alert."""
        with self.alert_lock:
            if alert_id in self.alerts:
                self.alerts[alert_id].status = AlertStatus.ESCALATED.name
                return True
        return False
    
    def _should_suppress_alert(self, alert: Alert) -> bool:
        """Check if alert should be suppressed based on rules."""
        # Check for duplicate recent alerts
        threshold = datetime.fromisoformat(alert.timestamp) - timedelta(minutes=1)
        
        for existing_alert in self.alerts.values():
            if (existing_alert.title == alert.title and 
                existing_alert.affected_host == alert.affected_host and
                datetime.fromisoformat(existing_alert.timestamp) > threshold):
                return True
        
        return False
    
    def register_listener(self, callback: Callable) -> None:
        """Register a callback for alert events."""
        self.alert_listeners.append(callback)
    
    def _notify_listeners(self, alert: Alert) -> None:
        """Notify all registered listeners about new alert."""
        for listener in self.alert_listeners:
            try:
                listener(alert)
            except Exception as e:
                print(f"Error notifying listener: {e}")
    
    def get_alerts(self, 
                   severity: Optional[AlertSeverity] = None,
                   status: Optional[AlertStatus] = None,
                   host: Optional[str] = None,
                   limit: int = 100) -> List[Alert]:
        """Get alerts with optional filtering."""
        
        filtered_alerts = []
        
        with self.alert_lock:
            for alert in self.alerts.values():
                if severity and alert.severity != severity.name:
                    continue
                if status and alert.status != status.name:
                    continue
                if host and alert.affected_host != host:
                    continue
                filtered_alerts.append(alert)
        
        # Sort by timestamp (newest first)
        filtered_alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return filtered_alerts[:limit]
    
    def get_critical_alerts(self, hours: int = 24) -> List[Alert]:
        """Get all critical and high severity alerts from last N hours."""
        threshold = datetime.now() - timedelta(hours=hours)
        critical_alerts = []
        
        with self.alert_lock:
            for alert in self.alerts.values():
                if alert.severity in [AlertSeverity.CRITICAL.name, AlertSeverity.HIGH.name]:
                    alert_time = datetime.fromisoformat(alert.timestamp)
                    if alert_time > threshold:
                        critical_alerts.append(alert)
        
        critical_alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return critical_alerts
    
    def get_alert_summary(self) -> Dict:
        """Get summary of all alerts."""
        summary = {
            "total_alerts": len(self.alerts),
            "by_severity": {
                AlertSeverity.CRITICAL.name: 0,
                AlertSeverity.HIGH.name: 0,
                AlertSeverity.MEDIUM.name: 0,
                AlertSeverity.LOW.name: 0,
                AlertSeverity.INFO.name: 0
            },
            "by_status": {
                AlertStatus.NEW.name: 0,
                AlertStatus.ACKNOWLEDGED.name: 0,
                AlertStatus.RESOLVED.name: 0,
                AlertStatus.ESCALATED.name: 0,
                AlertStatus.SUPPRESSED.name: 0
            },
            "by_source": {}
        }
        
        with self.alert_lock:
            for alert in self.alerts.values():
                summary["by_severity"][alert.severity] += 1
                summary["by_status"][alert.status] += 1
                
                source = alert.source
                if source not in summary["by_source"]:
                    summary["by_source"][source] = 0
                summary["by_source"][source] += 1
        
        return summary
    
    def cleanup_old_alerts(self) -> int:
        """Remove alerts older than retention period."""
        threshold = datetime.now() - timedelta(hours=self.alert_retention_hours)
        removed_count = 0
        
        with self.alert_lock:
            alerts_to_remove = [
                alert_id for alert_id, alert in self.alerts.items()
                if datetime.fromisoformat(alert.timestamp) < threshold
            ]
            
            for alert_id in alerts_to_remove:
                del self.alerts[alert_id]
                removed_count += 1
        
        return removed_count
    
    def export_alerts(self, format: str = "json", status_filter: Optional[str] = None) -> str:
        """Export alerts in specified format."""
        with self.alert_lock:
            alerts_to_export = [
                a.to_dict() for a in self.alerts.values()
                if status_filter is None or a.status == status_filter
            ]
        
        if format == "json":
            return json.dumps(alerts_to_export, indent=2)
        elif format == "csv":
            lines = ["alert_id,timestamp,severity,title,source,status,acknowledged_by"]
            for alert_dict in alerts_to_export:
                lines.append(
                    f'{alert_dict["alert_id"]},{alert_dict["timestamp"]},{alert_dict["severity"]},'
                    f'"{alert_dict["title"]}",{alert_dict["source"]},{alert_dict["status"]},'
                    f'{alert_dict.get("acknowledged_by", "")}'
                )
            return "\n".join(lines)
        else:
            return str(alerts_to_export)
    
    def get_alert_trend(self, hours: int = 24, interval_minutes: int = 60) -> Dict:
        """Get alert trend over time."""
        trend = {}
        current_time = datetime.now()
        start_time = current_time - timedelta(hours=hours)
        
        with self.alert_lock:
            for alert in self.alerts.values():
                alert_time = datetime.fromisoformat(alert.timestamp)
                if alert_time < start_time:
                    continue
                
                # Round to nearest interval
                minutes_ago = int((current_time - alert_time).total_seconds() / 60)
                interval_bucket = (minutes_ago // interval_minutes) * interval_minutes
                interval_key = f"{interval_bucket}m_ago"
                
                if interval_key not in trend:
                    trend[interval_key] = {severity.name: 0 for severity in AlertSeverity}
                
                trend[interval_key][alert.severity] += 1
        
        return trend


class AlertNotificationHandler:
    """Handle alert notifications."""
    
    def __init__(self):
        self.notification_history = []
        self.max_history = 1000
    
    def send_notification(self, alert: Alert, channels: List[str] = None) -> Dict:
        """Send alert through specified channels."""
        if channels is None:
            channels = ["memory"]  # Default to in-memory storage
        
        notification = {
            "alert_id": alert.alert_id,
            "timestamp": datetime.now().isoformat(),
            "channels": channels,
            "alert_data": alert.to_dict()
        }
        
        for channel in channels:
            if channel == "memory":
                self._notify_memory(alert)
            elif channel == "email":
                self._notify_email(alert)
            elif channel == "webhook":
                self._notify_webhook(alert)
            elif channel == "syslog":
                self._notify_syslog(alert)
        
        self.notification_history.append(notification)
        if len(self.notification_history) > self.max_history:
            self.notification_history.pop(0)
        
        return notification
    
    def _notify_memory(self, alert: Alert) -> None:
        """Store notification in memory."""
        pass
    
    def _notify_email(self, alert: Alert) -> None:
        """Send email notification."""
        # In production: integrate with email service
        pass
    
    def _notify_webhook(self, alert: Alert) -> None:
        """Send webhook notification."""
        # In production: send HTTP POST to configured webhooks
        pass
    
    def _notify_syslog(self, alert: Alert) -> None:
        """Send syslog notification."""
        # In production: integrate with syslog
        pass
