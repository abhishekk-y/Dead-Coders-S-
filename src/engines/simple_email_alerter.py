#!/usr/bin/env python3
"""
Simple Email Alert System - User Login & Security Notifications
Production-Grade Easy-to-Use Email Alerting for LogSentinel Pro v4.0
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass


@dataclass
class EmailConfig:
    """Email configuration."""
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    sender_email: str = "security-alerts@your-domain.com"
    sender_password: str = "your-app-password"
    sender_name: str = "LogSentinel Security"
    use_tls: bool = True


class SimpleEmailAlerter:
    """Simple, easy-to-use email alerting system."""
    
    def __init__(self, config: Optional[EmailConfig] = None):
        """Initialize email alerter."""
        self.config = config or EmailConfig()
        self.email_templates = self._initialize_templates()
        self.alert_history = []
    
    def _initialize_templates(self) -> Dict[str, str]:
        """Predefined email templates for common alerts."""
        return {
            'login_alert': self._template_login_alert,
            'brute_force': self._template_brute_force,
            'anomaly': self._template_anomaly,
            'critical': self._template_critical_alert,
            'report': self._template_report,
            'verification': self._template_verification
        }
    
    def send_login_alert(self,
                        user_email: str,
                        username: str,
                        login_form: str,
                        login_ip: str,
                        login_location: str,
                        login_device: str,
                        timestamp: Optional[str] = None) -> Tuple[bool, str]:
        """
        Send simple login alert to user.
        
        Args:
            user_email: User's email address
            username: Username that logged in
            login_form: Form/application they logged in from (e.g., "Admin Portal", "Web App", "Mobile App")
            login_ip: IP address of login
            login_location: Geographic location (e.g., "New York, USA")
            login_device: Device information (e.g., "Chrome on Windows 10")
            timestamp: Login time (auto-generated if not provided)
            
        Returns:
            (success: bool, message: str)
        """
        
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        subject = f"🔔 New Login Detected - {login_form}"
        
        body = f"""
        <h2>🔐 New Login to Your Account</h2>
        
        <p>Hi {username},</p>
        
        <p>We detected a new login to your account. Please verify this was you:</p>
        
        <table style="border-collapse: collapse; width: 100%; margin: 20px 0;">
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Login From:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{login_form}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Time:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{timestamp}</td>
            </tr>
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>IP Address:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{login_ip}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Location:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{login_location}</td>
            </tr>
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Device:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{login_device}</td>
            </tr>
        </table>
        
        <p><strong>⚠️ If this wasn't you:</strong></p>
        <ul>
            <li>Change your password immediately</li>
            <li>Enable two-factor authentication</li>
            <li>Contact support if account is compromised</li>
        </ul>
        
        <p style="color: #666; font-size: 12px;">
            This is an automated security alert. Do not reply to this email.
        </p>
        """
        
        return self.send_email(user_email, subject, body)
    
    def send_brute_force_alert(self,
                              admin_email: str,
                              target_username: str,
                              attempts_count: int,
                              source_ip: str,
                              source_location: str) -> Tuple[bool, str]:
        """Send brute force attack alert to admin."""
        
        subject = f"🚨 CRITICAL: Brute Force Attack Detected - {source_ip}"
        
        body = f"""
        <h2 style="color: red;">🚨 BRUTE FORCE ATTACK DETECTED</h2>
        
        <p><strong>Alert Level: CRITICAL</strong></p>
        
        <p>A brute force attack has been detected against your system.</p>
        
        <table style="border-collapse: collapse; width: 100%; margin: 20px 0;">
            <tr style="background-color: #ffcccc;">
                <td style="padding: 10px; border: 1px solid #cc0000;"><strong>Target Account:</strong></td>
                <td style="padding: 10px; border: 1px solid #cc0000;">{target_username}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Failed Attempts:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;"><span style="color: red; font-weight: bold;">{attempts_count}</span></td>
            </tr>
            <tr style="background-color: #ffcccc;">
                <td style="padding: 10px; border: 1px solid #cc0000;"><strong>Source IP:</strong></td>
                <td style="padding: 10px; border: 1px solid #cc0000;">{source_ip}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Location:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{source_location}</td>
            </tr>
        </table>
        
        <p><strong>✅ Actions Taken:</strong></p>
        <ul>
            <li>✓ Account temporarily locked</li>
            <li>✓ Source IP blocked at firewall</li>
            <li>✓ Incident logged for audit trail</li>
        </ul>
        
        <p><strong>🔧 Recommended Actions:</strong></p>
        <ul>
            <li>Review account activity logs</li>
            <li>Reset user password</li>
            <li>Enable MFA for this account</li>
            <li>Investigate source IP for other attacks</li>
        </ul>
        
        <p style="color: #666; font-size: 12px;">
            LogSentinel Security - Automatic Alert System
        </p>
        """
        
        return self.send_email(admin_email, subject, body)
    
    def send_anomaly_alert(self,
                          admin_email: str,
                          anomaly_type: str,
                          description: str,
                          severity: str,
                          metric_value: float,
                          expected_value: float,
                          timestamp: Optional[str] = None) -> Tuple[bool, str]:
        """Send anomaly detection alert."""
        
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        severity_color = {
            'CRITICAL': '#cc0000',
            'HIGH': '#ff6600',
            'MEDIUM': '#ffcc00',
            'LOW': '#0066cc'
        }
        color = severity_color.get(severity, '#0066cc')
        
        subject = f"⚠️ [{severity}] Anomaly Alert: {anomaly_type}"
        
        body = f"""
        <h2 style="color: {color};">⚠️ Anomaly Detected</h2>
        
        <p><strong>Alert Level: {severity}</strong></p>
        
        <p>{description}</p>
        
        <table style="border-collapse: collapse; width: 100%; margin: 20px 0;">
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Anomaly Type:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{anomaly_type}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Detected Time:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{timestamp}</td>
            </tr>
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Current Value:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;"><span style="color: red; font-weight: bold;">{metric_value}</span></td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Expected Value:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{expected_value}</td>
            </tr>
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Deviation:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{(metric_value/expected_value)*100:.1f}%</td>
            </tr>
        </table>
        
        <p><strong>🔧 Recommended Action:</strong></p>
        <p>Investigate immediately. Review system logs and metrics.</p>
        
        <p style="color: #666; font-size: 12px;">
            LogSentinel Security - Automatic Alert System
        </p>
        """
        
        return self.send_email(admin_email, subject, body)
    
    def send_security_report(self,
                            admin_email: str,
                            report_date: str,
                            total_logs: int,
                            alerts_gen: int,
                            critical_count: int,
                            attacks_detected: int,
                            top_threats: List[str]) -> Tuple[bool, str]:
        """Send daily/weekly security report."""
        
        subject = f"📊 Security Report - {report_date}"
        
        threats_html = "".join([f"<li>{threat}</li>" for threat in top_threats[:5]])
        
        body = f"""
        <h2>📊 Security Report</h2>
        
        <p>Daily security summary for {report_date}</p>
        
        <table style="border-collapse: collapse; width: 100%; margin: 20px 0;">
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Total Logs Processed:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{total_logs:,}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Alerts Generated:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{alerts_gen}</td>
            </tr>
            <tr style="background-color: #ffcccc;">
                <td style="padding: 10px; border: 1px solid #cc0000;"><strong>Critical Alerts:</strong></td>
                <td style="padding: 10px; border: 1px solid #cc0000;"><span style="color: red; font-weight: bold;">{critical_count}</span></td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Attacks Detected:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{attacks_detected}</td>
            </tr>
        </table>
        
        <p><strong>🔴 Top Threats:</strong></p>
        <ul>
            {threats_html}
        </ul>
        
        <p style="color: #666; font-size: 12px;">
            LogSentinel Security - Automatic Alert System
        </p>
        """
        
        return self.send_email(admin_email, subject, body)
    
    def send_email(self, to_email: str, subject: str, body: str) -> Tuple[bool, str]:
        """
        Send email - Core function (SIMPLE & EASY).
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            body: HTML email body
            
        Returns:
            (success: bool, message: str)
        """
        
        try:
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = f"{self.config.sender_name} <{self.config.sender_email}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Attach HTML content
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            if self.config.use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                    server.starttls(context=context)
                    server.login(self.config.sender_email, self.config.sender_password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP_SSL(self.config.smtp_server, 465) as server:
                    server.login(self.config.sender_email, self.config.sender_password)
                    server.send_message(msg)
            
            message = f"Email sent to {to_email}"
            self.alert_history.append({
                'timestamp': datetime.now().isoformat(),
                'recipient': to_email,
                'subject': subject,
                'status': 'sent'
            })
            
            return True, message
        
        except Exception as e:
            message = f"Failed to send email: {str(e)}"
            self.alert_history.append({
                'timestamp': datetime.now().isoformat(),
                'recipient': to_email,
                'subject': subject,
                'status': 'failed',
                'error': str(e)
            })
            return False, message
    
    def send_multiple_alerts(self,
                            alert_type: str,
                            recipients: List[str],
                            **kwargs) -> Dict[str, Tuple[bool, str]]:
        """Send same alert to multiple recipients."""
        
        results = {}
        
        for recipient in recipients:
            if alert_type == 'login':
                success, msg = self.send_login_alert(recipient, **kwargs)
            elif alert_type == 'brute_force':
                success, msg = self.send_brute_force_alert(recipient, **kwargs)
            elif alert_type == 'anomaly':
                success, msg = self.send_anomaly_alert(recipient, **kwargs)
            else:
                success, msg = False, "Unknown alert type"
            
            results[recipient] = (success, msg)
        
        return results
    
    def get_alert_history(self, limit: int = 100) -> List[Dict]:
        """Get alert history."""
        return self.alert_history[-limit:]
    
    def _template_login_alert(self) -> str:
        """Template for login alerts."""
        return "login_alert"
    
    def _template_brute_force(self) -> str:
        """Template for brute force alerts."""
        return "brute_force"
    
    def _template_anomaly(self) -> str:
        """Template for anomaly alerts."""
        return "anomaly"
    
    def _template_critical_alert(self) -> str:
        """Template for critical alerts."""
        return "critical"
    
    def _template_report(self) -> str:
        """Template for security reports."""
        return "report"
    
    def _template_verification(self) -> str:
        """Template for verification alerts."""
        return "verification"


# Easy-to-use helper functions
def alert_user_login(user_email: str,
                    username: str,
                    form_name: str,
                    ip_address: str,
                    location: str,
                    device: str) -> bool:
    """
    SIMPLE function to alert user about login.
    
    Usage:
        alert_user_login(
            user_email="user@example.com",
            username="john_doe",
            form_name="Admin Portal",
            ip_address="192.168.1.100",
            location="New York, USA",
            device="Chrome on Windows"
        )
    """
    alerter = SimpleEmailAlerter()
    success, msg = alerter.send_login_alert(
        user_email, username, form_name, ip_address, location, device
    )
    print(msg)
    return success


def alert_admin_brute_force(admin_email: str,
                           target_user: str,
                           attempts: int,
                           source_ip: str,
                           location: str) -> bool:
    """
    SIMPLE function to alert admin about brute force attack.
    
    Usage:
        alert_admin_brute_force(
            admin_email="admin@example.com",
            target_user="admin",
            attempts=50,
            source_ip="192.168.1.100",
            location="Unknown, Unknown"
        )
    """
    alerter = SimpleEmailAlerter()
    success, msg = alerter.send_brute_force_alert(
        admin_email, target_user, attempts, source_ip, location
    )
    print(msg)
    return success


def alert_admin_anomaly(admin_email: str,
                       anomaly_type: str,
                       description: str,
                       severity: str,
                       current_value: float,
                       expected_value: float) -> bool:
    """
    SIMPLE function to alert admin about anomaly.
    
    Usage:
        alert_admin_anomaly(
            admin_email="admin@example.com",
            anomaly_type="CPU Usage",
            description="CPU usage spike detected",
            severity="HIGH",
            current_value=95.5,
            expected_value=45.0
        )
    """
    alerter = SimpleEmailAlerter()
    success, msg = alerter.send_anomaly_alert(
        admin_email, anomaly_type, description, severity, current_value, expected_value
    )
    print(msg)
    return success


# Configuration helper
def setup_email_config(smtp_server: str,
                      smtp_port: int,
                      sender_email: str,
                      sender_password: str,
                      sender_name: str = "LogSentinel Security") -> EmailConfig:
    """Easy setup for email configuration."""
    return EmailConfig(
        smtp_server=smtp_server,
        smtp_port=smtp_port,
        sender_email=sender_email,
        sender_password=sender_password,
        sender_name=sender_name
    )
