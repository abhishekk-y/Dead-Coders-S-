#!/usr/bin/env python3
"""
Email Alerter for LogSentinel Pro v4.0
Production-grade email alerting via SMTP
"""

import os
import json
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class SMTPConfig:
    """SMTP configuration."""
    host: str
    port: int
    user: str
    password: str
    from_email: str
    from_name: str = "LogSentinel Security"


class EmailAlerter:
    """Professional email alerting via SMTP."""
    
    def __init__(self, smtp_config: SMTPConfig):
        """Initialize SMTP email alerter."""
        self.smtp_config = smtp_config
        self.alert_history = []
        
        if not smtp_config:
            raise ValueError("SMTP configuration required")
        
        print("[+] SMTP Email Alerter initialized")
    
    def send_attack_alert(self, 
                         to_email: str,
                         attack_name: str,
                         severity: str,
                         description: str,
                         remediation: str,
                         source_ip: str,
                         log_sample: str,
                         cve_ids: List[str] = None,
                         confidence: float = 0.95) -> Dict:
        """Send critical attack alert."""
        
        cve_ids = cve_ids or []
        color_map = {
            'CRITICAL': '#dc3545',
            'HIGH': '#ff6b35',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }
        color = color_map.get(severity, '#6c757d')
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
                .header {{ background: {color}; color: white; padding: 20px; border-radius: 4px; margin-bottom: 20px; }}
                .header h1 {{ margin: 0; font-size: 24px; }}
                .alert-box {{ background: #fff3cd; border-left: 4px solid {color}; padding: 15px; margin: 15px 0; }}
                .section {{ margin: 20px 0; }}
                .section-title {{ font-weight: bold; color: #333; font-size: 16px; margin-bottom: 10px; }}
                .detail {{ background: #f9f9f9; padding: 12px; margin: 8px 0; border-radius: 4px; font-family: monospace; word-break: break-all; }}
                .remediation {{ background: #d4edda; padding: 15px; border-radius: 4px; margin: 15px 0; }}
                .footer {{ color: #666; font-size: 12px; margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px; }}
                .badge {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 5px; }}
                .badge-critical {{ background: #dc3545; color: white; }}
                .badge-high {{ background: #ff6b35; color: white; }}
                .badge-medium {{ background: #ffc107; color: #333; }}
                .badge-low {{ background: #28a745; color: white; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 Security Alert - Attack Detected</h1>
                </div>
                
                <div class="section">
                    <div class="section-title">Attack Information</div>
                    <div class="detail">
                        <strong>Attack Type:</strong> {attack_name}<br>
                        <strong>Severity:</strong> <span class="badge badge-{severity.lower()}">{severity}</span><br>
                        <strong>Confidence:</strong> {confidence*100:.0f}%<br>
                        <strong>Detected:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">Description</div>
                    <div class="detail">{description}</div>
                </div>
                
                <div class="section">
                    <div class="section-title">Attack Source</div>
                    <div class="detail">
                        <strong>Source IP:</strong> {source_ip}<br>
                        <strong>Log Sample:</strong><br>
                        <code>{log_sample[:200]}</code>
                    </div>
                </div>
                
                {f'<div class="section"><div class="section-title">CVE References</div><div class="detail">{", ".join(cve_ids)}</div></div>' if cve_ids else ''}
                
                <div class="remediation">
                    <strong>🛡️ Recommended Actions:</strong><br>
                    {remediation}
                </div>
                
                <div class="section">
                    <div class="section-title">Next Steps</div>
                    <div class="detail">
                        1. Review the log sample above<br>
                        2. Check for similar patterns in your logs<br>
                        3. Implement recommended remediation<br>
                        4. Monitor for additional attacks<br>
                        5. Update firewall/WAF rules if needed
                    </div>
                </div>
                
                <div class="footer">
                    <strong>LogSentinel Pro v4.0</strong> | Global Attack Recognition System<br>
                    This is an automated security alert. Do not reply to this email.<br>
                    For support: security@logsentinel.com
                </div>
            </div>
        </body>
        </html>
        """
        
        subject = f"🚨 [{severity}] {attack_name} - Immediate Action Required"
        
        return self._send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content
        )
    
    def send_anomaly_alert(self,
                          to_email: str,
                          metric_name: str,
                          current_value: float,
                          baseline_value: float,
                          anomaly_score: float,
                          severity: str,
                          explanation: str) -> Dict:
        """Send anomaly detection alert."""
        
        deviation_pct = ((current_value - baseline_value) / baseline_value) * 100
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
                .header {{ background: #ff6b35; color: white; padding: 20px; border-radius: 4px; margin-bottom: 20px; }}
                .metric-box {{ background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 10px 0; }}
                .metric-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #ddd; }}
                .metric-label {{ font-weight: bold; }}
                .metric-value {{ font-family: monospace; font-size: 14px; }}
                .chart {{ background: white; padding: 15px; margin: 15px 0; border: 1px solid #ddd; border-radius: 4px; }}
                .footer {{ color: #666; font-size: 12px; margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>⚠️ Anomaly Detected</h1>
                </div>
                
                <div class="metric-box">
                    <div class="metric-row">
                        <span class="metric-label">Metric:</span>
                        <span class="metric-value">{metric_name}</span>
                    </div>
                    <div class="metric-row">
                        <span class="metric-label">Current Value:</span>
                        <span class="metric-value" style="color: red; font-weight: bold;">{current_value:,.2f}</span>
                    </div>
                    <div class="metric-row">
                        <span class="metric-label">Baseline Value:</span>
                        <span class="metric-value">{baseline_value:,.2f}</span>
                    </div>
                    <div class="metric-row">
                        <span class="metric-label">Deviation:</span>
                        <span class="metric-value" style="color: red; font-weight: bold;">{deviation_pct:+.1f}%</span>
                    </div>
                    <div class="metric-row">
                        <span class="metric-label">Anomaly Score:</span>
                        <span class="metric-value">{anomaly_score:.2f}/100</span>
                    </div>
                    <div class="metric-row">
                        <span class="metric-label">Severity:</span>
                        <span class="metric-value" style="font-weight: bold;">{severity}</span>
                    </div>
                </div>
                
                <div style="background: #f9f9f9; padding: 15px; border-radius: 4px; margin: 15px 0;">
                    <strong>Analysis:</strong><br>
                    {explanation}
                </div>
                
                <div class="footer">
                    <strong>LogSentinel Pro v4.0</strong> | ML Anomaly Detection<br>
                    Detected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
                </div>
            </div>
        </body>
        </html>
        """
        
        subject = f"⚠️ [{severity}] Anomaly Detected: {metric_name}"
        
        return self._send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content
        )
    
    def send_security_report(self,
                            to_email: str,
                            report_type: str,
                            total_logs: int,
                            total_alerts: int,
                            critical_count: int,
                            high_count: int,
                            report_data: Dict = None) -> Dict:
        """Send daily/weekly security report."""
        
        report_data = report_data or {}
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
                .container {{ max-width: 700px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
                .header {{ background: #003d7a; color: white; padding: 20px; border-radius: 4px; margin-bottom: 20px; }}
                .header h1 {{ margin: 0; font-size: 28px; }}
                .stats-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 20px 0; }}
                .stat-card {{ background: #f0f0f0; padding: 20px; border-radius: 4px; text-align: center; border-left: 4px solid #003d7a; }}
                .stat-number {{ font-size: 32px; font-weight: bold; color: #003d7a; }}
                .stat-label {{ color: #666; font-size: 12px; margin-top: 5px; }}
                .critical {{ border-left-color: #dc3545; }}
                .high {{ border-left-color: #ff6b35; }}
                .medium {{ border-left-color: #ffc107; }}
                .low {{ border-left-color: #28a745; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th {{ background: #003d7a; color: white; padding: 10px; text-align: left; }}
                td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
                tr:nth-child(even) {{ background: #f9f9f9; }}
                .footer {{ color: #666; font-size: 12px; margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 Security Report - {report_type.title()}</h1>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{total_logs:,}</div>
                        <div class="stat-label">Total Logs Processed</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_alerts}</div>
                        <div class="stat-label">Total Alerts</div>
                    </div>
                    <div class="stat-card critical">
                        <div class="stat-number">{critical_count}</div>
                        <div class="stat-label">CRITICAL Alerts</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-number">{high_count}</div>
                        <div class="stat-label">HIGH Alerts</div>
                    </div>
                </div>
                
                <h3>Summary</h3>
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>Report Period</td>
                        <td>{datetime.now().strftime('%Y-%m-%d')}</td>
                    </tr>
                    <tr>
                        <td>Detection Rate</td>
                        <td>{(total_alerts/max(total_logs,1)*100):.2f}% of logs triggered alerts</td>
                    </tr>
                    <tr>
                        <td>Critical Issues</td>
                        <td>{critical_count} critical security events</td>
                    </tr>
                    <tr>
                        <td>Action Items</td>
                        <td>Review CRITICAL alerts immediately</td>
                    </tr>
                </table>
                
                <h3>Recommendations</h3>
                <ul>
                    <li>Review all CRITICAL alerts within 4 hours</li>
                    <li>Investigate HIGH severity events within 24 hours</li>
                    <li>Update security policies based on findings</li>
                    <li>Share report with security team</li>
                </ul>
                
                <div class="footer">
                    <strong>LogSentinel Pro v4.0</strong> | Security Operations Center<br>
                    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                    For questions contact: security@logsentinel.com
                </div>
            </div>
        </body>
        </html>
        """
        
        subject = f"📊 Security Report - {report_type.title()} ({datetime.now().strftime('%Y-%m-%d')})"
        
        return self._send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content
        )
    
    def send_login_alert(self,
                        to_email: str,
                        username: str,
                        form_name: str,
                        ip_address: str,
                        location: str,
                        device: str) -> Dict:
        """Send login notification alert."""
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
                .header {{ background: #28a745; color: white; padding: 20px; border-radius: 4px; margin-bottom: 20px; }}
                .info-box {{ background: #f0f8f0; border-left: 4px solid #28a745; padding: 15px; margin: 15px 0; border-radius: 4px; }}
                .info-row {{ padding: 8px 0; }}
                .info-label {{ font-weight: bold; color: #333; }}
                .info-value {{ font-family: monospace; color: #666; }}
                .footer {{ color: #666; font-size: 12px; margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Login Detected</h1>
                </div>
                
                <p>Hi {username},</p>
                <p>Someone just logged into your account. Here are the details:</p>
                
                <div class="info-box">
                    <div class="info-row">
                        <span class="info-label">Timestamp:</span><br>
                        <span class="info-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Form/Application:</span><br>
                        <span class="info-value">{form_name}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">IP Address:</span><br>
                        <span class="info-value">{ip_address}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Location:</span><br>
                        <span class="info-value">{location}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Device:</span><br>
                        <span class="info-value">{device}</span>
                    </div>
                </div>
                
                <p><strong>If this wasn't you:</strong></p>
                <ul>
                    <li>Change your password immediately</li>
                    <li>Review recent account activity</li>
                    <li>Contact support if you have concerns</li>
                </ul>
                
                <div class="footer">
                    <strong>LogSentinel Pro v4.0</strong> | Security Notifications<br>
                    This is an automated security notification.
                </div>
            </div>
        </body>
        </html>
        """
        
        subject = f"✅ New Login: {username} via {form_name}"
        
        return self._send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content
        )
    
    def _send_email(self, 
                   to_email: str,
                   subject: str,
                   html_content: str,
                   attachments: List[Dict] = None) -> Dict:
        """Internal method to send email via SMTP."""
        
        attachments = attachments or []
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.smtp_config.from_name} <{self.smtp_config.from_email}>"
            msg['To'] = to_email
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Add attachments
            for att in attachments:
                from email.mime.base import MIMEBase
                from email import encoders
                
                attachment = MIMEBase('application', 'octet-stream')
                attachment.set_payload(att['content'])
                encoders.encode_base64(attachment)
                attachment.add_header('Content-Disposition', 'attachment',
                                   filename=att['filename'])
                msg.attach(attachment)
            
            # Send email
            if self.smtp_config.port == 587:
                server = smtplib.SMTP(self.smtp_config.host, self.smtp_config.port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_config.host, self.smtp_config.port)
            
            server.login(self.smtp_config.user, self.smtp_config.password)
            server.send_message(msg)
            server.quit()
            
            result = {
                'success': True,
                'method': 'SMTP',
                'to_email': to_email,
                'subject': subject,
                'timestamp': datetime.now().isoformat()
            }
            
            self.alert_history.append(result)
            return result
            
        except Exception as e:
            error_msg = str(e)
            print(f"[!] SMTP error: {error_msg}")
            result = {
                'success': False,
                'method': 'SMTP',
                'error': error_msg,
                'to_email': to_email,
                'timestamp': datetime.now().isoformat()
            }
            
            self.alert_history.append(result)
            return result
    
    def get_history(self) -> List[Dict]:
        """Get email send history."""
        return self.alert_history


# Backwards compatibility alias
class SendGridEmailAlerter(EmailAlerter):
    """Backwards compatibility class - now uses SMTP only (SendGrid removed)."""
    
    def __init__(self, config=None, smtp_config=None):
        """Initialize with backwards compatibility."""
        # If config is passed but smtp_config isn't, treat config as smtp_config
        if config and not smtp_config:
            if hasattr(config, 'host'):  # It's an SMTPConfig
                smtp_config = config
            else:  # It's a SendGridConfig (legacy), ignore it
                print("[!] SendGrid config ignored - using SMTP only")
        
        if not smtp_config:
            raise ValueError("SMTP configuration required")
        
        super().__init__(smtp_config)
