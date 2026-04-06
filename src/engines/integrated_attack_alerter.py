"""
Integrated Attack Alerter - Coordinates Telegram + Email + PDF Alerts
Handles multi-channel alert delivery with attack remediation
"""

import os
import threading
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Try to import alerter modules
try:
    from telegram_alerter import TelegramAlerter
except ImportError:
    TelegramAlerter = None

try:
    from sendgrid_alerter import EmailAlerter, SMTPConfig
except ImportError:
    EmailAlerter = None
    SMTPConfig = None

try:
    from pdf_reporter import PDFReporter
except ImportError:
    PDFReporter = None


class IntegratedAttackAlerter:
    """Coordinates multi-channel alert delivery"""
    
    def __init__(self):
        """Initialize alerter with all channels"""
        self.telegram_alerter = TelegramAlerter() if TelegramAlerter else None
        
        # Initialize email alerter with SMTP config
        self.email_alerter = None
        if EmailAlerter and SMTPConfig:
            try:
                smtp_config = SMTPConfig(
                    host=os.getenv('SMTP_HOST', 'smtp.gmail.com'),
                    port=int(os.getenv('SMTP_PORT', '587')),
                    user=os.getenv('SMTP_USER', ''),
                    password=os.getenv('SMTP_PASSWORD', ''),
                    from_email=os.getenv('SMTP_FROM_EMAIL', ''),
                    from_name='LogSentinel Pro Security'
                )
                self.email_alerter = EmailAlerter(smtp_config)
            except Exception as e:
                print(f"⚠️  Email alerter initialization failed: {e}")
                self.email_alerter = None
        
        self.pdf_reporter = PDFReporter() if PDFReporter else None
        
        self.remediation_map = {
            'BRUTE_FORCE': [
                'Enable account lockout after 5 failed attempts',
                'Require strong password policies (12+ chars, mixed case)',
                'Enable 2FA for all accounts',
                'Use fail2ban or similar to rate-limit login attempts',
                'Monitor SSH port (22) for unusual activity',
                'Consider moving SSH to non-standard port'
            ],
            'PORT_SCAN': [
                'Enable firewall to block unknown ports',
                'Close unnecessary open ports',
                'Implement IDS/IPS for anomaly detection',
                'Enable connection tracking',
                'Review and limit network exposure',
                'Segment network into security zones'
            ],
            'SQL_INJECTION': [
                'Use parameterized queries/prepared statements',
                'Validate and sanitize all user input',
                'Implement Web Application Firewall (WAF)',
                'Enable SQL error message suppression',
                'Implement principle of least privilege for DB accounts',
                'Conduct code review of affected endpoints'
            ],
            'DDOS': [
                'Contact ISP to activate DDoS mitigation',
                'Rate-limit requests at edge/firewall',
                'Implement CAPTCHA challenge for suspicious traffic',
                'Blacklist attacking IP ranges',
                'Increase bandwidth capacity or use CDN',
                'Configure traffic shaping for normal users'
            ],
            'MALWARE': [
                'Isolate affected system immediately',
                'Run full antivirus/anti-malware scan',
                'Check for persistence mechanisms (cron, registry)',
                'Review recent system changes and logs',
                'Consider full OS reinstall from clean media',
                'Update all security software'
            ],
            'UNAUTHORIZED_ACCESS': [
                'Terminate compromised user sessions',
                'Force password reset for affected accounts',
                'Audit sudo/admin logs for unauthorized actions',
                'Restore from clean backup if needed',
                'Review and tighten privilege escalation controls',
                'Enable privilege escalation monitoring'
            ],
            'DATA_EXFILTRATION': [
                'Isolate systems immediately',
                'Review outbound connections and logs',
                'Activate incident response team',
                'Notify affected users/regulators per compliance',
                'Identify and secure potentially stolen data',
                'Implement DLP (Data Loss Prevention) controls'
            ],
            'PRIVILEGE_ESCALATION': [
                'Verify account permissions and remove unnecessary privileges',
                'Update all systems to latest security patches',
                'Implement kernel hardening (SELinux/AppArmor)',
                'Enable privilege escalation monitoring',
                'Restrict sudo command usage',
                'Review user group memberships'
            ]
        }
    
    def send_attack_alert(self, attack_data: dict) -> dict:
        """
        Send attack alert via all channels
        
        Args:
            attack_data: Dict with keys: type, severity, source_ip, description, port
            
        Returns:
            Dict with delivery status for each channel
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_data.get('type', 'UNKNOWN'),
            'channels': {}
        }
        
        try:
            # 1. Send Telegram alert (instant)
            if self.telegram_alerter:
                try:
                    telegram_msg = self._format_telegram_message(attack_data)
                    self.telegram_alerter.send_alert(telegram_msg)
                    results['channels']['telegram'] = 'sent'
                    print(f"✅ Telegram alert sent for {attack_data.get('type')}")
                except Exception as e:
                    results['channels']['telegram'] = f'failed: {str(e)}'
                    print(f"❌ Telegram failed: {e}")
            
            # 2. Generate PDF report
            if self.pdf_reporter:
                try:
                    remediation = self._get_remediation(attack_data.get('type'))
                    recommendations = self._get_recommendations(attack_data)
                    
                    report_data = {
                        'attack_type': attack_data.get('type'),
                        'severity': attack_data.get('severity'),
                        'source_ip': attack_data.get('source_ip'),
                        'timestamp': datetime.now(),
                        'description': attack_data.get('description'),
                        'remediation_steps': remediation,
                        'recommendations': recommendations,
                        'metadata': attack_data
                    }
                    
                    # Create report file
                    report_path = self.pdf_reporter.generate_attack_report(report_data)
                    results['channels']['pdf'] = f'generated: {report_path}'
                    print(f"📄 PDF report generated: {report_path}")
                except Exception as e:
                    results['channels']['pdf'] = f'failed: {str(e)}'
                    print(f"❌ PDF generation failed: {e}")
            
            # 3. Send email with details
            if self.email_alerter:
                try:
                    remediation_text = '\n'.join(self._get_remediation(attack_data.get('type')))
                    
                    self.email_alerter.send_attack_alert(
                        to_email=os.getenv('SECURITY_ALERT_EMAIL', ''),
                        attack_name=attack_data.get('type', 'Unknown'),
                        severity=attack_data.get('severity', 'MEDIUM'),
                        description=attack_data.get('description', ''),
                        remediation=remediation_text,
                        source_ip=attack_data.get('source_ip', ''),
                        log_sample=str(attack_data),
                        confidence=0.95
                    )
                    results['channels']['email'] = 'sent'
                    print(f"✉️  Email alert sent for {attack_data.get('type')}")
                except Exception as e:
                    results['channels']['email'] = f'failed: {str(e)}'
                    print(f"❌ Email failed: {e}")
            
            results['status'] = 'success'
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            print(f"❌ Fatal error in alert delivery: {e}")
        
        return results
    
    def _format_telegram_message(self, attack_data: dict) -> str:
        """Format attack data for Telegram"""
        severity = attack_data.get('severity', 'UNKNOWN')
        attack_type = attack_data.get('type', 'UNKNOWN')
        source_ip = attack_data.get('source_ip', 'Unknown')
        description = attack_data.get('description', '')
        
        # Severity emoji
        emoji_map = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '📌',
            'LOW': 'ℹ️'
        }
        emoji = emoji_map.get(severity, '⚠️')
        
        message = f"""{emoji} *{severity}* - {attack_type}

*Source:* {source_ip}
*Type:* {attack_type}
*Description:* {description}
*Time:* {datetime.now().strftime('%H:%M:%S')}

🛡️ LogSentinel Pro - Real-Time Threat Detection
"""
        return message
    
    def _format_email_message(self, attack_data: dict) -> str:
        """Format attack data for email body"""
        msg = f"""
SECURITY ALERT - LogSentinel Pro
================================

Attack Type: {attack_data.get('type')}
Severity: {attack_data.get('severity')}
Source IP: {attack_data.get('source_ip')}
Port: {attack_data.get('port', 'Unknown')}
Timestamp: {datetime.now().isoformat()}

Description:
{attack_data.get('description')}

Remediation Steps:
{self._get_remediation_text(attack_data.get('type'))}

Recommendations:
{self._get_recommendations_text(attack_data)}

---
This is an automated alert from LogSentinel Pro
Please review the attached PDF report for detailed analysis
"""
        return msg
    
    def _get_remediation(self, attack_type: str) -> list:
        """Get remediation steps for attack type"""
        return self.remediation_map.get(attack_type, [
            'Review security logs',
            'Identify affected systems',
            'Isolate if necessary',
            'Deploy patches',
            'Monitor for recurrence',
            'Document incident'
        ])
    
    def _get_remediation_text(self, attack_type: str) -> str:
        """Get remediation as formatted text"""
        remediation = self._get_remediation(attack_type)
        return '\n'.join([f"{i+1}. {step}" for i, step in enumerate(remediation)])
    
    def _get_recommendations(self, attack_data: dict) -> list:
        """Get recommendations based on attack specifics"""
        attack_type = attack_data.get('type')
        source_ip = attack_data.get('source_ip')
        
        recommendations = [
            f'Block IP {source_ip} at firewall level',
            f'Increase monitoring for {attack_type} patterns',
            'Review similar historical incidents',
            'Update detection signatures',
            'Brief security team on findings',
            'Schedule follow-up scan after remediation'
        ]
        return recommendations
    
    def _get_recommendations_text(self, attack_data: dict) -> str:
        """Get recommendations as formatted text"""
        recommendations = self._get_recommendations(attack_data)
        return '\n'.join([f"• {rec}" for rec in recommendations])


def demo_attack_scenarios():
    """Demo attack scenarios for testing"""
    alerter = IntegratedAttackAlerter()
    
    demo_attacks = [
        {
            'type': 'BRUTE_FORCE',
            'severity': 'CRITICAL',
            'source_ip': '192.0.2.100',
            'port': 22,
            'description': 'SSH brute force attack - 25 failed login attempts in 30 seconds',
        },
        {
            'type': 'SQL_INJECTION',
            'severity': 'CRITICAL',
            'source_ip': '198.51.100.78',
            'port': 443,
            'description': 'SQL injection in login endpoint - UNION-based attack detected',
        },
        {
            'type': 'PORT_SCAN',
            'severity': 'HIGH',
            'source_ip': '203.0.113.45',
            'description': 'Network reconnaissance - 256 ports scanned in 10 seconds',
        }
    ]
    
    print("\n" + "="*80)
    print("🎯 IntegratedAttackAlerter - Demo Scenario")
    print("="*80 + "\n")
    
    for attack in demo_attacks:
        print(f"\n📤 Sending {attack['type']} alert...")
        result = alerter.send_attack_alert(attack)
        print(f"   Result: {result}")
        print()


if __name__ == "__main__":
    demo_attack_scenarios()
