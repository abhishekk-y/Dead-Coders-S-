#!/usr/bin/env python3
"""
LogSentinel Pro — SMTP Email Alerter
Uses Python built-in smtplib — no SendGrid dependency needed.
Supports Gmail, Outlook, Yahoo, or any custom SMTP server.
"""

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load .env from clone_layout dir
env_path = Path(__file__).parent.parent.parent.parent.parent / "clone_layout" / ".env"
if not env_path.exists():
    env_path = Path(__file__).parent / ".env"
load_dotenv(env_path, override=False)

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)
SMTP_TO   = os.environ.get("ALERT_TARGET_EMAIL", "")


def _send_raw(subject: str, html_body: str, to_email: str = None) -> dict:
    """Core SMTP send function."""
    to = to_email or SMTP_TO
    if not SMTP_USER or not SMTP_PASS or not to:
        return {"success": False, "error": "SMTP credentials not configured in .env"}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"LogSentinel Pro <{SMTP_FROM}>"
    msg["To"]      = to
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, [to], msg.as_string())
        return {"success": True, "to": to, "subject": subject, "timestamp": datetime.now().isoformat()}
    except Exception as e:
        return {"success": False, "error": str(e), "timestamp": datetime.now().isoformat()}


def send_attack_alert(attack_name: str, severity: str, description: str,
                      source_ip: str, remediation: str, log_sample: str = "",
                      cve_ids: list = None, confidence: float = 0.95,
                      to_email: str = None) -> dict:
    """Send critical attack alert email."""
    color = {"CRITICAL": "#dc3545", "HIGH": "#ff6b35", "MEDIUM": "#ffc107"}.get(severity, "#6c757d")
    cve_section = f"<p><strong>CVE References:</strong> {', '.join(cve_ids)}</p>" if cve_ids else ""

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0d0e12;color:#e0e0e0;padding:20px">
    <div style="max-width:600px;margin:0 auto;background:#1a1b21;border-radius:8px;overflow:hidden;border:1px solid #2a2b31">
      <div style="background:{color};padding:20px">
        <h1 style="margin:0;color:white;font-size:22px">🚨 {severity} Security Alert</h1>
        <p style="margin:5px 0 0;color:rgba(255,255,255,0.8)">{attack_name}</p>
      </div>
      <div style="padding:20px">
        <table style="width:100%;border-collapse:collapse;margin-bottom:16px">
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Severity</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31;font-weight:bold;color:{color}">{severity}</td></tr>
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Source IP</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31;font-family:monospace;color:#14b8a6">{source_ip}</td></tr>
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Confidence</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31">{confidence*100:.0f}%</td></tr>
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Time</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
        </table>
        <div style="background:#14151a;border-radius:6px;padding:14px;margin-bottom:14px">
          <strong style="color:#888;text-transform:uppercase;font-size:11px">Description</strong>
          <p style="margin:6px 0 0;color:#ccc">{description}</p>
        </div>
        {cve_section}
        <div style="background:#14151a;border-left:4px solid {color};border-radius:4px;padding:14px;margin-bottom:14px">
          <strong style="color:#888;text-transform:uppercase;font-size:11px">🛡️ Recommended Action</strong>
          <p style="margin:6px 0 0;color:#ccc">{remediation}</p>
        </div>
        {f'<div style="background:#0d0e12;border-radius:4px;padding:12px;margin-bottom:14px"><code style="font-size:12px;color:#aaa">{log_sample[:300]}</code></div>' if log_sample else ''}
        <div style="border-top:1px solid #2a2b31;padding-top:14px;color:#666;font-size:12px">
          LogSentinel Pro v4.0 — Automated Security Alert · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
        </div>
      </div>
    </div></body></html>"""

    subject = f"🚨 [{severity}] {attack_name} — Immediate Action Required"
    return _send_raw(subject, html, to_email)


def send_anomaly_alert(metric_name: str, current_value: float, baseline_value: float,
                       anomaly_score: float, severity: str, explanation: str,
                       to_email: str = None) -> dict:
    """Send ML anomaly detection email."""
    dev_pct = ((current_value - baseline_value) / max(baseline_value, 0.001)) * 100
    color   = "#ff6b35"

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0d0e12;color:#e0e0e0;padding:20px">
    <div style="max-width:600px;margin:0 auto;background:#1a1b21;border-radius:8px;overflow:hidden;border:1px solid #2a2b31">
      <div style="background:{color};padding:20px">
        <h1 style="margin:0;color:white;font-size:22px">⚠️ ML Anomaly Detected</h1>
        <p style="margin:5px 0 0;color:rgba(255,255,255,0.8)">{metric_name}</p>
      </div>
      <div style="padding:20px">
        <table style="width:100%;border-collapse:collapse;margin-bottom:16px">
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Metric</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31;font-family:monospace">{metric_name}</td></tr>
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Current Value</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31;color:#f43f5e;font-weight:bold">{current_value:,.2f}</td></tr>
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Baseline</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31">{baseline_value:,.2f}</td></tr>
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Deviation</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31;color:#f43f5e;font-weight:bold">{dev_pct:+.1f}%</td></tr>
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Anomaly Score</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31">{anomaly_score:.1f} / 100</td></tr>
          <tr><td style="padding:8px;border-bottom:1px solid #2a2b31;color:#888">Severity</td>
              <td style="padding:8px;border-bottom:1px solid #2a2b31;font-weight:bold;color:{color}">{severity}</td></tr>
        </table>
        <div style="background:#14151a;border-radius:6px;padding:14px;margin-bottom:14px">
          <strong style="color:#888;text-transform:uppercase;font-size:11px">Analysis</strong>
          <p style="margin:6px 0 0;color:#ccc">{explanation}</p>
        </div>
        <div style="border-top:1px solid #2a2b31;padding-top:14px;color:#666;font-size:12px">
          LogSentinel Pro v4.0 — ML Anomaly Detection · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
        </div>
      </div>
    </div></body></html>"""

    return _send_raw(f"⚠️ [{severity}] Anomaly Detected: {metric_name}", html, to_email)


def send_security_report(report_type: str, total_logs: int, total_alerts: int,
                         critical_count: int, high_count: int,
                         to_email: str = None) -> dict:
    """Send a structured security report email."""
    rate = (total_alerts / max(total_logs, 1)) * 100

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0d0e12;color:#e0e0e0;padding:20px">
    <div style="max-width:650px;margin:0 auto;background:#1a1b21;border-radius:8px;overflow:hidden;border:1px solid #2a2b31">
      <div style="background:linear-gradient(135deg,#1d4ed8,#7c3aed);padding:24px">
        <h1 style="margin:0;color:white;font-size:24px">📊 Security Report: {report_type}</h1>
        <p style="margin:6px 0 0;color:rgba(255,255,255,0.7)">{datetime.now().strftime('%Y-%m-%d')}</p>
      </div>
      <div style="padding:20px">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
          <div style="background:#14151a;border-radius:6px;padding:16px;border-left:4px solid #3b82f6">
            <div style="font-size:28px;font-weight:bold;color:#3b82f6">{total_logs:,}</div>
            <div style="font-size:11px;color:#666;margin-top:4px;text-transform:uppercase">Logs Processed</div>
          </div>
          <div style="background:#14151a;border-radius:6px;padding:16px;border-left:4px solid #f59e0b">
            <div style="font-size:28px;font-weight:bold;color:#f59e0b">{total_alerts}</div>
            <div style="font-size:11px;color:#666;margin-top:4px;text-transform:uppercase">Total Alerts</div>
          </div>
          <div style="background:#14151a;border-radius:6px;padding:16px;border-left:4px solid #dc3545">
            <div style="font-size:28px;font-weight:bold;color:#dc3545">{critical_count}</div>
            <div style="font-size:11px;color:#666;margin-top:4px;text-transform:uppercase">CRITICAL Events</div>
          </div>
          <div style="background:#14151a;border-radius:6px;padding:16px;border-left:4px solid #ff6b35">
            <div style="font-size:28px;font-weight:bold;color:#ff6b35">{high_count}</div>
            <div style="font-size:11px;color:#666;margin-top:4px;text-transform:uppercase">HIGH Events</div>
          </div>
        </div>
        <div style="background:#14151a;border-radius:6px;padding:14px;margin-bottom:14px">
          <p style="margin:0;color:#888;font-size:12px">
            📈 Detection rate: <strong style="color:#ccc">{rate:.3f}%</strong> of traffic triggered alerts.
            {critical_count} critical events require immediate action.
          </p>
        </div>
        <div style="border-top:1px solid #2a2b31;padding-top:14px;color:#666;font-size:12px">
          LogSentinel Pro v4.0 — Automated Security Report · Powered by Dead Coder Society
        </div>
      </div>
    </div></body></html>"""

    return _send_raw(f"📊 Security Report — {report_type} ({datetime.now().strftime('%Y-%m-%d')})", html, to_email)
