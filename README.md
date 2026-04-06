# LogSentinel Pro v3.0 — Enterprise SIEM Platform

🛡️ **Advanced Python-based Enterprise SIEM** with ML-powered threat detection, professional PDF reporting, and interactive command-line interfaces. A comprehensive security platform featuring premium threat intelligence, behavioral analysis, and enterprise-grade compliance reporting.

---

## 🏗️ Platform Architecture

The platform implements a sophisticated multi-layered security architecture:

1. **🔐 Enterprise Authentication**: Device-bound licensing with SHA-256 fingerprinting and session persistence
2. **🧠 ML Threat Detection**: Behavioral baseline learning with MITRE ATT&CK technique mapping  
3. **📊 Professional Reporting**: ReportLab-powered PDF generation with executive summaries and risk visualizations
4. **🔍 Advanced Analytics**: Real-time threat intelligence with custom IOC management
5. **⚙️ Configuration Management**: Dynamic rule engine with threshold-based alerting
6. **🔗 Blockchain Integrity**: SHA-256 audit ledger for tamper-evident log verification
7. **🎯 Interactive CLI**: Rich-powered terminal interfaces with animated progress and real-time status
8. **📋 Compliance Frameworks**: SOX, PCI-DSS, HIPAA, and ISO27001 assessment reporting

## 🎯 Premium Features

| Feature | Technology | Description |
|---------|-----------|-------------|
| **🔐 Device-Bound Licensing** | SHA-256 Fingerprinting | Hardware-locked license keys with one-time activation |
| **🧠 ML Threat Detection** | scikit-learn + Advanced Algorithms | Behavioral baseline learning with anomaly scoring |
| **📊 Professional PDF Reports** | ReportLab + matplotlib | Executive summaries with risk gauges and compliance assessments |
| **🎨 Rich Interactive CLI** | Rich Terminal Framework | Animated banners, progress bars, and real-time status displays |
| **🔍 Threat Intelligence** | Custom IOC Database | 50,000+ indicators with MITRE ATT&CK technique mapping |
| **⚙️ Dynamic Configuration** | JSON Rule Engine | Live threshold management with custom detection rules |
| **🔗 Blockchain Verification** | SHA-256 Proof-of-Work | Tamper-evident audit ledger for log integrity |
| **📋 Compliance Reporting** | Multi-Framework Support | SOX, PCI-DSS, HIPAA, ISO27001 assessment templates |
| **🎯 Advanced Analytics** | Statistical Analysis | Threat trend analysis with dashboard visualization |
| **🔒 Enterprise Authentication** | Session Management | Persistent login with organizational binding |
| **📄 Multi-Format Export** | JSON/PDF/TXT | STIX 2.1 bundles and professional report generation |

## 📁 Project Structure

```
LogSentinel-Pro/
├── README.md                        # Project documentation (You are here)
├── SDC.md                           # Software Development Context (Issues, Arch, Lifecycle)
├── requirements.txt                 # Core Python dependencies
├── .env.example                     # Example environment variables template
├── .gitignore                       # Ignored system and environment files
├── logsentinel                      # Main SIEM CLI executable
├── logsentinel-admin                # Admin license management CLI
├── src/                             # Core Application Source Code
│   ├── cli/                         # CLI entry points and admin consoles
│   └── engines/                     # ML logic, config, parse, alert engines
├── docs/                            # Comprehensive documentation and guides
├── tests/                           # Unit and integration test suite
├── scripts/                         # Standalone execution and simulation scripts
├── sample_reports/                  # Generated compliance PDF and JSON examples
└── assets/                          # UI Assets and dependencies
```

> **🔒 Note on Environment Variables**: To keep security protocols intact, the actual `.env` configuration file is **hidden** and completely ignored via git. Developers must use `.env.example` as a template to structure their local tokens (SendGrid, Telegram, Webhooks).

## 🚨 Active Alert System

The SIEM leverages a multi-threaded asynchronous alert pipeline optimized for preventing blocks:
- **Telegram Bot Integration (`telegram_alerter.py`)**:
  - Automatically captures critical threat logs and forwards them to a configured Telegram Chat via a secure Bot Token.
  - Formats alerts into highly readable markdown cards highlighting the **Attacker IP**, **Severity**, **MITRE ATT&CK Technique**, and **Detection Time**.
  - Rate-limits itself dynamically to prevent API bans during high-volume DDoS attempts.
- **SendGrid Email Alerter**: Batched HTML summaries summarizing compliance risk and system health over long aggregation periods.
- **Debouncing Engine**: Prevents alert fatigue and spam by thresholding identical grouped events across configured intervals.

## 📓 Software Development Context (SDC)

For a complete look into LogSentinel Pro's development life cycle—the scalability boundaries we passed, the architecture decisions we forged, and the issues we successfully mitigated—please read our [Software Development Context (SDC.md)](SDC.md) document.

## 🚀 Quick Start


### Prerequisites
- **Python 3.8+**: Core platform runtime
- **Virtual Environment**: `python3 -venv venv_premium`
- **ML Dependencies**: `pip install scikit-learn numpy pandas`
- **PDF Generation**: `pip install reportlab matplotlib Pillow`
- **Rich Terminal**: `pip install rich`

### Installation & Setup
```bash
# Clone and navigate
cd LogSentinel-Pro

# Create virtual environment (if not exists)
python3 -m venv venv_premium
source venv_premium/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make executables available
chmod +x logsentinel logsentinel-admin
```

### First Launch
```bash
# Start main SIEM platform
./logsentinel

# Or start admin console
./logsentinel-admin
```

> **🔑 License Required**: First run requires a license key. Use the admin console to generate keys or contact your administrator.

## 💻 Command Usage

### Main SIEM Platform
```bash
# Interactive mode (recommended)
./logsentinel

# Direct commands
./logsentinel scan /var/log/auth.log              # Threat analysis
./logsentinel scan /var/log/auth.log -v -r        # Verbose with report
./logsentinel report /var/log/auth.log            # Generate PDF report
./logsentinel report data.json --compliance PCI-DSS # Compliance report
./logsentinel settings --show                     # View configuration
./logsentinel analytics --dashboard               # Threat dashboard
./logsentinel blockchain --verify                 # Verify log integrity
```

### Premium Features
```bash
# Professional PDF Reports
./logsentinel report /var/log/auth.log --compliance SOX
./logsentinel report scan_results.json --format executive

# Configuration Management  
./logsentinel settings --export config.json
./logsentinel settings --import config.json

# Threat Intelligence
./logsentinel analytics --iocs                    # Manage custom IOCs
./logsentinel analytics --trends                  # Show threat trends
```

### Admin Console
```bash
# License Management
./logsentinel-admin generate                      # Create license key
./logsentinel-admin list                          # Show all licenses
./logsentinel-admin stats                         # License statistics
./logsentinel-admin audit                         # View access logs
./logsentinel-admin revoke <key>                  # Revoke license
```

## 🥷 Live Demonstration (Kali Linux vs LogSentinel Pro)

To prove the efficacy of the ML-threat modeling and the Telegram Alert System, run a live penetration testing simulation:

1. **Start the SIEM Listener**: On your defense machine (running LogSentinel Pro), initialize the interactive monitor and dashboard:
   ```bash
   python scripts/setup_dashboard.py
   ```
2. **Execute an Attack from Kali Linux**: Switch to your offensive Kali machine. Fire a simulated brute-force or SQLi payload against the defense machine:
   ```bash
   # Example: Hydra SSH Brute-Force
   hydra -l root -P rockyou.txt ssh://<LogSentinel-IP>
   
   # Example: NMAP Aggressive Scan
   nmap -A -T4 <LogSentinel-IP>
   ```
3. **Observe the Detection**: 
   - The ML-engine will instantly recognize behavioral signature deviations.
   - The terminal UI will flash **🔴 CRITICAL THREAT DETECTED**.
   - Your configured **Telegram Bot** will vibrate your phone with an exact breakdown of the attack type (e.g., *MITRE T1110: Brute Force*), origin IP, and severity.
   - Review `/sample_reports` for a newly auto-generated PDF detailing the attack sequence.

## 🎨 Interface Design

The platform features a professional dark theme with Rich terminal framework:

| Element | Style | Purpose |
|---------|-------|---------|
| **Animated Banners** | ASCII Art + Colors | Professional branding and status |
| **Progress Bars** | Multi-stage Animations | Real-time operation feedback |
| **Status Panels** | Bordered Rich Tables | License status and system info |
| **Interactive Menus** | Colored Command Lists | Premium feature navigation |
| **Risk Gauges** | matplotlib Charts | Visual risk assessment in PDFs |
| **Color Coding** | Threat Level Indicators | Red (critical), Yellow (warning), Green (safe) |

## 🔒 Security Architecture

### Authentication System
- **Device Fingerprinting**: SHA-256 hash of hardware identifiers
- **One-Time Keys**: License keys work only on registered devices  
- **Session Persistence**: Encrypted local session storage
- **Audit Trail**: Complete access logging and failed attempt tracking

### Threat Detection
- **Behavioral Baselines**: ML learning of normal system patterns
- **IOC Database**: 50,000+ threat indicators from security feeds
- **MITRE ATT&CK**: Technique mapping and attack chain analysis
- **Anomaly Scoring**: Statistical deviation detection with risk scoring

### Data Integrity
- **Blockchain Ledger**: SHA-256 proof-of-work for tamper detection
- **Hash Verification**: File integrity checking with cryptographic proofs
- **Audit Logs**: Immutable record of all system operations

## 📊 Reporting Capabilities

### Professional PDF Reports
- **Executive Summary**: High-level risk assessment for management
- **Technical Analysis**: Detailed findings with remediation steps
- **Risk Gauges**: Visual risk scoring with matplotlib charts
- **Compliance Assessment**: Framework-specific evaluation reports

### Supported Formats
- **PDF Reports**: Professional layouts with charts and branding
- **JSON Export**: STIX 2.1 compatible threat intelligence bundles
- **CSV Data**: Statistical exports for analysis tools
- **Text Summaries**: Command-line friendly output formats

## 🔧 Configuration

The platform uses a dynamic JSON-based configuration system:

```json
{
  "detection_rules": {
    "failed_logins": {"threshold": 5, "window": "5m"},
    "privilege_escalation": {"enabled": true, "severity": "high"},
    "suspicious_processes": {"patterns": [".*\\.tmp\\.exe$"]}
  },
  "thresholds": {
    "risk_score": {"low": 30, "medium": 60, "high": 85},
    "alert_frequency": {"max_per_hour": 50}
  },
  "integrations": {
    "syslog_server": "localhost:514",
    "webhook_url": "https://alerts.company.com/webhook"
  }
}
```

## 🎯 Use Cases

### Enterprise Security Operations
- **SOC Analysis**: Real-time threat hunting and incident response
- **Compliance Auditing**: Automated assessment against regulatory frameworks
- **Executive Reporting**: Professional risk communication to leadership
- **Threat Intelligence**: Integration with external IOC feeds and databases

### Security Research
- **Attack Pattern Analysis**: MITRE ATT&CK technique identification  
- **Behavioral Modeling**: ML-based anomaly detection research
- **Log Forensics**: Deep investigation of security incidents
- **Threat Hunting**: Proactive search for advanced persistent threats

## 📈 Performance Metrics

The platform has been tested and optimized for enterprise environments:

- **Log Processing**: 10,000+ events per minute
- **ML Analysis**: Real-time behavioral scoring
- **PDF Generation**: Executive reports in under 30 seconds
- **Memory Usage**: Optimized for long-running operations
- **Scalability**: Supports multi-gigabyte log files

## 🤝 Contributing

LogSentinel Pro is designed as an enterprise-grade security platform. For feature requests, security issues, or integration support:

1. **Security Issues**: Report privately to maintain responsible disclosure
2. **Feature Requests**: Focus on enterprise security operations requirements
3. **Integration**: API-first design supports custom threat intelligence feeds
4. **Documentation**: Comprehensive inline help and interactive guidance

## 📋 License

This software requires a valid enterprise license key for operation. Contact your system administrator or security team for access credentials.

---

**🛡️ LogSentinel Pro** - Advanced Enterprise SIEM Platform  
*Powered by Machine Learning • Professional PDF Reporting • Interactive CLI*
