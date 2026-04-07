# abhisekk-y - Backend & Engines Setup Guide

## Your Assignment
You are responsible for the **backend engines and detection systems**.

## Quick Start (April 6, 11:00 AM)

### Step 1: Switch to Your Branch
```powershell
git checkout feature/backends-engines
```

### Step 2: Set Your Git Config (First Time Only)
```powershell
git config user.name "abhisekk-y"
git config user.email "abhisekk-y@gircool.dev"
```

### Step 3: Start Working
Your files are in:
- `src/engines/` - All detection/analysis engines
- `src/engines/sendgrid_alerter.py` - Email alerts
- `src/engines/smtp_alerter.py` - SMTP alerts
- `src/engines/telegram_alerter.py` - Telegram alerts

## Files You Own
```
src/engines/
├── advanced_detection.py
├── anomaly_detection_ml.py
├── anomaly_detector_advanced.py
├── live_log_analyzer.py
├── cve_analyzer.py
├── global_attack_recognizer.py
├── config_manager.py
├── sendgrid_alerter.py
├── smtp_alerter.py
├── telegram_alerter.py
├── alert_manager.py
└── integrated_attack_alerter.py
```

## Commit Pattern
Make commits as you complete features:

```powershell
# After finishing detection engine
git add src/engines/advanced_detection.py
git commit -m "[BACKEND-ENGINE] Advanced detection system implemented

- Pattern matching for attack signatures
- Real-time log analysis
- Performance optimizations

Author: @abhisekk-y
Time: 1:30 PM on Apr 6"
```

## Checkpoints (When to Push)
- **Hour 3 (2:00 PM)**: `git push origin feature/backends-engines`
  - Engines running and tested
  
- **Hour 6 (5:00 PM)**: `git push origin feature/backends-engines`
  - All alerts working
  
- **Hour 9 (8:00 PM)**: `git push origin feature/backends-engines`
  - Final version with error handling

## Testing Your Code
```powershell
cd src/engines
python -m pytest  # if you add tests
python advanced_detection.py  # test manually
```

## Integrate with Others
- Anurag's CLI will CALL your engines
- Shubhanshu's dashboard will DISPLAY alerts from your engines
- Make sure functions are well-documented!

## Need to Update requirements.txt?
Only if you add new Python packages. Discuss with team first!

```powershell
pip freeze > requirements_new.txt
# Review and only add your new packages to requirements.txt
```

## DO NOT
❌ Commit to `main` branch  
❌ Commit to `develop` branch  
❌ Modify other people's files  
❌ Push production data (keys.csv, licenses.csv)

---

**Good luck! Remember: Clean commits = Happy teacher! 🚀**
