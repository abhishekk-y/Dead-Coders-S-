# Shubhanshu-ydv - Dashboard & Frontend Setup Guide

## Your Assignment
You are responsible for the **web dashboard, frontend UI, and report generation**.

## Quick Start (April 6, 11:00 AM)

### Step 1: Switch to Your Branch
```powershell
git checkout feature/dashboard-frontend
```

### Step 2: Set Your Git Config (First Time Only)
```powershell
git config user.name "Shubhanshu-ydv"
git config user.email "shubhanshu-ydv@gircool.dev"
```

### Step 3: Start Working
Your files are in:
- `src/gui/` - All frontend UI and styling
- `src/engines/pdf_reporter.py` - Report generation
- `scripts/DASHBOARD_QUICKSTART.py` - Dashboard setup

## Files You Own
```
src/gui/
├── index.html               (main dashboard page)
├── premium_dashboard.html   (premium features)
├── login.html               (authentication page)
├── styles.css               (all styling)
├── app.js                   (frontend JavaScript)
├── dashboard_server.py      (Flask/Django backend)
├── server.py                (alternative server)
└── run_dashboard.bat        (launcher script)

src/engines/
├── pdf_reporter.py          (your responsibility)
├── professional_pdf_reporter.py
└── live_report_generator.py

scripts/
└── DASHBOARD_QUICKSTART.py  (your responsibility)
```

## Commit Pattern
Make commits as you complete features:

```powershell
# After styling the dashboard
git add src/gui/styles.css src/gui/index.html
git commit -m "[DASHBOARD-UI] Premium dashboard layout and responsive styling

- Mobile-responsive design
- Dark/light theme support
- Real-time alert visualization
- Performance optimized CSS

Author: @Shubhanshu-ydv
Time: 2:00 PM on Apr 6"
```

## Checkpoints (When to Push)
- **Hour 3 (2:00 PM)**: `git push origin feature/dashboard-frontend`
  - Dashboard UI responsive and styled
  - Login page working
  
- **Hour 6 (5:00 PM)**: `git push origin feature/dashboard-frontend`
  - Reports generating in PDF format
  - Dashboard displays data from APIs
  
- **Hour 9 (8:00 PM)**: `git push origin feature/dashboard-frontend`
  - Full UI tested and refined
  - All visual bugs fixed

## Testing Your Code
```powershell
# Start dashboard server
cd src/gui
python dashboard_server.py
# Visit http://localhost:5000

# Test report generation
python ../engines/pdf_reporter.py

# Test quick start
python ../../scripts/DASHBOARD_QUICKSTART.py
```

## Frontend Technologies
- **HTML**: Structure and layout
- **CSS**: Styling and responsiveness (`styles.css`)
- **JavaScript**: `app.js` for interactivity
- **Python**: `dashboard_server.py` for backend

## Integration Points
- **With abhisekk-y**: Your dashboard DISPLAYS their alerts
  - Listen to alert events via WebSocket or polling
  - Format data from `/api/profile` endpoint

- **With Anurag Singh**: Your dashboard RECEIVES data from his CLI
  - Consume JSON outputs from orchestrator
  - Real-time refresh of log data

## API Endpoints You Need to Use
```python
# From config_manager.py
config.get('dashboard_port')
config.get('alert_webhook_url')
config.get('report_output_dir')
```

## Frontend Best Practices
✓ Responsive design (works on desktop, tablet, mobile)  
✓ Dark theme for night monitoring  
✓ Real-time updates without page reload  
✓ Clear visual hierarchy for alerts  
✓ Professional styling

## DO NOT
❌ Commit to `main` branch  
❌ Commit to `develop` branch  
❌ Modify other people's files  
❌ Hard-code server/API URLs (use config file)

---

**Good luck! Beautiful UI = Happy presentation! 🚀**
