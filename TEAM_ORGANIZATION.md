# GIRCOOL Project - Team Organization & Timeline
**Timeline: April 6, 2026 (11 AM) → April 7, 2026 (5 AM)**  
**Total Duration: 18 hours**

---

## Team Members & Assignments

### 1. **abhisekk-y** - Backend & Engines
**Branch:** `feature/backends-engines`

**Responsibilities:**
- Log analysis engines (`src/engines/`)
  - `advanced_detection.py`
  - `anomaly_detection_ml.py`
  - `live_log_analyzer.py`
  - `cve_analyzer.py`
  - `global_attack_recognizer.py`
- Configuration & Data Management
  - `config_manager.py`
  - Database utilities
- Email Alerting Systems
  - `sendgrid_alerter.py`
  - `smtp_alerter.py`
  - `telegram_alerter.py`

**Milestones:**
- Hour 0-3: Core engines tested & documented
- Hour 3-6: Alert systems integrated
- Hour 6-9: Error handling & logging finalized
- Hour 9+: Code review & cleanup

---

### 2. **Anurag Singh (anuragSingh2jz)** - CLI & Orchestration
**Branch:** `feature/cli-orchestration`

**Responsibilities:**
- Command-line interface
  - `src/cli/logsentinel_cli.py`
  - `src/cli/logsentinel_admin.py`
  - `tui_layout.py`
- Main entry point
  - `src/cli/logsentinel_main.py`
- Security Orchestration
  - `src/engines/security_orchestrator.py`
  - `integrated_attack_alerter.py`
- Attack Simulation & Testing
  - `scripts/attack_simulator.py`
  - Test scripts

**Milestones:**
- Hour 0-3: CLI interface structured & tested
- Hour 3-6: Security orchestrator integrated
- Hour 6-9: Attack simulation functional
- Hour 9+: End-to-end testing & validation

---

### 3. **Shubhanshu-ydv** - Dashboard & Frontend
**Branch:** `feature/dashboard-frontend`

**Responsibilities:**
- Web Dashboard & GUI
  - `src/gui/dashboard_server.py`
  - `src/gui/index.html`
  - `src/gui/premium_dashboard.html`
  - `src/gui/styles.css`
  - `src/gui/app.js`
  - `src/gui/login.html`
- Report Generation
  - `src/engines/live_report_generator.py`
  - `src/engines/pdf_reporter.py`
  - `src/engines/professional_pdf_reporter.py`
- Dashboard Launch
  - `src/gui/run_dashboard.bat`
  - `scripts/DASHBOARD_QUICKSTART.py`

**Milestones:**
- Hour 0-3: Dashboard UI responsive & styled
- Hour 3-6: Report generation working
- Hour 6-9: Authentication & security checks
- Hour 9+: Visual refinement & testing

---

## Git Flow Structure

```
main (production-ready)
├── develop (integration branch - DO NOT PUSH YET)
│   ├── feature/backends-engines (abhisekk-y)
│   ├── feature/cli-orchestration (Anurag Singh)
│   └── feature/dashboard-frontend (Shubhanshu-ydv)
```

---

## Timeline & Checkpoints

### April 6, 11:00 AM - Project Kickoff
- [ ] Each person creates their feature branch
- [ ] Initial work begins (3 hours)

### April 6, 2:00 PM - First Checkpoint (Hour 3)
- [ ] abhisekk-y: Engines running & documented
- [ ] Anurag Singh: CLI interface ready for integration
- [ ] Shubhanshu-ydv: Dashboard UI complete

### April 6, 5:00 PM - Integration Point (Hour 6)
- [ ] All components testable independently
- [ ] Integration testing begins
- [ ] Documentation updated

### April 6, 8:00 PM - Final Testing (Hour 9)
- [ ] End-to-end testing across all modules
- [ ] Bug fixes & cleanup
- [ ] Code review preparation

### April 7, 5:00 AM - Delivery Ready
- [ ] All code tested & documented
- [ ] Ready for final integration & teacher review

---

## Commit Strategy

**Each person:**
1. Works on their feature branch (`git checkout feature/YOUR-FEATURE`)
2. Makes regular atomic commits (1 feature = 1-3 commits)
3. Push commits when checkpoint is reached
4. **Main branch stays clean until final merge**

**Commit Message Format:**
```
[FEATURE-NAME] Brief description

- Detail 1
- Detail 2

Author: @username
Time: HH:MM on Apr 6/7
```

---

## Push Schedule (Show Teacher Progress)

**When to push to feature branches:**
- **Hour 3 (2:00 PM):** First push - basics working
- **Hour 6 (5:00 PM):** Integration push - components communicating
- **Hour 9 (8:00 PM):** Final push - ready for teacher review

**Final Merge to Main:**
- **April 7, 5:00 AM:** One person merges develop → main after all testing

---

## Files to NOT Modify
- `keys.csv`, `licenses.csv` (production data)
- `requirements.txt` (update only if adding new dependencies - discuss with team)
- `README.md` (update at end only)

---

## Success Criteria
✅ All 3 team members have visible commit history  
✅ Balanced contribution across features  
✅ Clean, organized Git history  
✅ Main branch has final working version  
✅ All modules integrated & tested  
✅ Teacher can see gradual progress in commit timeline
