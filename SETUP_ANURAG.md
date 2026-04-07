# Anurag Singh (anuragSingh2jz) - CLI & Orchestration Setup Guide

## Your Assignment
You are responsible for the **command-line interface and security orchestration**.

## Quick Start (April 6, 11:00 AM)

### Step 1: Switch to Your Branch
```powershell
git checkout feature/cli-orchestration
```

### Step 2: Set Your Git Config (First Time Only)
```powershell
git config user.name "Anurag Singh"
git config user.email "anuragSingh2jz@gircool.dev"
```

### Step 3: Start Working
Your files are in:
- `src/cli/` - Command-line interface
- `src/engines/security_orchestrator.py` - Orchestration logic
- `scripts/` - Testing and simulation scripts

## Files You Own
```
src/cli/
├── logsentinel_cli.py          (main CLI)
├── logsentinel_admin.py        (admin commands)
├── logsentinel_main.py         (entry point)
└── tui_layout.py               (terminal UI)

src/engines/
├── security_orchestrator.py    (your responsibility)
└── integrated_attack_alerter.py

scripts/
├── attack_simulator.py         (your responsibility)
├── integration_examples.py
└── examples_integration_demo.py
```

## Commit Pattern
Make commits as you complete features:

```powershell
# After building CLI interface
git add src/cli/logsentiel_cli.py
git commit -m "[CLI-INTERFACE] Command-line interface with argument parsing

- Main menu with logging commands
- User input validation
- Integration with backend engines
- Help documentation

Author: @anuragSingh2jz
Time: 1:45 PM on Apr 6"
```

## Checkpoints (When to Push)
- **Hour 3 (2:00 PM)**: `git push origin feature/cli-orchestration`
  - CLI commands working
  - Can run basic operations
  
- **Hour 6 (5:00 PM)**: `git push origin feature/cli-orchestration`
  - Security orchestrator integrated
  - Attack simulator functional
  
- **Hour 9 (8:00 PM)**: `git push origin feature/cli-orchestration`
  - Full end-to-end testing completed

## Testing Your Code
```powershell
# Test CLI
python src/cli/logsentinel_cli.py --help

# Test attack simulator
python scripts/attack_simulator.py

# Show your work is complete
python src/cli/logsentinel_main.py
```

## Integration Points
- **With abhisekk-y**: Your CLI CALLS their engines
  - Import and call: `advanced_detection()`, `anomaly_detector()`, etc.
  - Make sure error handling is robust!

- **With Shubhanshu-ydv**: Your CLI data feeds the dashboard
  - Make sure outputs are in JSON format when needed
  - Document your data structures

## Important: Test Integration
Coordinate with the team around Hour 6 to make sure:
1. CLI calls backends properly
2. Data flows to dashboard correctly
3. Alerts trigger through the orchestrator

## DO NOT
❌ Commit to `main` branch  
❌ Commit to `develop` branch  
❌ Modify other people's files  
❌ Hard-code server addresses (use config_manager)

---

**Good luck! Clean code = Happy review! 🚀**
