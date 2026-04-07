@echo off
REM GIRCOOL Team Setup - Create feature branches
REM Run this ONCE before team members start working

echo ===== GIRCOOL Project - Git Flow Setup =====
echo.

REM Set up initial branches (only run once)
git branch develop
git branch feature/backends-engines
git branch feature/cli-orchestration
git branch feature/dashboard-frontend

echo.
echo ===== Branches Created =====
git branch -v

echo.
echo ===== Next Steps =====
echo.
echo Person 1 (abhisekk-y):
echo   git checkout feature/backends-engines
echo   Start working on: src/engines/
echo.
echo Person 2 (Anurag Singh - anuragSingh2jz):
echo   git checkout feature/cli-orchestration
echo   Start working on: src/cli/
echo.
echo Person 3 (Shubhanshu-ydv):
echo   git checkout feature/dashboard-frontend
echo   Start working on: src/gui/
echo.
echo See TEAM_ORGANIZATION.md for full details!
echo.
pause
