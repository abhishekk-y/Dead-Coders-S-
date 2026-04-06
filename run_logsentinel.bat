@echo off
echo Starting LogSentinel Pro v4.0 - Enterprise SIEM (Industry Share Edition)
echo.

:: Check for Python
py --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python 'py' command not found. Trying 'python'...
    python --version >nul 2>&1
    IF %ERRORLEVEL% NEQ 0 (
        echo ERROR: Python is not installed or not in PATH. Please install Python 3.8+ to continue.
        pause
        exit /b 1
    ) ELSE (
        set PYTHON_CMD=python
    )
) ELSE (
    set PYTHON_CMD=py
)

echo ========================================================
echo   LogSentinel Pro v4.0.0 - Enterprise SIEM Suite
echo ========================================================
echo.
echo  [1] Launch Interactive TUI (70/30 Split-Screen)
echo  [2] Launch Enterprise Web GUI (SolarWinds Dashboard)
echo  [3] Launch Admin Console (License Management)
echo  [4] Exit
echo.
set /p choice="Enter Selection (1-4): "

if "%choice%"=="1" (
    %PYTHON_CMD% src\cli\logsentinel_main.py
) else if "%choice%"=="2" (
    echo Starting Web Server...
    start http://localhost:8080/login.html
    %PYTHON_CMD% src\gui\server.py
) else if "%choice%"=="3" (
    %PYTHON_CMD% src\cli\logsentinel_admin.py
) else (
    exit /b 0
)

pause
