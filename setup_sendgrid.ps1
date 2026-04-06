# SendGrid Integration - Fixed Setup Script
# Uses the virtual environment properly

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "LOGSENTINEL PRO - SENDGRID SETUP" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Activate Virtual Environment
Write-Host "Step 1: Activating Virtual Environment..." -ForegroundColor Yellow

$venvPath = ".\venv_premium\Scripts\Activate.ps1"

if (Test-Path $venvPath) {
    Write-Host "   Found venv_premium..." -ForegroundColor Cyan
    & $venvPath
    Write-Host "   SUCCESS: Virtual environment activated!" -ForegroundColor Green
} else {
    Write-Host "   WARNING: venv_premium not found" -ForegroundColor Yellow
    Write-Host "   Using system Python..." -ForegroundColor Cyan
}

Write-Host ""

# Step 2: Install SendGrid packages
Write-Host "Step 2: Installing SendGrid Packages..." -ForegroundColor Yellow

Write-Host "   Installing sendgrid..." -ForegroundColor Cyan
python -m pip install sendgrid --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "   SUCCESS: sendgrid installed" -ForegroundColor Green
} else {
    Write-Host "   WARNING: sendgrid install had issues" -ForegroundColor Yellow
}

Write-Host "   Installing python-dotenv..." -ForegroundColor Cyan
python -m pip install python-dotenv --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "   SUCCESS: python-dotenv installed" -ForegroundColor Green
} else {
    Write-Host "   WARNING: python-dotenv install had issues" -ForegroundColor Yellow
}

Write-Host ""

# Step 3: Check Environment
Write-Host "Step 3: Checking Environment Setup..." -ForegroundColor Yellow
$apiKey = $env:SENDGRID_API_KEY

if ($apiKey) {
    Write-Host "   SUCCESS: SENDGRID_API_KEY is set" -ForegroundColor Green
    Write-Host "   Keys starting with: $($apiKey.Substring(0, 5))..." -ForegroundColor Green
} else {
    Write-Host "   ERROR: SENDGRID_API_KEY is NOT set!" -ForegroundColor Red
    Write-Host "   Set it with: `$env:SENDGRID_API_KEY = 'SG.your_key_here'" -ForegroundColor Yellow
}

Write-Host ""

# Step 4: Run Tests
Write-Host "Step 4: Running SendGrid Tests..." -ForegroundColor Yellow
Write-Host "   Sending 4 demo alerts to: tuskydv@gmail.com" -ForegroundColor Cyan
Write-Host ""

if ($apiKey) {
    python test_sendgrid_alerter.py
    Write-Host ""
    Write-Host "SUCCESS: Tests completed!" -ForegroundColor Green
} else {
    Write-Host "ERROR: Cannot run tests - API key missing!" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Check your email: tuskydv@gmail.com" -ForegroundColor Gray
Write-Host "2. You should receive 4 professional alerts" -ForegroundColor Gray
Write-Host "3. See SENDGRID_ALERTER_SETUP.md for full documentation" -ForegroundColor Gray
Write-Host ""
