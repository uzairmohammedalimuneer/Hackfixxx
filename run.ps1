# HACKFIX AI — Startup Script (Windows PowerShell)
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  HACKFIX AI — Website Security Scanner Engine            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$CurrentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# 1. Start Deliberately Vulnerable Test Target (Port 8001) in background
Write-Host "[1/3] Starting Vulnerable Test Target on http://127.0.0.1:8001..." -ForegroundColor Yellow
$TargetProcess = Start-Process -FilePath "$CurrentDir\backend\.venv\Scripts\python.exe" -ArgumentList "-m uvicorn test_target.target_app:app --host 127.0.0.1 --port 8001" -WorkingDirectory "$CurrentDir\backend" -PassThru

# 2. Start FastAPI Backend (Port 8000) in background
Write-Host "[2/3] Starting HACKFIX AI Backend on http://127.0.0.1:8000..." -ForegroundColor Yellow
$BackendProcess = Start-Process -FilePath "$CurrentDir\backend\.venv\Scripts\python.exe" -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload" -WorkingDirectory "$CurrentDir\backend" -PassThru

# 3. Start Next.js Frontend (Port 3000)
Write-Host "[3/3] Starting HACKFIX AI Frontend on http://localhost:3000..." -ForegroundColor Green
Write-Host "Press Ctrl+C to terminate all services." -ForegroundColor White

try {
    Set-Location -Path "$CurrentDir\frontend"
    npm run dev
}
finally {
    Write-Host "Shutting down background services..." -ForegroundColor Yellow
    if ($BackendProcess -and !$BackendProcess.HasExited) { Stop-Process -Id $BackendProcess.Id -Force }
    if ($TargetProcess -and !$TargetProcess.HasExited) { Stop-Process -Id $TargetProcess.Id -Force }
}

