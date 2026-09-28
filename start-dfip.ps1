# DFIP - Digital Forensics Investigation Platform Startup Script
$ErrorActionPreference = 'Stop'

Write-Host "=== Starting DFIP Platform ===" -ForegroundColor Cyan

$baseDir = $PSScriptRoot
$mongoBin = "C:\Users\partt\.mongodb\bin\mongod.exe"
$mongoData = "C:\Users\partt\.mongodb\data"
$pythonExe = Join-Path $baseDir "backend\.venv\Scripts\python.exe"
$frontendDir = Join-Path $baseDir "frontend"

# Refresh PATH for Node / tools
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')

# 1. Start MongoDB if not already running
$mongoRunning = Get-Process -Name "mongod" -ErrorAction SilentlyContinue
if (-not $mongoRunning) {
    Write-Host "[1/3] Starting MongoDB database on 127.0.0.1:27017..." -ForegroundColor Yellow
    if (-not (Test-Path $mongoData)) { New-Item -ItemType Directory -Force -Path $mongoData | Out-Null }
    Start-Process -FilePath $mongoBin -ArgumentList "--dbpath `"$mongoData`" --bind_ip 127.0.0.1 --port 27017" -WindowStyle Hidden
    Start-Sleep -Seconds 2
} else {
    Write-Host "[1/3] MongoDB is already running." -ForegroundColor Green
}

# 2. Start Backend API if not already running
$port8000 = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if (-not $port8000) {
    Write-Host "[2/3] Starting FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Yellow
    Start-Process -FilePath $pythonExe -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8000" -WorkingDirectory (Join-Path $baseDir "backend") -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else {
    Write-Host "[2/3] Backend is already running on port 8000." -ForegroundColor Green
}

# 3. Start Frontend if not already running
$port5173 = Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue
if (-not $port5173) {
    Write-Host "[3/3] Starting Vite Frontend on http://127.0.0.1:5173..." -ForegroundColor Yellow
    Start-Process -FilePath "npm.cmd" -ArgumentList "run dev -- --host 127.0.0.1" -WorkingDirectory $frontendDir -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else {
    Write-Host "[3/3] Frontend is already running on port 5173." -ForegroundColor Green
}

Write-Host "`n=== DFIP is ready! ===" -ForegroundColor Green
Write-Host "Frontend URL:  http://localhost:5173" -ForegroundColor White
Write-Host "Backend Health: http://localhost:8000/health" -ForegroundColor White
Write-Host "`nDemo Accounts (password for all: DemoPassword!2026):" -ForegroundColor Cyan
Write-Host "  - admin@dfip.local"
Write-Host "  - investigator@dfip.local"
Write-Host "  - analyst@dfip.local"
Write-Host "  - viewer@dfip.local"

# Open default browser
Start-Process "http://localhost:5173"
