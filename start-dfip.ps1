# Starts DFIP with Docker Compose and opens the web portal.
#   .\start-dfip.ps1            # start (builds images the first time)
#   .\start-dfip.ps1 -Rebuild   # rebuild images after pulling new code
param([switch]$Rebuild)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker Desktop is not installed or not on PATH.' }
if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
    Write-Host 'Created .env from .env.example (demo settings). Change the secrets before real use.' -ForegroundColor Yellow
}

Write-Host '=== Starting DFIP ===' -ForegroundColor Cyan
if ($Rebuild) { docker compose up -d --build } else { docker compose up -d }

Write-Host 'Waiting for the API...' -NoNewline
$ok = $false
for ($i = 0; $i -lt 90; $i++) {
    try {
        $h = Invoke-RestMethod -Uri 'http://localhost/health' -TimeoutSec 3
        if ($h.status -eq 'ok') { $ok = $true; break }
    } catch { }
    Start-Sleep -Seconds 2
    Write-Host '.' -NoNewline
}
Write-Host ''
if (-not $ok) { throw 'DFIP did not become healthy. Check: docker compose logs backend' }

Write-Host "DFIP $($h.version) is running: http://localhost (API http://localhost:8000)" -ForegroundColor Green
if ($h.demo_mode) { Write-Host 'Demo mode is on: demo accounts are listed on the sign-in page.' -ForegroundColor Yellow }
Start-Process 'http://localhost'
