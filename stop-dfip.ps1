# DFIP - Digital Forensics Investigation Platform Shutdown Script
Write-Host "=== Stopping DFIP Platform Services ===" -ForegroundColor Yellow

# Stop frontend (Vite/Node processes associated with project)
Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*node-v24*" } | Stop-Process -Force -ErrorAction SilentlyContinue

# Stop uvicorn/python
Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*backend\.venv*" } | Stop-Process -Force -ErrorAction SilentlyContinue

# Stop mongod
Get-Process -Name "mongod" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*\.mongodb\bin\mongod.exe*" } | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "All DFIP services stopped." -ForegroundColor Green
