# Stops the DFIP containers. Data (database volume, storage/) is kept.
# To delete all cases and database records as well: docker compose down -v
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
Write-Host '=== Stopping DFIP ===' -ForegroundColor Yellow
docker compose stop
Write-Host 'DFIP stopped. Start again with .\start-dfip.ps1' -ForegroundColor Green
