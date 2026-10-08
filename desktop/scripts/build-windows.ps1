# Builds the DFIP Investigator Windows installers (NSIS .exe and .msi).
#
# Prerequisites: Node.js 20+, Rust stable (rustup), and the Tauri Windows prerequisites
# (Microsoft C++ Build Tools, WebView2 runtime) - see desktop/INSTALL.md.
#
#   .\desktop\scripts\build-windows.ps1            # build only
#   .\desktop\scripts\build-windows.ps1 -Publish   # build and copy installers to storage/downloads,
#                                                  # where the web site's Desktop section offers them
param([switch]$Publish)
$ErrorActionPreference = 'Stop'

$desktop = Resolve-Path "$PSScriptRoot/.."
$repo = Resolve-Path "$desktop/.."

foreach ($tool in 'node', 'npm', 'cargo') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is not installed or not on PATH (see desktop/INSTALL.md)" }
}

Write-Host '==> Installing UI dependencies (frontend/)' -ForegroundColor Cyan
Push-Location "$repo/frontend"; npm ci --no-audit --no-fund; Pop-Location

Write-Host '==> Installing the Tauri CLI (desktop/)' -ForegroundColor Cyan
Push-Location $desktop; npm ci --no-audit --no-fund

Write-Host '==> Building the desktop UI and the Tauri shell' -ForegroundColor Cyan
# tauri build runs frontend's "build:desktop" first (see src-tauri/tauri.conf.json).
npx tauri build --bundles nsis,msi
Pop-Location

$bundle = "$desktop/src-tauri/target/release/bundle"
$installers = Get-ChildItem "$bundle/nsis/*-setup.exe", "$bundle/msi/*.msi" -ErrorAction SilentlyContinue
if (-not $installers) { throw "No installers found under $bundle" }

foreach ($f in $installers) {
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
    Write-Host ("{0}  {1}" -f $hash, $f.Name)
}

if ($Publish) {
    $dest = "$repo/storage/downloads"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    foreach ($f in $installers) {
        # Tauri names: "DFIP Investigator_2.1.0_x64-setup.exe" / "..._x64_en-US.msi"; spaces become dashes.
        Copy-Item $f.FullName (Join-Path $dest ($f.Name -replace ' ', '-'))
    }
    Write-Host "Published to $dest" -ForegroundColor Green
}
