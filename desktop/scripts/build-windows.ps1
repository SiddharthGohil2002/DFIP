$ErrorActionPreference='Stop'
Set-Location "$PSScriptRoot/../ui"
npm install
npm run build
Set-Location ../src-tauri
cargo tauri build --bundles nsis,msi
Write-Host 'DFIP Windows installers are in desktop/src-tauri/target/release/bundle/'
