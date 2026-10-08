# Building DFIP Investigator for Windows

Windows is the only supported desktop target.

## Prerequisites (once per build machine)

1. **Node.js 20+** (`node --version`).
2. **Rust** via [rustup](https://rustup.rs) (stable, MSVC toolchain: `rustup default stable-msvc`).
3. **Microsoft C++ Build Tools** ("Desktop development with C++" workload) — required by Rust on Windows.
4. **WebView2 runtime** — preinstalled on Windows 10 (current builds) and 11.

Tauri's full checklist: https://tauri.app/start/prerequisites/

## Build the installers

From the repository root in PowerShell:

```powershell
.\desktop\scripts\build-windows.ps1            # builds NSIS (.exe) and MSI installers
.\desktop\scripts\build-windows.ps1 -Publish   # also copies them to storage\downloads
```

The script installs the UI and Tauri CLI dependencies, builds the desktop UI (`frontend`, `npm run build:desktop`), compiles the Rust shell and prints each installer's SHA-256. Output: `desktop\src-tauri\target\release\bundle\nsis\` and `...\bundle\msi\`.

With `-Publish`, the DFIP website's **Desktop app** section lists the installers with their SHA-256 (the server serves only files named like Tauri's installers, `*_x64-setup.exe` and `*_x64_en-US.msi`).

The installers are unsigned unless you configure code signing (Tauri `bundle.windows.certificateThumbprint`); unsigned installers trigger a SmartScreen warning.

## Develop

```powershell
cd desktop
npm install
npm run dev      # starts the desktop UI dev server (port 1420) and opens it in the native window
```

Without Rust you can still work on the desktop UI in a browser: `cd frontend; npm run dev:desktop`, then open http://127.0.0.1:1420. Native features (local hash verification, workstation details) report that they need the installed app.

## Icons

Generated from `desktop/app-icon.svg` with `npm run icons` (in `desktop/`).
