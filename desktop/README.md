# DFIP Investigator (desktop)

The Windows desktop client for DFIP. It opens on a single sign-in page; after sign-in it shows the same case workspace as the web portal (case desktop, evidence, deleted files, timeline, browser history, USB devices, indicators, carving, keyword search, findings, reports, chain of custody, administration), connected to a DFIP server.

## How it is built

- **UI:** not in this folder. It is the shared React app in `../frontend`, built in desktop mode (`npm run build:desktop` → `frontend/dist-desktop`). Desktop mode drops the public website, uses hash routing, and enables the desktop-only features below.
- **Shell:** `src-tauri/` is a Tauri 2 app (Rust) that loads that build in a native window (WebView2).
- **Server:** chosen on the sign-in page (**Server** button), default `http://localhost:8000`. The server's `CORS_ORIGINS` must include `http://tauri.localhost` (the default compose file does).

## Desktop-only features

- **Workstation registration:** on sign-in the app registers this workstation (`POST /api/desktop/register`) and sends its device token with every request. Servers running with `REQUIRE_DESKTOP_FOR_WRITES=true` accept writes only from registered workstations.
- **Verify a local copy** (evidence page): hashes a local file with SHA-256/SHA-512 on the workstation, streaming, without uploading it, and compares it with the registered evidence's acquisition hash.
- **This workstation** panel: host name, OS, architecture, and which forensic tools are installed locally.

The Rust side also exposes non-overwriting evidence copy, read-only marking, directory listing and an allow-listed tool runner (`src-tauri/src/main.rs`); the current UI does not use them yet.

## Build and run

See [INSTALL.md](INSTALL.md).
