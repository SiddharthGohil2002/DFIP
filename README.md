# DFIP — Digital Forensics Investigation Platform

DFIP is a production-oriented digital-forensics case-management and examination suite with a MongoDB system of record, immutable evidence workflow, SHA-256 integrity verification, chain of custody, tamper-evident audit logging, RBAC, background analysis jobs, specialist-tool adapters, investigator workspaces, administration, WebSockets, and forensic reporting.

## Architecture

- **UI:** one React 19 + TypeScript + Vite codebase (`frontend/`) built twice: the **web** portal (public website + sign-in + workspace, served by nginx) and the **desktop** app (sign-in + workspace only, inside the Tauri 2 shell in `desktop/`)
- **API:** FastAPI + Pydantic
- **Database:** MongoDB with indexes and migration-safe startup
- **Evidence:** filesystem-backed original store with SHA-256 manifest and read-only permissions
- **Jobs:** Celery workers on Redis; job state in MongoDB
- **Forensic adapters:** allow-listed integrations for The Sleuth Kit, ExifTool, tshark, YARA, Volatility and strings when installed
- **Security:** JWT access/refresh tokens, PBKDF2-SHA256 password hashing, RBAC, audit hash chain, CORS controls
- **Reporting:** PDF generation with report hash
- **Realtime:** authenticated WebSocket notifications
- **Deployment:** Docker Compose, Nginx static frontend, health checks

## Quick start

1. Install Docker Desktop / Docker Engine + Compose.
2. Copy `.env.example` to `.env` and replace `JWT_SECRET`, MongoDB root credentials, and CORS settings.
3. For a first demo run, keep `DEMO_MODE=true`. With `DEMO_MODE=false`, the backend refuses to start with a placeholder `JWT_SECRET` and requires `ADMIN_PASSWORD` for the initial `admin@dfip.local` account.
4. Writes (cases, uploads, analysis, findings, reports) are allowed from the web portal and enforced by RBAC. Set `REQUIRE_DESKTOP_FOR_WRITES=true` to restrict writes to registered DFIP desktop workstations; the web portal reads this from `/health` and becomes read-only.
5. Accounts: users can create an account from the sign-in page (web and desktop). With the default `REGISTRATION_MODE=approval` it stays pending until an administrator approves it and picks its role (Users page); `open` activates accounts immediately as investigators, `disabled` hides the option. Sign-in is required every time the desktop app starts and in every new browser session.
6. On Linux hosts, make `./storage` writable by the container user: `sudo chown -R 10001:10001 storage`.
7. Start:

```bash
docker compose up --build
```

8. Open `http://localhost`.
9. API health: `http://localhost:8000/health`.

### Demo accounts

Only for local demonstration with `DEMO_MODE=true`:

- `admin@dfip.local` / `DemoPassword!2026`
- `investigator@dfip.local` / `DemoPassword!2026`
- `analyst@dfip.local` / `DemoPassword!2026`
- `viewer@dfip.local` / `DemoPassword!2026`

Disable demo mode and remove/rotate these identities before production deployment.

## Forensic workflow

1. Create a case.
2. Acquire/export the source image using your approved acquisition procedure.
3. Upload the E01/EX01/RAW/DD/AFF/AFF4 image into the evidence register.
4. DFIP computes SHA-256 and records acquisition metadata.
5. The original object is marked immutable and written read-only at the filesystem layer.
6. Verify integrity whenever required.
7. Run analysis as a background job or through the interactive analysis endpoint.
8. Use specialist adapters when their tools are installed.
9. Review timeline, browser/USB/network/email/malware artifacts, patterns and anomalies.
10. Create evidence-linked findings.
11. Generate a versioned PDF report and retain its SHA-256.
12. Review the chain of custody and tamper-evident audit chain.

## Production hardening checklist

- Use dedicated encrypted evidence storage / WORM object storage.
- Place DFIP behind TLS and a hardened reverse proxy.
- Use a private MongoDB network and encrypted MongoDB deployment.
- Rotate JWT and MongoDB secrets through a secrets manager.
- Disable demo mode and create named accounts with strong passwords.
- Add enterprise identity federation (OIDC/SAML) if required.
- Deploy the worker separately from the API for high-volume cases.
- Add malware-analysis VMs/sandboxes outside the API host; never execute submitted evidence inside the web process.
- Add centralized logs, metrics, backups, retention policies and disaster recovery.
- Validate forensic procedures and admissibility requirements against the applicable jurisdiction and agency SOPs.

## Testing

Backend syntax checks are safe to run offline:

```bash
python -m compileall backend/app
```

With dependencies available:

```bash
cd backend
pytest -q
```

Or inside the backend image (no local Python needed): `docker compose build backend && docker run --rm dfip-backend python -m pytest -q`.

End-to-end check of the analysis pipeline against a running stack, using a generated Windows-like test disk:

```bash
docker run --rm -v "$PWD:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-test-image.sh
python scripts/test-image/e2e_analysis.py        # uploads, analyzes, recovers, reports
```

See `docs/forensic-engine.md` for the pipeline stages and known limitations.

UI (both targets; `tsc` runs with strict unused-code checks):

```bash
cd frontend
npm ci
npm run build           # web portal  -> frontend/dist
npm run build:desktop   # desktop UI  -> frontend/dist-desktop
```

## Important forensic boundary

DFIP does not claim that a web application alone replaces a validated forensic acquisition workstation or every specialist parser. The adapter layer is deliberately isolated so validated versions of The Sleuth Kit/libewf, Plaso, ExifTool, Wireshark/tshark, YARA, Volatility and other approved tooling can be deployed in a controlled forensic worker environment. Original evidence is never intentionally modified by the DFIP analysis layer.

## Integrated forensic tooling

The default backend image is wired to run these tools in a controlled worker context:

- The Sleuth Kit (`mmls`, `fsstat`, `fls`, `istat`, `icat`) for volume/filesystem examination and selected-file recovery.
- libewf / `ewf-tools` for E01/EWF support at the image/tooling layer.
- ExifTool for recovered-file metadata.
- YARA for static rule matching.
- `strings` and `file` for lightweight triage.
- tshark for PCAP analysis.
- Volatility 3 for memory-image triage (`windows.info` baseline check).

The Debian package names used by the image are `sleuthkit`, `ewf-tools`, `libewf2`, `libimage-exiftool-perl`, `tshark`, and `yara`; these are available in Debian Bookworm. Volatility 3 is installed from PyPI; its current release is 2.28.0 and its CLI uses the `vol` command.

No specialist tool is invoked through a shell, and original evidence is never used as a writable destination.

## User interface

One React codebase in `frontend/`, built for two targets:

| | Web portal (`npm run build`) | Desktop app (`npm run build:desktop`) |
|---|---|---|
| Opens on | Public website (`/`): features with screenshots, workflow, evidence integrity, platforms and download, FAQ | The sign-in page |
| After sign-in | The case workspace | The same case workspace, plus workstation details and local hash verification |
| Server | Same origin (nginx proxies `/api`) | Configurable on the sign-in page (default `http://localhost:8000`) |

The workspace is organised around an **active case** (switcher in the top bar). Its home screen, the *case desktop*, shows the evidence with live analysis progress and a tile for every function with live counts: Evidence, Deleted files, Timeline, Browser history, USB devices, Indicators (YARA, patterns, anomalies), File carving, Keyword search, Findings, Reports and Chain of custody. Administrators also get Users and Audit log. Actions a role cannot perform are hidden; the server enforces every permission regardless. Times display in UTC by default (switchable to local time in the top bar).

Development: `npm run dev` (web, port 5173, proxies the API on 8000) or `npm run dev:desktop` (desktop UI in a browser, port 1420).

## DFIP Investigator Desktop

`desktop/` is the Tauri 2 shell that loads the desktop build of the UI in a native Windows window. Its native commands (Rust, `desktop/src-tauri/src/main.rs`) include streaming SHA-256/SHA-512 hashing of local files, used to verify a local copy of an image against the registered evidence without uploading it again. On sign-in the app registers the workstation with the server, which allows `REQUIRE_DESKTOP_FOR_WRITES=true` deployments.

Build the installers with `desktop/scripts/build-windows.ps1` (needs Rust and the Tauri Windows prerequisites; see `desktop/INSTALL.md`), or with only Docker: `sh desktop/scripts/build-windows-docker.sh` (cross-compiles the NSIS installer). Installers in `storage/downloads` are offered on the website (hero and Platforms section), on the web sign-in page and in the web workspace sidebar, each with its SHA-256.
