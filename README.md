# DFIP — Digital Forensics Investigation Platform

DFIP is a production-oriented digital-forensics case-management and examination suite with a MongoDB system of record, immutable evidence workflow, SHA-256 integrity verification, chain of custody, tamper-evident audit logging, RBAC, background analysis jobs, specialist-tool adapters, investigator workspaces, administration, WebSockets, and forensic reporting.

## Architecture

- **Frontend:** React 19 + TypeScript + Vite + Three.js + Framer Motion
- **API:** FastAPI + Pydantic
- **Database:** MongoDB with indexes and migration-safe startup
- **Evidence:** filesystem-backed original store with SHA-256 manifest and read-only permissions
- **Jobs:** durable MongoDB job queue + worker thread for long-running operations
- **Forensic adapters:** allow-listed integrations for The Sleuth Kit, ExifTool, tshark, YARA, Volatility and strings when installed
- **Security:** JWT access/refresh tokens, PBKDF2-SHA256 password hashing, RBAC, audit hash chain, CORS controls
- **Reporting:** PDF generation with report hash
- **Realtime:** authenticated WebSocket notifications
- **Deployment:** Docker Compose, Nginx static frontend, health checks

## Quick start

1. Install Docker Desktop / Docker Engine + Compose.
2. Copy `.env.example` to `.env` and replace `JWT_SECRET`, MongoDB root credentials, and CORS settings.
3. For a first demo run, keep `DEMO_MODE=true`.
4. Start:

```bash
docker compose up --build
```

5. Open `http://localhost`.
6. API health: `http://localhost:8000/health`.

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

Frontend:

```bash
cd frontend
npm install
npm run build
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

The web UI now connects Acquisition/File Recovery/Forensic modules to the backend examination APIs, background jobs, artifact store and specialist-tool runner. No specialist tool is invoked through a shell, and original evidence is never used as a writable destination.

## DFIP Investigator Desktop

The project now includes a Tauri 2 desktop execution layer under `desktop/`. The desktop shell reuses the investigator UI and adds native operations for SHA-256 hashing, non-destructive evidence copying, read-only preservation, local offline-ready case workspaces, directory inventory, specialist-tool discovery, and bounded allow-listed execution of Sleuth Kit/libewf-adjacent tools, ExifTool, YARA, tshark, Volatility, strings and file identification when installed on the host.

See `desktop/INSTALL.md` for build instructions. Native installers are not included until they can be built and signed on the target platform.
