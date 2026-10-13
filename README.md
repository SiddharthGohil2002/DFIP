# DFIP — Digital Forensics Investigation Platform

DFIP is a production-oriented digital-forensics case-management and examination suite with a MongoDB system of record, immutable evidence workflow, SHA-256 integrity verification, chain of custody, tamper-evident audit logging, RBAC, background analysis jobs, specialist-tool adapters, investigator workspaces, administration, WebSockets, and forensic reporting.

## Architecture

- **UI:** one React 19 + TypeScript + Vite codebase (`frontend/`) built twice: the **web** portal (public website + sign-in + workspace, served by nginx) and the **desktop** app (sign-in + workspace only, inside the Tauri 2 shell in `desktop/`)
- **API:** FastAPI + Pydantic
- **Database:** MongoDB with indexes and migration-safe startup
- **Evidence:** filesystem-backed original store with SHA-256 manifest and read-only permissions
- **Jobs:** Celery workers on Redis; job state in MongoDB
- **Analysis:** 28 analysis modules (`backend/app/forensic/modules/`) in three profiles (quick, standard, full), run by Celery workers; external tools (The Sleuth Kit, libyal tools, tshark, Volatility 3, ClamAV, capa, ExifTool, ffmpeg, Tesseract, 7-Zip and others) run without a shell, in their own process group, under time and memory limits
- **Security:** JWT access/refresh tokens, PBKDF2-SHA256 password hashing, RBAC, audit hash chain, CORS controls
- **Reporting:** report templates; signed PDF (PAdES, optional RFC 3161 timestamp) and the same content as HTML, each with its SHA-256; tables as CSV and XLSX, the case as CASE/UCO JSON-LD, indicators as STIX 2.1 and MISP
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
3. Upload the evidence: a disk image (E01 with its segments, raw or split raw, VHD, VHDX, VMDK, QCOW2, AFF), a collection of files (ZIP or TAR: KAPE, Velociraptor, phone extractions), a network capture (pcap, pcapng) or a memory image (raw, crash dump, LiME).
4. DFIP computes SHA-256 and records acquisition metadata.
5. The original object is marked immutable and written read-only at the filesystem layer.
6. Verify integrity whenever required.
7. Run the analysis as a background job with a profile (Quick triage, Standard, Full) or chosen modules; unlock encrypted volumes with their key when needed.
8. Use specialist adapters when their tools are installed.
9. Review the results: files and their hashes, content search, timeline, browser, USB, Windows activity and registry, event logs, NTFS internals, shadow copies, email, chat and cloud, pictures, programs and malware indicators, Linux and macOS, network captures, phones and memory images; the link graph and the case summary.
10. Create evidence-linked findings, with pictures; have another investigator review and approve them.
11. Generate a signed report from a template (PDF and HTML, SHA-256 recorded); export tables, the case (CASE/UCO) or its indicators (STIX, MISP).
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

Full functional testing (isolated API suite with ground-truth checks, browser suites for web and desktop UI, desktop app): see [tests/README.md](tests/README.md). In short: `sh tests/system/run.sh` and `sh tests/ui/run.sh`.

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

The backend image holds the tools the analysis modules run (`backend/Dockerfile`, `backend/requirements.txt`, exact versions pinned):

- **Disks and file systems:** The Sleuth Kit (pytsk3 in-process, and `mmls`, `fls`, `icat`, `istat`, `blkls`), libewf, libvhdi, libvmdk, libqcow, libbde (BitLocker), libluksde (LUKS), libvshadow (Volume Shadow Copies), libfsntfs (MFT, alternate data streams, USN journal), APFS through the Sleuth Kit.
- **Windows artefacts:** regipy and libregf (registry), libscca (Prefetch), liblnk and libolecf (shortcuts, Jump Lists), libevtx (event logs) with a Sigma-subset rule engine, libesedb (SRUM, Windows Search).
- **Files and content:** libmagic, yara-python, pdftotext, 7-Zip, olefile and defusedxml, an SQLite FTS5 trigram index per evidence item, google-re2.
- **Email, chat and media:** libpff (PST/OST), Python's mailbox and email modules, ExifTool, Pillow, ffmpeg, Tesseract OCR.
- **Malware:** pefile, signify (Authenticode), capa with pinned rules, ClamAV (databases downloaded or added offline), YARA rule sets, VirusTotal lookups (off unless a case turns them on).
- **Networks, phones and memory:** tshark (pcap, pcapng), DFIP's own Android and iOS readers, Volatility 3 (with symbol packs; offline unless `MEMORY_SYMBOL_SERVER` is on).
- **Reports and exports:** ReportLab, pyHanko (PAdES signatures), openpyxl, stix2, case-utils.

No specialist tool is invoked through a shell, and original evidence is never used as a writable destination.

## User interface

One React codebase in `frontend/`, built for two targets:

| | Web portal (`npm run build`) | Desktop app (`npm run build:desktop`) |
|---|---|---|
| Opens on | Public website (`/`): features with screenshots, workflow, evidence integrity, platforms and download, FAQ | The sign-in page |
| After sign-in | The case workspace | The same case workspace, plus workstation details and local hash verification |
| Server | Same origin (nginx proxies `/api`) | Configurable on the sign-in page (default `http://localhost:8000`) |

The workspace is organised around an **active case** (switcher in the top bar). Its home screen, the *case desktop*, shows the evidence with live analysis progress and a tile for every function with live counts: Evidence and Physical evidence; Files, Timeline, Browser history, Email, Chat and cloud, Phones, Network, Pictures and videos, USB devices, Windows activity, Event logs, File system journal, Shadow copies, Linux and macOS, Memory, Computer and users; Indicators, File carving, Found data, Link graph, Case summary and Keyword search; Findings (with peer review), Tagged items, Reports and Chain of custody. Administrators also get Users, Audit log, Hash sets, Malware rules, Retention and System & tools (with the memory symbol packs). Every table exports as CSV or XLSX. Actions a role cannot perform are hidden; the server enforces every permission regardless. Times display in UTC by default (switchable to local time in the top bar).

Development: `npm run dev` (web, port 5173, proxies the API on 8000) or `npm run dev:desktop` (desktop UI in a browser, port 1420).

## DFIP Investigator Desktop

`desktop/` is the Tauri 2 shell that loads the desktop build of the UI in a native Windows window. Its native commands (Rust, `desktop/src-tauri/src/main.rs`) include streaming SHA-256/SHA-512 hashing of local files, used to verify a local copy of an image against the registered evidence without uploading it again. On sign-in the app registers the workstation with the server, which allows `REQUIRE_DESKTOP_FOR_WRITES=true` deployments.

Build the installers with `desktop/scripts/build-windows.ps1` (needs Rust and the Tauri Windows prerequisites; see `desktop/INSTALL.md`), or with only Docker: `sh desktop/scripts/build-windows-docker.sh` (cross-compiles the NSIS installer). Installers in `storage/downloads` are offered on the website (hero and Platforms section), on the web sign-in page and in the web workspace sidebar, each with its SHA-256.
