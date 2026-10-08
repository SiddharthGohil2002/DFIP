# Changelog

## Unreleased

### Added — accounts and required sign-in
- A labeled **Sign out** button with the signed-in user's name and role in the top bar (web and desktop), replacing the small icon at the bottom of the sidebar; the sign-in page confirms "You have signed out."
- "Create account" on the web and desktop sign-in pages (`POST /api/auth/register`). `REGISTRATION_MODE`: `approval` (default; administrators approve pending accounts and choose the role on the Users page, with a badge on the menu item), `open` or `disabled`.
- Sign-in is required on every desktop app launch and every new browser session: tokens are kept in session storage, and tokens stored by older versions are deleted at start-up.
- Clearer sign-in errors for pending and disabled accounts; unique index on user email.
- Field hints are no longer part of the input's accessible name.

### Added — Windows installer and download links
- `desktop/scripts/build-windows-docker.sh` cross-compiles the NSIS installer in Docker (`cargo-xwin`), so no Rust or Visual C++ toolchain is needed; it publishes to `storage/downloads`.
- "Download for Windows" links on the website navigation and hero, the web sign-in page and the web workspace sidebar, shown whenever an installer is published.

### Fixed — desktop app
- The app crashed with a stack overflow at sign-in: two 1 MiB stack buffers (hashing, evidence copy) were inlined into the command dispatcher, exceeding the 1 MiB main-thread stack. Buffers are now on the heap, and hashing, copying and tool discovery run off the UI thread.
- Tauri build hooks pointed at a non-existent folder (`cwd` is relative to `src-tauri`).
- The local-copy path example showed doubled backslashes.

### Changed — rebuilt web and desktop UI (2.1.0)
- One UI codebase (`frontend/`) with two targets: the web portal (public website + sign-in + workspace) and the desktop app (single sign-in page, then the workspace). The duplicated `desktop/ui` copy is removed.
- New case workspace: active-case switcher, a "case desktop" home with evidence status, live analysis progress and a tile per function with live counts, and dedicated pages for evidence (drag-and-drop upload with progress), evidence detail (manifest, integrity, partitions/filesystems, custody), deleted files and recovered files (with ExifTool metadata), timeline (zoomable activity chart, filters, paging), browser history, USB devices, indicators, carving, keyword search, findings, reports, chain of custody, and administration (users, audit log, system & tools).
- UTC/local time display switch; role-aware actions using permissions returned at sign-in; web portal becomes read-only automatically when the server requires desktop writes.
- Desktop: server address set on the sign-in page, workstation registration on sign-in, local hash verification of an image copy, workstation panel. Tauri shell builds from the shared UI and now has icons and a capability file; unused plugins removed.
- API: `GET /cases/{id}/overview`, `GET /forensics/search`, `GET /forensics/timeline/histogram`, browser filters, reports by case, permissions in `/auth/me`, `demo_mode`/`require_desktop_for_writes` in `/health`.
- Desktop downloads: the hard-coded "official release" metadata for a 10 KB launcher stub is replaced by an endpoint that lists only real Tauri installers in `storage/downloads`, with hashes computed from the files. Stub launcher files removed from `releases/` and `frontend/public`.
- `start-dfip.ps1` / `stop-dfip.ps1` now use Docker Compose (they referenced another machine's paths).

### Added — MVP disk image analysis
- **Full analysis pipeline** (`app/forensic/pipeline.py`) run by the `FORENSIC_ANALYSIS` job: integrity re-check, partition and filesystem indexing (Sleuth Kit bodyfile), MACB timeline, browser history/downloads, USB device history, YARA scan of user scripts/executables, case patterns/anomalies. Idempotent per evidence item.
- **Deleted file listing and recovery**: `GET /forensics/evidence/{id}/files`, recovery keeps original names and logs to chain of custody, `GET /forensics/artifacts/{id}/download`.
- **USB activity detection** (`app/forensic/usb.py`) from the SYSTEM hive and setupapi.dev.log; `GET /forensics/usb`.
- **Timeline API** filters (type, time range, text, order, paging); `GET /forensics/browser`.
- **PDF report** now covers evidence, chain of custody, analysis summary, deleted/recovered files, USB, browser history and downloads, YARA hits, findings, notable timeline and audit-chain status.
- **UI**: analysis panel with live progress on the evidence page; Deleted File Recovery, Browser and USB pages; server-side timeline filters.
- Test disk image builder, end-to-end script, and parser unit tests with a real SYSTEM hive fixture.

### Fixed — MVP
- fls bodyfile parsing read the file name from the wrong column; mmls descriptions included the length column.
- PhotoRec wrote output outside the inventoried directory and received malformed `/cmd` options; Scalpel had no config and could never run.
- Non-admin users could not log in; web writes required the (unbuildable) desktop app; case assignment crashed; IDs could collide; report text was not escaped; nginx lost the backend after it was recreated.

### Fixed
- `POST /api/forensics/demo/seed/{case_id}` could previously be called on any real case with evidence, injecting synthetic ("DEMO_DATA") timeline events and artifacts with no check that the case was actually a demo case. Now requires `DEMO_MODE=true` and that both the case and its evidence record are explicitly flagged `demo: true`.

### Added
- **Redis + Celery job pipeline.** Replaced the in-process `threading` worker loop with real Celery tasks (`app/tasks.py`) on a Redis broker/backend. Jobs now survive API process restarts and can scale across multiple worker processes. New `celery_worker` service in `docker-compose.yml`. Job cancellation now attempts real Celery task revocation.
- **Browser artifact parsing** (`app/forensic/browser_artifacts.py`): real SQLite parsers for Chromium (Chrome/Edge/Brave) `History`/`Cookies` and Firefox `places.sqlite`/`cookies.sqlite`. Always operates on a scratch copy, never the original evidence file. Chromium cookie *values* are intentionally not decrypted (OS-keychain-encrypted) — only metadata is extracted, to avoid fabricating a "decrypted" value.
- **File carving** (`app/forensic/carving.py`): real PhotoRec and Scalpel subprocess wrappers following the same allow-list/no-shell pattern as `forensic/tools.py`. Every recovered file is SHA-256 hashed and registered as a chain-of-custody-tracked artifact. New endpoint: `POST /api/forensics/evidence/{eid}/carve`.
- **Threat intelligence connectors** (`app/threatintel/client.py`): real HTTP clients for VirusTotal (hash lookup), AbuseIPDB (IP reputation), AlienVault OTX (indicator pulses), and URLhaus (host/URL lookup, no key required). Providers without a configured API key return an explicit `NOT_CONFIGURED` status rather than a fabricated verdict. Results are cached in MongoDB with full raw-response provenance. New router: `app/api/threatintel.py`.
- **Real ML anomaly detection** (`app/analysis/services.py::MLAnomalyService`): scikit-learn `IsolationForest` over per-event feature vectors. Requires at least 15 timeline events to run; below that threshold it returns `INSUFFICIENT_DATA` and the API falls back to the existing rule-based `AnomalyService` rather than presenting an unreliable ML score as if it were meaningful.
- **Real AI retrieval** (`app/ai/services.py::VectorSearchService`): TF-IDF + cosine similarity search over a case's forensic artifacts, replacing the previous no-op that always returned `[]`. Lexical rather than embedding-based, by design, so results stay fully auditable without requiring an external embedding API key.
- New frontend/desktop pages: Threat Intelligence lookup, File Carving trigger — wired to the endpoints above in both the web frontend and the Tauri desktop app.

### Known limitations (see README for full inventory)
- Threat intel and ML features require configuration/data to produce real results (see .env.example); this is intentional, not a bug.
- This phase was built and syntax-checked without Docker/network access in the build environment. Full integration testing (`docker compose up`, live job execution, live provider lookups) should be run in your own environment before relying on this in casework.
