# Changelog

## Unreleased

### Added — time zone, computer and users
- **The computer's time zone is read from the SYSTEM hive** before the file system is indexed (Windows zone name mapped to IANA with Unicode CLDR; a custom zone is used exactly as the hive's own daylight-saving rules). FAT file times, which Windows stores in local time, are now converted to true UTC (`fls -z`), daylight saving applied per date; access times on FAT are flagged as date-only. `setupapi.dev.log` uses the same rule (it used one fixed offset before). Fixes the documented limitation that FAT times were local time shown as UTC.
- **Set the time zone by hand** on the evidence page (with a reason, audited): the file system index and what is built on it are re-run; tags follow their items. `PUT /api/evidence/{id}/time-zone`.
- **Computer and users** page and report section: computer name, Windows edition/version/build, install date, owner, last shutdown, network interfaces, last signed-in user, and the user accounts from SAM (SID, full name, last logon, logon count, password last set, disabled) joined with user profiles. Recycle Bin items show their user's name; accounts are searchable. `GET /api/forensics/computer`.
- New analysis modules `tz_probe` (Computer time zone) and `computer` (Computer and users); the report header states the time basis.
- Test disk: SYSTEM, SOFTWARE and SAM hives for the scenario computer written with hivex (the HP USB keys copied from the real Windows 7 hive), FAT times written in US Eastern local time as Windows would, and two files in standard time (January, November).

### Fixed — registry
- Binary registry values longer than 128 bytes were read cut short (regipy trims them by default); they are now read in full.

### Changed — analysis modules (foundation for the next features)
- **Analysis modules and profiles.** An analysis is now a plan of modules (file system index; browser, USB and Windows activity; YARA scan), each owning its own output. Choose a profile (Quick triage, Standard, Full) or individual modules in the new **Analysis options** dialog, and re-run a single module from the evidence page's **Analysis modules** card; only its records are replaced, and the modules built on it are refreshed. `POST /api/jobs/analysis/{id}` accepts `{profile}` or `{modules}`; `GET /api/jobs/analysis/modules` lists them.
- **One analysis per evidence at a time** (409 while one is queued or running).
- Jobs are claimed by one worker and send heartbeats: a redelivered message never starts a second run, and a job whose worker died is taken over and continues after the modules it had completed.
- External tools run in their own process group under a memory limit; cancelling a job now stops a long-running tool (for example `fls` on a large disk) instead of waiting for it to finish.
- In-process reading of disk images (pytsk3) behind a new evidence-source layer, and a `volume_id` (`p2048`) on file-index records and file endpoints.
- Tag keys no longer include times that a time-zone correction could change; existing tags are migrated at startup.
- Test infrastructure: the test-disk generator writes a manifest of every file it created; `scripts/test-image/fetch-samples.sh` downloads pinned public samples (dfVFS, Plaso, python-evtx; Apache-2.0); `SECTIONS=07b,12b sh tests/system/run.sh` runs selected system-test sections.

### Fixed — analysis jobs
- Long analyses could run twice: Redis redelivered unacknowledged tasks after its 1-hour default visibility timeout while the analysis limit is 6 hours. The timeout now outlasts the longest job.
- The analysis summary could grow past MongoDB's 16 MB document limit on disks with many warnings; the summary keeps the first 200 and every warning is stored in `pipeline_warnings`.
- Old analysis run records and work folders no longer pile up on every re-run.

### Added — investigation features
- **Windows activity** (new page, timeline, search, report): programs run from Prefetch files (run count, up to eight last-run times, files loaded, volume; Windows 10/11 compressed Prefetch included, via libscca), files opened from shortcuts in the Recent folders (target, removable/network drive with label and serial, target times; via liblnk) and files moved to the Recycle Bin from `$I` records (original path, size, deletion time, and the `$R` content, which can be recovered). In the demo case this proves the chain: SecureDelete.exe ran, the payroll export was opened from the SanDisk drive (E:) and then moved to the Recycle Bin.
- **Tags**: a bookmark button on deleted files, timeline events, browser records, USB devices, Windows activity records and recovered or carved files marks them as Evidence, Notable or Follow up with a note. A Tagged items page lists them, the case report has a "Tagged evidence" section, and tags stay attached to the right records when an analysis is re-run.
- **Activity dashboard**: a day-of-week x hour heatmap of the user's activity, the busiest days, top websites, file types and a USB connection timeline, in UTC or local time (daylight saving applied per event), with an option to include filesystem times.
- **File viewer**: View any indexed file (including deleted ones) or a recovered or carved file without downloading it: a text, image or PDF preview chosen from the file's content, and a paged hex view with go-to-offset. Each view is recorded in the audit log.
- **Legal hold**: administrators and investigators can place a case under legal hold (with a reason); while held, no evidence in the case can be deleted, by anyone. Shown in the top bar, on the case desktop and in the report header.
- The PDF report numbers its sections automatically; new sections: Windows activity and Tagged evidence.
- Test disk: Prefetch, Recent shortcut and Recycle Bin files for the demo story, a PNG and a PDF; generated by `backend/tests/fixtures/winfmt.py` and checked against libscca, liblnk and ExifTool.
- Dialogs open on top of the page (rendered at the document root), so a dialog opened from a table row no longer takes on the row's alignment. With a case under legal hold, the top bar's New case button shows only its icon on medium-width windows, so it no longer runs under the search box. Switching tabs on Windows activity and Browser history no longer shows the previous tab's rows under the new tab's columns while the new rows load.

### Added — evidence management
- **One registration per image per case.** An upload whose SHA-256 matches evidence already in the case is refused (409) and discarded, whatever its file name; the message names the existing evidence. The upload card warns as soon as a file with the same name and size as registered evidence is chosen. The same image can still be registered in a different case.
- **Delete evidence** (web and desktop): a Delete action on the Evidence register and on the evidence page, for administrators and investigators (new `EVIDENCE_DELETE` permission). A reason is required. It removes the stored image, its E01 working copy, recovered and carved files, and every analysis result taken from it, and recomputes the case's patterns and anomalies. The chain of custody and the audit log keep the item's history and record the deletion with the reason; findings stay but lose the link; reports already generated are not changed. Refused while an analysis of the image is queued or running.

### Fixed — found by the full functional test
- **E01 images were not analysed.** The Sleuth Kit build in the backend image crashes on every EWF file, so E01 analysis "completed" with nothing found. E01 evidence is now checked with `ewfverify`, exported once to a raw working copy (trimmed to the media size, compared with the MD5 stored in the E01, recorded in the chain of custody) and analysed from that copy; corrupt E01 files are refused.
- **Offline sync bypassed access control.** `/desktop/sync/push` let any signed-in user, including a viewer, change any case (even add themselves to it), add chain-of-custody records and create findings in cases they could not open. Every record now needs case access and the matching permission, only safe fields are written, and workstation events are labelled as such.
- **Live events reached other teams.** WebSocket events (case names, finding titles, evidence hashes) were broadcast to every connected user; they now go only to the case's members and administrators.
- A SHA-512 sent with an upload was stored without being checked; the server now always computes it and refuses an upload whose client value does not match.
- Investigators' audit log showed the whole platform; non-administrators now see their own actions and their cases' activity.
- Report PDFs: custody actions are readable labels instead of codes that broke mid-word, and verifications show the person's name instead of a database ID (also on the Custody page).
- Validation: `.local` email addresses are accepted (they were rejected at sign-up), admin-created users need a valid email, a case cannot be renamed to an empty name, a finding can only link evidence from its own case, and an unknown carving engine is refused with 400.
- URLhaus now requires an API key (`URLHAUS_API_KEY`); without one nothing is sent and the lookup says it is not configured.
- Report downloads require `REPORT_READ` (as documented).

### Added — from testing
- **Change password** in the top bar (users could not change the initial password an administrator set).
- UI during a server outage: pages say the server is not responding instead of "Bad Gateway" or loading forever (nginx fails fast), and a reload no longer signs the user out.
- Narrow windows: wide tables keep their action buttons (Recover, Open) in view, IDs and short hashes no longer wrap, the timeline source column wraps, and side cards move below on Reports.
- Test suites in the repository: `tests/system` (isolated stack, ground-truth checks against Sleuth Kit and the known test image, all configuration modes, PDF text) and `tests/ui` (Playwright suites, outage check); see `tests/README.md`. Unit tests for E01 working copies.

### Changed — launch-ready website and UI polish
- New public website: hero with a product screenshot, the tools DFIP is built on, key facts, one section per analysis feature with a real screenshot, the six-step workflow, evidence-integrity safeguards, platforms with the Windows download and its SHA-256, FAQ and a closing call to action. Works down to phone width with a menu button. "Get started" and "Create account" open the account form directly (`/login?mode=register`).
- Page title, description, theme colour, favicon, Apple touch icon and link-preview (Open Graph / Twitter) image.
- Inter and JetBrains Mono are bundled with the app, so the desktop app looks the same offline.
- Workspace: quick case search in the top bar, an icon on every page header, a "Getting started" checklist on the case desktop until the first evidence, analysis, finding and report exist, a refined sidebar, cards and spacing, thin themed scrollbars (instead of the classic Windows ones in the desktop app), and a two-row timeline filter bar.
- Sign-in on phones shows the DFIP brand and a link back to the website.

### Fixed — UI
- Evidence text rendered with substituted glyphs: the font's contextual alternates turned `2x8` into `2×8` (for example in a Firefox profile path) and `->` into an arrow. They are now off everywhere.
- Long paths, URLs and serial numbers broke mid-word even where there was a space; they now wrap at spaces first.
- The desktop build no longer bundles the website and its screenshots.

### Added — accounts and required sign-in
- A labeled **Sign out** button with the signed-in user's name and role in the top bar (web and desktop), replacing the small icon at the bottom of the sidebar; the sign-in page confirms "You have signed out."
- "Create account" on the web and desktop sign-in pages (`POST /api/auth/register`). `REGISTRATION_MODE`: `approval` (default; administrators approve pending accounts and choose the role on the Users page, with a badge on the menu item), `open` or `disabled`.
- Sign-in is required on every desktop app launch and every new browser session: tokens are kept in session storage, and tokens stored by older versions are deleted at start-up.
- Clearer sign-in errors for pending and disabled accounts; unique index on user email.
- Field hints are no longer part of the input's accessible name.

### Added — Windows installer and download links
- `desktop/scripts/build-windows-docker.sh` cross-compiles the NSIS installer in Docker (`cargo-xwin`), so no Rust or Visual C++ toolchain is needed; it publishes to `storage/downloads`.
- "Download for Windows" links on the website, the web sign-in page and the web workspace sidebar, shown whenever an installer is published.

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
