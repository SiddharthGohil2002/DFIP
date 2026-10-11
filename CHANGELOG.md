# Changelog

## Unreleased

### Added — registry evidence
- **Registry activity** (new `registry` module, every profile) from each user's NTUSER.DAT and UsrClass.dat, Amcache.hve, SYSTEM and SOFTWARE: programs started from Explorer (UserAssist), folders browsed including on USB and network drives (ShellBags), Explorer searches, typed paths and addresses, recent documents, Run dialog commands, remote desktop connections, mapped network drives, Amcache (with SHA-1), ShimCache, BAM, autostart entries (Run/RunOnce, services, Image File Execution Options debuggers, Winlogon) and installed programs. Dirty hives have their transaction logs applied first.
- **Windows activity** gains tabs: Execution evidence (one row per program merging Prefetch, UserAssist, BAM, Amcache and ShimCache), Folders browsed, Searches and typed paths, Persistence (entries that stand out flagged with the reason), Installed programs, Remote desktop and drives. Registry records can be tagged, are on the timeline and the activity dashboard, are searchable, and have report sections.
- The backend image gains libfwsi, libfwps (shell items) and RegRipper (used by the tests as an independent reader). Test disk: alice's NTUSER.DAT and UsrClass.dat, an Amcache.hve, and BAM, ShimCache, services, autostart, IFEO and Uninstall entries, written with hivex, with real key write times and hive header names.

### Fixed — found while testing registry evidence
- Windows XP UserAssist control values were reported as a program with a negative run count; ShimCache was read from every control set (each entry listed twice); ShimCache paths kept the `\??\` prefix.
- Tabs scroll sideways instead of overflowing on narrow windows; tags on found data were labelled "ENTITY" in the report.

### Added — archives, embedded files and unallocated space
- **Archive contents** (new `containers` module and Files tab): members of ZIP, 7z, RAR, tar, gzip and other archives, pictures and objects embedded in Word, Excel, PowerPoint and OpenDocument files, packages embedded in legacy Office (OLE) files and PDF attachments, two levels deep. Members are hashed, typed, matched with hash sets, scanned with YARA, searchable and scanned for found data like any file; they can be viewed and recovered (with a chain-of-custody record). Encrypted members are listed and flagged, not extracted.
- **Archive-bomb and path safety:** members are stored under generated names; 7-Zip unpacks into an empty folder from which only regular files are taken, under a file-size limit; per-member size, expansion-ratio and per-container and per-evidence limits.
- **Unallocated space** (new `unallocated` module): the strings in every file system's free blocks are streamed from `blkls` (never written to disk), mapped to their byte offset in the volume and indexed, so content search and found data cover deleted data whose directory entry is gone. Hits open the volume's raw bytes at the offset, highlighted.
- Analysis modules can *follow* another module: re-running archive extraction refreshes hash sets, YARA and the content index; re-reading unallocated space refreshes found data.
- The backend image gains 7-Zip. Test disk: `export-backup.zip` with a nested 7z, a Word document with an embedded picture and OLE package, and a PDF with an attachment.

### Added — content search and found data
- **Search inside files** (Keyword search → File contents, or Regular expression): the text of documents, PDFs, text files, SQLite databases and the readable strings of every other file, deleted files included, in a per-evidence full-text index (new `content` module, Full profile). Case-insensitive substring search, or RE2 regular expressions; each hit shows a snippet and, where the text is stored in the file as such, **View at offset** opens the hex view at the match, highlighted. Every content search is recorded in the audit log.
- **Found data** (new page and `found_data` module): email, web and IP addresses, phone numbers, card numbers (Luhn), IBANs (mod-97), Bitcoin and Ethereum addresses (checksums) and Aadhaar numbers (Verhoeff), with every occurrence's file and byte offset. Card and Aadhaar numbers are masked; showing one in full is audited. Found values can be tagged, are searchable by name, counted on the case desktop and listed in a new report section.
- Text extraction: encodings detected (UTF-8, UTF-16 with or without a byte-order mark, Windows-1252), Word/Excel/PowerPoint and OpenDocument via defusedxml, RTF, PDF via pdftotext, SQLite tables read in a separate process. The backend image gains poppler-utils, google-re2 and defusedxml.
- Test disk: a contacts file with published test identifiers (and a mistyped card number that must not be reported), a Word document, an RTF, a UTF-16 note and an OpenDocument text.

### Added — file hashes, types, encryption and hash sets
- **Every file is hashed and typed** (new `fileproc` analysis module, standard profile): MD5, SHA-1 and SHA-256 of every file in the index, deleted ones included (as their content is on the disk now), its real type from its content (libmagic), a category, entropy, and encryption. One in-process read per file.
- **Renamed files**: a file whose content contradicts its name is flagged with what the name suggests (for example the payroll CSV renamed `holiday.jpg`: "JPEG image").
- **Encrypted files and volumes**: password-protected ZIPs (AES and ZipCrypto), encrypted Office documents (new and 97-2003 formats), encrypted PDFs, and headerless high-entropy files that look like encrypted containers (VeraCrypt); BitLocker (including To Go) and LUKS volumes are recognised and reported as needing their key.
- **Hash sets** (new Administration → Hash sets page, `HASHSET_MANAGE`): import known-good, known-bad and notable sets from a plain list, a CSV or the NIST NSRL RDS v3 SQLite, uploaded or placed on the server for large sets. Each set is stored in its own SQLite lookup file, not in MongoDB. Every analysed evidence item is re-matched when a set is imported or deleted (new `hash_match` module). Known-good files are hidden by default; known-bad and notable files are indicators, and a known-bad match notifies the case's investigator.
- **Files page** (renamed from Deleted files): Type column, Renamed / Encrypted / hash-set badges, filters (type, flag, hide known-good files) and a details dialog with all hashes, type, entropy, encryption, hash sets and every other place in the case with the same content (`GET /api/forensics/hash`). Keyword search accepts a hash.
- **Indicators**: Hash set matches, and Renamed and encrypted files. Report sections "Hash set matches" and "Renamed and encrypted files"; overview counts and the case desktop show them.
- **YARA now uses yara-python in-process** and picks programs, scripts, documents and archives anywhere on the disk by their real type (was: scripts and executables under user profiles, by extension), deleted files included.
- Test disk: the renamed payroll copy, an AES-encrypted ZIP, a password-protected Word document, a random-data container and the EICAR test file.

### Fixed — found while testing file processing
- Plain-text and CSV hash-set imports failed as soon as progress was reported (a text file's position can't be read while iterating over it).
- INI-style text (libmagic's `application/x-wine-extension-ini`, such as `setupapi.dev.log`) counts as text, not as a renamed file.
- The Reports page lists the report's current sections.

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
