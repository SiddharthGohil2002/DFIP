# Changelog

## Unreleased

### Added — Memory images
- **Memory images** (new `memory` module and **Memory** page): Windows memory captures (raw, complete crash dumps, LiME, VMware .vmem) are evidence of their own, read with Volatility 3: the Windows release and the capture time, processes as a tree with their paths and command lines, network connections, code injected into processes (malfind, with its first bytes), services, and the DLLs of the processes that stand out. Processes, connections, services and DLLs that stand out are flagged with the reason (look-alike names, the wrong folder or parent, a second lsass.exe, a shell started by Word, encoded PowerShell, injected code, temporary folders, programs that rarely connect). Injected code is listed with the malware indicators; internet addresses can be looked up with threat intelligence and go into the STIX and MISP exports.
- Raw captures with other names are uploaded with "This is a memory image" on the Evidence page; a process minidump is refused. An image Volatility cannot read fails its analysis saying why (no Windows kernel, a Linux kernel, missing symbols).
- **Symbol packs** (System & tools): administrators add the symbol packs Volatility needs or download the Windows pack; Volatility runs offline unless `MEMORY_SYMBOL_SERVER` is turned on.
- Report section, keyword search, tags, overview counts and the case summary cover memory images.

### Added — Reports, exports and court readiness
- **Signed reports**: every report PDF is signed (PAdES) with the organisation's certificate (`REPORT_SIGNING_P12`) or, without one, a self-signed certificate DFIP makes and marks as untrusted; with `REPORT_TSA_URL` it carries an RFC 3161 timestamp (PAdES-B-T). **Check** a stored report or any PDF someone was given: whether anything was changed or added after signing, who signed, whether the certificate and timestamp are trusted, and whether it is byte for byte a report DFIP made.
- **HTML reports**: each report is also one self-contained HTML file with the same content (pictures inline, no scripts, nothing fetched).
- **Report templates**: choose and reorder the sections (the list now comes from the server, so it is never out of date), fill in the cover (title, organisation, reference, who it is for, classification on every page, scope), include only approved findings, and show pictures attached to findings. Templates are saved for reuse.
- **Pictures in findings**: screenshots (PNG or JPEG) attached to a finding while it is a draft, shown on the Findings page and in reports.
- **Exports**: every table exports as CSV or XLSX: all rows its filters select, not only the page shown, with spreadsheet formulas defused and each export audited with its SHA-256. The case exports as CASE/UCO JSON-LD (checked with `case_validate`), and its indicators of compromise (malware matches, known-bad and VirusTotal-flagged files, programs that stand out, upload destinations) as STIX 2.1 or a MISP event with a TLP marking. New permission use: `REPORT_EXPORT` (administrators and investigators).
- The desktop app can read the SHA-256 headers of downloads (exposed through CORS).
- The backend image gains pyHanko, openpyxl, stix2 and case-utils (with `pyhanko-cli` for the tests' independent check).

### Added — Review, teamwork and evidence management
- **Peer review of findings**: findings are drafts until someone else who may review findings (new permission `FINDING_REVIEW`: administrators and investigators) approves them or asks for changes. The author sends a finding to a chosen reviewer, edits and resubmits it, reopens an approved one; every step is kept in the finding's history and the audit log, and reports show each finding's status and reviewer.
- **Case members and comments**: cases can be shared with other users (Team in the case dialog). Findings, tags, files and evidence take comments; typing @ offers the case's people, and a mention notifies only someone who can already see the case.
- **Link graph** (new page): people, devices, files, programs, internet hosts and accounts joined by what the records say they did (ran, opened, stored on, connected, visited, downloaded, emailed, messaged, called, synced, uploaded, logged in), each line citing its records; focus, expand, filters and a table of every connection.
- **Case summary** (new page): numbered facts built from the records, each citing them. **Claude mode** (off for every case until turned on): ask Claude about the facts you tick, and nothing else; answers cite the facts, and every request is kept and audited. Needs `ANTHROPIC_API_KEY` (model `claude-opus-5-5` by default).
- **Physical evidence** (new page): seized items with bag and seal numbers, storage, photos and linked disk images; check out, check in (seal state), move, release and destroy, refused when the state or a legal hold does not allow it; a custody form to print and sign; a report section.
- **Retention** (Administration): closing a case starts its retention period; a daily check (new `celery_beat` service) notifies administrators of cases due. Administrators delete a case's data with the case number typed and a reason; legal hold, running work and held physical evidence block it, and the case remains as a deleted record.
- The backend image gains the Anthropic SDK; the frontend gains d3-force for the graph layout.

### Added — Network captures and phones
- **Network captures** (new `network` module and **Network** page): pcap and pcapng files are evidence of their own. tshark reads conversations (with the names each server went by), DNS lookups and their answers, HTTP requests and responses, and the server names of TLS connections. Every file HTTP carried, and each file of a form upload, is kept under its SHA-256 and indexed as a member of the capture, so hash sets, YARA, ClamAV, programs, pictures and content search cover it; requests show what they sent and received. Hosts can be looked up with threat intelligence on request.
- **Phones** (new `phone` module and **Phones** page): Android and iOS full file system extractions (ZIP or TAR) are recognised when unpacked. Android: device, SMS and MMS with attachments, calls, contacts, WhatsApp (current and older layouts), installed apps with install times (Android binary XML read), saved Wi-Fi networks, Chrome. iOS: device, iMessage/SMS with attachments, calls (FaceTime and app calls), contacts, WhatsApp, Safari, installed apps, Wi-Fi. The other party is named from the contacts; attachments open from the extraction; encrypted messaging, VPN and cleaning apps are flagged; Wi-Fi passwords are never kept.
- Evidence kinds: modules declare whether they apply to disks, collections or captures, and a capture runs only those that apply.
- Report sections, timeline events (messages, calls and HTTP requests count as activity on the dashboard), tags, keyword search and overview counts for both. The phone's time zone is taken from the phone.
- Fixed: a file of a collection opened with its volume (`volume_id=pkg`, as the Files page asks) was refused as an invalid volume; files of a collection with several drives are now told apart by their volume.
- dpkt is added to the backend image as the tests' independent pcap reader. The test data gains a capture of the laptop uploading the payroll export, and alice's Android phone and iPhone.

### Added — Collections, Linux and macOS, Plaso timelines
- **Logical evidence**: a ZIP or TAR of collected files (KAPE, Velociraptor offline collections, CyLR, UAC) is uploaded as evidence and analysed like a disk. It is unpacked safely (names that climb out, links and archive bombs refused), every file hashed, the manifest in the chain of custody, and times taken from the archive. On the scenario laptop a KAPE collection gives the same results as the disk image.
- **Linux and macOS** (new `unix` module and page): accounts (a second root account flagged), shell history with times (copies to other computers, wiping and privilege changes flagged), logins and log events from wtmp, btmp, auth.log and syslog (SSH, sudo, accounts created, USB devices), cron, systemd and launchd jobs (hidden or temporary programs flagged), recently used files, Safari history and downloads, download quarantine and Wi-Fi networks; Linux and macOS browser profiles; the time zone from the computer's own files.
- **More file systems**: ext4 and HFS+ as before, and APFS volumes through the Sleuth Kit's tools.
- **Plaso timelines**: a timeline made by Plaso (json_line or l2tcsv) is imported into a case from the Timeline page, its events shown next to DFIP's own and summarised in the report.
- Symbolic links on disk images are indexed under their own names (with their targets).

### Added — Disk images, encrypted volumes and shadow copies
- **More image formats**: VHD, VHDX, VMDK and QCOW2 virtual disks, read through a raw working copy made with libyal and hashed. Differencing disks and snapshots are uploaded with their parents; on their own they are refused, naming the parent.
- **Images in several files**: EnCase segments (`.E01`, `.E02` ...) and raw images split into numbered parts upload together as one evidence item. Each file and the whole are hashed; a missing segment or part is refused before anything is registered, and an integrity check names the file that changed.
- **Encrypted volumes**: BitLocker (password or recovery password, BitLocker To Go included) and LUKS volumes are unlocked from the evidence page. The key is checked at once, stored encrypted and audited; the decrypted volume becomes evidence of its own, hashed, in the chain of custody and analysed. Deleting the original deletes it too.
- **Volume Shadow Copies** (new `shadow_copies` module and page): every snapshot of every NTFS volume, when it was made, and the files deleted, changed or added since; snapshots can be browsed, their files viewed and recovered as they were. A report section, timeline events, tags and search.
- Every upload is now stored in a folder of its own under its own name. `DATA_ENCRYPTION_KEY` sets the key stored secrets are encrypted with. The backend image gains qemu-utils, libvshadow-utils, libbde-utils and libluksde-utils (the tests' independent readers).

### Added — Malware checks
- **Programs** (new `executables` module, standard and full profiles): every Windows program and DLL on the evidence (renamed, deleted, in archives or attached to email) parsed without running it: compile time, sections and their entropy, imports, version information and its Authenticode signature checked against Microsoft's trusted roots. Programs that stand out come first, with the reasons: packed, built under another name, a system program's name in the wrong folder, a bad or untrusted signature, imports that wipe files, inject into processes or log keys. Indicators gains a Programs card with each program's details.
- **capa** (pinned release) lists what a program's code does, with ATT&CK techniques: automatically for the programs that stand out most, and on request.
- **ClamAV** (new `clamav` module): files scanned with the official databases (downloaded with freshclam or copied in) and with signature files of your own; detections appear with the YARA matches.
- **YARA rule sets**: administrators add their own rules (compiled before they are accepted, `include` refused), turn them off and on, and every analysed evidence item is rescanned. A new **Malware rules** administration page manages rule sets and ClamAV databases.
- **Automatic VirusTotal lookups** (new `reputation` module): off until turned on per case; then only the hashes of programs are sent, at the configured rate, and each answer is kept with the program. The VirusTotal address can be changed (`VIRUSTOTAL_BASE_URL`) for a proxy or mirror.
- The report's malware section lists signature matches and the programs that stand out; programs can be tagged and found by search.
- The backend image gains ClamAV, capa, osslsigncode and UPX. The test disk gains a signed file wiper built from C and a UPX-packed copy named svchost.exe.

### Added — Pictures and videos
- **Pictures and videos** (new `media` module, standard and full profiles, and a new page): every picture and video found by its content (renamed and deleted files, archive members and email attachments included) with a thumbnail, its camera, when it was taken (made UTC from the picture's own offset or GPS time, else the computer's time zone, with the basis shown), its GPS position on an offline world map, and for videos their length, format, creation time, location and a keyframe per scene.
- **Text in pictures and scans** (new `ocr` module, full profile): tesseract reads pictures and scanned PDFs; the text is searchable and found data (account numbers, addresses) covers it.
- Picture and video times on the timeline; filters by camera, location, deleted, where found; a report section; overview counts.
- The backend image gains ffmpeg and tesseract. The test disk gains a GPS-tagged photo, a whiteboard with writing, a scanned payment instruction and a video in three scenes.

### Added — Email, chat, cloud storage and browser depth
- **Email** (new `email` module and page): Outlook PST/OST (libpff), MBOX, Thunderbird folders and EML/MSG files, with folders, people, times, bodies and headers. Messages Thunderbird users deleted but that are still in the folder file are found and marked. Attachments become files in the file index, so hash sets, YARA and content search cover them. HTML email is shown sanitised in a sandbox that loads nothing from the internet (tracking pixels are counted, never fetched).
- **Chat and cloud storage** (new `chat_cloud` module and page): Skype (classic) messages, calls, file transfers and contacts; Teams, WhatsApp, Telegram, Signal and other apps detected with where their (encrypted) data is; every file OneDrive and Google Drive for desktop synced, with OneDrive's SHA-1 linked to the same content on the disk; Dropbox accounts.
- **Browser depth** (new `browser_depth` module and Browser history tabs): searches, cookies, bookmarks, form history, saved logins (sites and user names; passwords are never decrypted or shown) and **deleted history rows recovered** from SQLite free pages, free space and write-ahead log frames, for Chrome, Edge, Brave, Opera, Vivaldi and Firefox. Opera and Vivaldi history and downloads are read too.
- Records can be tagged, are found by keyword search, are counted on the overview and have report sections; searches, sent email, calls and file transfers count as user activity on the dashboard.
- The backend image gains libpff, and pff-tools and the sqlite3 shell for the tests. Five more Plaso samples are pinned (Chrome History, Web Data and Cookies, Firefox places.sqlite, Skype main.db) and put on the samples disk with the PST.

### Added — NTFS internals
- **File system journal** (new `ntfs` module, standard and full profiles, and a new page) for every NTFS volume:
  - **Timestomping**: files whose `$STANDARD_INFORMATION` times look set back, compared with their `$FILE_NAME` times, flagged strong or possible with the reasons. No false positives on a real Windows XP `$MFT` of 13,060 entries.
  - **Alternate data streams**, with the Mark of the Web decoded (which downloaded files came from where) and streams that Windows does not write flagged for review.
  - **The USN change journal**: every file created, renamed, overwritten, deleted or with its times changed that the journal still holds, with full paths; a wipe (rename, overwrite, delete) shows on the timeline.
- Records can be tagged, are found by keyword search, are counted on the overview and have a report section; downloads count as user activity on the dashboard.
- The backend image gains libfsntfs and libqcow (the tests read Plaso's journal sample from its QCOW image). A second test disk, alice's office desktop on NTFS, is built with ntfs-3g and libntfs-3g (`make-ntfs-image.sh`).

### Added — Jump Lists, Windows Timeline, thumbnails, SRUM and Windows Search
- **Jump Lists** (new `user_activity` module, standard and full profiles): the files and folders each program opened, with when (AutomaticDestinations: last used, pinned, use count, the computer and the MAC address from the object identifiers) and the programs' own lists and tasks (CustomDestinations).
- **Windows Timeline** (ActivitiesCache.db): applications and documents opened, how long an application was in use, clipboard copies with the copied text, and entries the user deleted from the Timeline.
- **Thumbnails** from Explorer's thumbnail caches, viewable like recovered files: a picture that was deleted or wiped can still be seen.
- **SRUM**: network bytes sent and received per application and user, network connections and application resource use.
- **Windows Search index** (Windows.edb, and Windows 11's Windows.db): what Windows knew about files, including files that are no longer on the disk; thumbnails are linked to the files the index knows.
- Windows activity gains the tabs Jump lists, Timeline, Thumbnails, Network usage and Search index; the records are on the timeline and the activity dashboard, can be tagged and searched, are counted on the overview and have a report section.
- The backend image gains libesedb and libolecf, and impacket's ESE reader (used by the tests as an independent reader). The test disk gains alice's Jump Lists, Windows Timeline and thumbnail cache; `fetch-samples.sh` also builds a disk from Plaso's real Jump Lists, ActivitiesCache.db, SRUDB.dat and Windows.edb.

### Added — Windows event logs
- **Event logs** (new `eventlogs` module, standard and full profiles, and a new page): every record of every Windows event log (.evtx), read with libevtx, including records recovered from unused space. Notable events are described in plain English with their user: logons (with logon type) and logoffs, failed logons (with the reason), account and group changes, cleared logs, services, scheduled tasks, Remote Desktop, PowerShell (encoded commands decoded), USB devices, Microsoft Defender, startup and shutdown. Every record can be searched and filtered by log, event ID, category, level, user and time, and opened with its XML.
- **Detections**: a Sigma rule engine (subset of the specification, regular expressions in RE2) with 15 curated rules: cleared logs, suspicious services, encoded PowerShell and download cradles, accounts created, deleted and added to Administrators, password guessing and spraying, Defender alerts and protection turned off, suspicious scheduled tasks, Remote Desktop logons, audit policy changes. Detections are leads, listed with their usual false positives.
- **USB devices** gain connect and remove times from the event logs (Partition/Diagnostic, Kernel-PnP, DriverFrameworks); a drive seen only in the event logs is added. Notable events are on the timeline and logons on the activity dashboard; event records can be tagged, are found by keyword search, are counted on the overview and have a report section.
- The backend image gains libevtx and python-evtx (used by the tests as an independent reader). Test disk: Security, System, PowerShell and Partition/Diagnostic logs written by a new EVTX writer.

### Fixed — found while testing event logs
- Keyword search did not show its registry results (they were counted in the total but not listed).

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
