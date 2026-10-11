# Forensic Engine

## Evidence safety model

The API stores an acquisition hash before analysis, marks the original object immutable, changes its local filesystem mode to read-only, and records custody/audit events. Analysis receives a path to the preserved object and never receives a write capability by design.

## Adapter boundary

`app/forensic/tools.py` contains an allow-list for specialist utilities. Commands are executed without a shell, with bounded time and output, and only through named tool adapters.

Supported integration points:

- The Sleuth Kit: `fls`, `istat`, `fsstat`, `mmls`
- ExifTool
- tshark
- YARA
- Volatility (`vol`)
- strings

Tool availability is exposed by `GET /api/forensics/tooling`.

## Full analysis pipeline

`POST /api/jobs/analysis/{evidence_id}` queues a `FORENSIC_ANALYSIS` Celery job (`app/tasks.py`) that runs `app/forensic/pipeline.py`. After the integrity check (step 1), the work is done by **analysis modules** (`app/forensic/modules/`), each owning its own output; see *Analysis modules and profiles* below. In order:

1. **Integrity**: re-hash the original image (SHA-256) and refuse to continue if it no longer matches the acquisition hash. The check is logged to the chain of custody.
   - **E01/EX01 only** (`app/forensic/working_image.py`): the Sleuth Kit build in the image (4.12 with libewf 20140816) crashes on EWF images, so the E01 is checked with `ewfverify`, exported once with `ewfexport` to a raw working copy in `storage/analysis/working/<EVID>.raw`, trimmed to the media size and compared with the MD5 stored in the E01. A corrupt E01 or a mismatch stops the analysis. The copy (read-only) is recorded in the chain of custody as `WORKING_COPY_CREATED` with its SHA-256, and every later tool (`mmls`, `fls`, `icat`, `istat`, carving) reads it. The uploaded E01 is never modified and is still what integrity checks hash.
2. **Partitions** (module `fs_index`): `mmls`; every non-meta, allocated, non-extended slot is examined. An image without a partition table is examined at offset 0.
3. **Filesystem index**: per partition, `fsstat` (filesystem type) and `fls -r -m /` written to a bodyfile under `storage/analysis/pipeline/<EVID>/<JOB>/`. Every entry, allocated or deleted, goes into the `fs_entries` collection (`app/forensic/filesystem.py`).
4. **Timeline**: one `FILE_MACB` event per distinct timestamp of each entry, labelled like `mactime` (`m.cb` etc.) (`app/forensic/timeline.py`). The bodyfile is kept so results can be re-checked with `mactime -b`.
5. **Artifact extraction** (module `artifacts`, `app/forensic/artifact_locator.py`): known paths are selected from the file index and copied out with `icat`, keeping their names and SQLite `-journal`/`-wal` sidecars:
   - Chrome / Edge / Brave / Chromium `.../User Data/<profile>/History`
   - Firefox `.../Profiles/<profile>/places.sqlite`
   - `Windows/System32/config/SYSTEM`
   - `Windows/INF/setupapi.dev*.log`
   - `$Recycle.Bin/<SID>/$I*` (paired with the matching `$R*` content), `Users/<user>/AppData/Roaming/Microsoft/{Windows,Office}/Recent/*.lnk`, `Windows/Prefetch/*.pf`
6. **Browser history** (`app/forensic/browser_artifacts.py`): visits and downloads (Chromium `urls`/`downloads`; Firefox `moz_places` and `moz_annos` download annotations), stored as `BROWSER_HISTORY` / `BROWSER_DOWNLOAD` artifacts and timeline events.
7. **USB history** (`app/forensic/usb.py`, using `regipy`): `Enum\USBSTOR` (vendor, product, revision, serial, friendly name), `Enum\USB` (VID/PID), `MountedDevices` (drive letter, volume GUID), and the device-property timestamps `0064` first install, `0065` last install, `0066` last arrival, `0067` last removal (Windows 7 and 8+ layouts). `setupapi.dev.log` first-install times are converted to UTC with the hive's `ActiveTimeBias`. Results go to `usb_artifacts` and `USB_ACTIVITY` timeline events.
8. **Windows activity** (`app/forensic/windows_activity.py`): Prefetch files (libscca, including Windows 10/11 compressed files) give the programs that ran, their run count, up to eight last-run times and the files they loaded; shortcuts in the Recent folders (liblnk) give the files the user opened, the drive they were on (type, serial, label) and the target's own times; Recycle Bin `$I` records (v1 and v2) give the original path, size and deletion time. Stored as `PROGRAM_RUN`, `RECENT_FILE` and `RECYCLE_BIN_ITEM` artifacts, with `PROGRAM_RUN`, `RECENT_FILE_OPENED` (the shortcut's own times: created = first opened, modified = last opened) and `FILE_DELETED_TO_RECYCLE_BIN` timeline events. At most 2,048 Prefetch and 5,000 shortcut and `$I` files are parsed per analysis.
9. **File hashes and types** (module `fileproc`): every file in the index, allocated or deleted, is read once in-process (pytsk3, 1 MiB chunks, in disk order) for MD5, SHA-1 and SHA-256, its type from the first 64 KiB (libmagic, never the name), entropy and encryption markers; see *File processing and hash sets* below.
10. **Hash sets** (module `hash_match`): every file's hashes are looked up in the imported hash sets; known-bad and notable files become `HASH_SET_MATCH` indicators.
11. **YARA** (module `yara`): programs, scripts, documents and archives anywhere on the disk, chosen by their real type from `fileproc` (bounded: 20,000 files, 32 MiB each, 8 GiB in all), are read in-process and scanned with yara-python and `backend/rules/default.yar` (60 s per file); matches become `MALWARE_INDICATOR` artifacts, deleted files included.
12. **File contents** (module `content`, Full profile): the text of every file that has any goes into a per-evidence SQLite FTS5 index; see *Content search and found data* below.
13. **Found data** (module `found_data`, Full profile): email, web and IP addresses, phone, card, IBAN, cryptocurrency and Aadhaar numbers recognised and validated in that text, stored in `entities`.
14. **Tags** (runs after every job): tags on this evidence's items are re-linked to the new records by their natural key (see `app/services/tags.py`).
15. **Case analytics** (runs after every job): patterns and anomalies are recomputed for the case.

Everything written carries `analysis_job_id`, `pipeline_module` and `module_run_id` for provenance.

### Analysis modules and profiles

| Module | Needs | Writes |
|---|---|---|
| `tz_probe` Computer time zone | - | facts `zone`, `source`, `detected`, `hive`, `override` |
| `fs_index` File system index | `tz_probe` | `fs_entries`, `FILE_MACB` events, facts `partitions`, `offsets`, `filesystems` (with `encryption`) |
| `computer` Computer and users | - | `COMPUTER_INFO`, `USER_ACCOUNT`, fact `accounts` |
| `artifacts` Browser, USB and Windows activity | `fs_index` | `EXTRACTED_FILE`, browser, USB and activity records and events |
| `fileproc` File hashes and types | `fs_index` | fields on `fs_entries`: `md5`, `sha1`, `sha256`, `mime`, `magic`, `file_category`, `ext_mismatch`, `expected_type`, `entropy`, `encryption`, `hash_basis`, `hash_error`; fact `categories` |
| `hash_match` Hash sets | `fileproc` | fields on `fs_entries`: `hash_status`, `hash_sets`; `HASH_SET_MATCH`; fact `sets` |
| `yara` YARA scan | `fileproc` | `MALWARE_INDICATOR` |
| `content` File contents | `fileproc` | `storage/analysis/text/<EVID>.sqlite` (rebuilt and renamed over the old one); fact `index` |
| `found_data` Found data | `content` | `entities` |

- **Profiles:** `quick` (time zone, file system index, computer, artifacts: no file hashing or YARA), `standard` (every module except the content ones; the default when the request has no body) and `full` (everything: also `content` and `found_data`). A request may instead name `modules`.
- **Run plan:** the requested modules, plus any prerequisite that has not completed (or was written by an older module version), plus every module that depends on something being re-run and had completed before. Re-running `yara` runs only `yara`; re-running `fs_index` also refreshes `artifacts`, `fileproc`, `hash_match` and `yara`; importing or deleting a hash set re-runs only `hash_match`.
- **Own output only:** a module first deletes its previous documents (`pipeline_module=<name>`), unsets the fields it adds to other modules' documents (`fileproc` and `hash_match` on `fs_entries`) and its facts; nothing else is touched, so the other modules' records keep their IDs. Output written before modules existed (no `pipeline_module`) is replaced as a whole by a standard run.
- **Status:** each module's status, version, run ID, counts and first warnings are kept on the evidence (`modules.<name>`); `analysis_summary` and the job summary merge the counts of every module's latest completed run, so a partial re-run still reports the whole evidence. All warnings go to `pipeline_warnings`; the job summary keeps the first 200 (`warnings_total` has the number).
- **Jobs:** one analysis per evidence at a time (another request returns 409). A worker claims a queued job atomically and sends heartbeats; a redelivered message for a job another worker owns, or that already finished, is ignored (`DUPLICATE_IGNORED`). If a worker dies, the job is taken over once its heartbeat is 10 minutes old and continues after the modules it had completed. The Celery visibility timeout is longer than the longest allowed analysis, so a long job is not redelivered while it runs.
- **External tools** run through `run_tool` (`app/forensic/modules/base.py`): no shell, an own process group, a 4 GiB address-space limit, a timeout, and a cancellation check every 2 seconds that kills the whole process group.
- **Work folders** (`storage/analysis/pipeline/<EVID>/<JOB>/`) of earlier jobs are removed once no module's current output refers to them.

### Time zone, computer and users

- **Time zone** (`tz_probe`, `app/forensic/timezone.py`): before the file system is indexed, the SYSTEM hive is read in-process (pytsk3) and `ControlSet\Control\TimeZoneInformation` gives the Windows zone (`TimeZoneKeyName`), the offsets and the daylight-saving rules. The zone is mapped to IANA with Unicode CLDR's `windowsZones.xml` (`app/forensic/windows_zones.py`, release 48-2; e.g. Eastern Standard Time -> America/New_York); a zone without a mapping is turned into an exact POSIX TZ string from the hive's own rules (`STD5DST4,M3.2.0/2:00:00,M11.1.0/2:00:00`). An investigator can set the zone on the evidence (`PUT /api/evidence/{id}/time-zone` with a reason, audited); that re-runs `tz_probe` and everything built on it. Without a SYSTEM hive the zone is UTC and FAT volumes are flagged.
- **Conversion:** `fls -z <zone>` lists FAT and exFAT (which store local time) in that zone, so `fs_entries` and `FILE_MACB` events hold true UTC; each FAT entry records the zone used (`time_zone`) and `atime_date_only` (FAT keeps only the date of the last access; access events carry `access_date_only`). `setupapi.dev.log` is converted with the same zone, daylight saving applied per date. Local times in the repeated hour when clocks go back are read as the first (daylight) occurrence. The backend image includes `tzdata` and `tzdata-legacy` for the zone names.
- **Computer** (`computer`, `app/forensic/system_info.py`): SYSTEM (computer name, last shutdown, network interfaces with an address), SOFTWARE (edition, display version, build and UBR, install date, registered owner, user profiles with their last load, last signed-in user) and SAM (machine SID; per user the V record's name, full name and comment, and the F record's last logon, password last set, logon and failed-logon counts and account flags). Accounts are joined with profiles by SID; profiles without a local account (domain or Azure AD users) are listed too. Each result lists the hives it came from with their SHA-256. Recycle Bin items show the user name for their SID.

### File processing and hash sets

- **One read per file** (`fileproc`, `app/forensic/filetypes.py`): files are sorted by inode (roughly their order on the disk) and read in 1 MiB chunks; the same pass feeds the three hashes, a byte histogram of the first 4 MiB (Shannon entropy) and the first 64 KiB for the type. A deleted file is hashed as its content is on the disk now (`hash_basis` says so; its clusters may have been reused). A file that can't be read gets `hash_error` and is counted as unreadable.
- **Type:** libmagic (python-magic, the `file` command's database) on the first 64 KiB. libmagic 5.46 can't recognise a ZIP from a buffer (its rules read the end of the file), so a file that starts like a ZIP is identified from its central directory: Office Open XML (by `[Content_Types].xml` and `word/`, `xl/`, `ppt/`), OpenDocument and EPUB (by the stored `mimetype` member), else ZIP. The type gives a category (program, script, document, archive, picture, video, audio, email, database, registry hive, shortcut, text, empty, other).
- **Renamed files:** an extension that promises a type the content contradicts is flagged (`ext_mismatch`) with what the name suggests (`expected_type`, e.g. "JPEG image" for a CSV named `holiday.jpg`). Extensions with no clear expectation, and contents libmagic can't type, are not flagged.
- **Encryption** (`encryption: {kind, detail}`): ZIP entries with the encryption flag (AES or ZipCrypto, from the local header), encrypted Office documents (an OLE container with `EncryptionInfo`/`EncryptedPackage`, the Word FIB encryption bit, an Excel `FILEPASS` record, PowerPoint `EncryptedSummary`; olefile), PDF encryption dictionaries (`/Encrypt` in the trailer area), and `HIGH_ENTROPY`: a file of at least 1 MiB, a whole number of 512-byte sectors, with no recognisable type and entropy of at least 7.95 bits per byte, as an encrypted container (VeraCrypt) is. Compressed media are high-entropy too but have a type, so they are not flagged.
- **Encrypted volumes** (`fs_index`, `app/forensic/volumes.py`): every volume is checked for LUKS (its `LUKS` magic) and BitLocker (libbde's volume signature check, which also recognises the BitLocker To Go discovery volume) before its file system is read. An encrypted volume is counted (`encrypted_volumes`) and reported as needing its recovery key or password; a To Go discovery volume's readable FAT part is still indexed.
- **Hash sets** (`app/forensic/hashsets.py`, `app/api/hashsets.py`): administrators (`HASHSET_MANAGE`) import a set as known good, known bad or notable, from an upload or (for large sets such as the NSRL) a file placed in `storage/hashsets/incoming`. Formats are recognised from the content: a plain list (one MD5, SHA-1 or SHA-256 per line; `md5sum`/`sha256sum` output; `#` comments), a CSV with `md5`/`sha1`/`sha256` columns, or the NIST NSRL RDS v3 SQLite (`FILE` table). A background `HASHSET_IMPORT` job writes each set to its own SQLite file (`storage/hashsets/<set id>.sqlite`) with one `WITHOUT ROWID` table of raw digests per algorithm, so even the NSRL is looked up in batches of 500 without loading it into memory or MongoDB; lines that are not a hash are counted, and an uploaded source is deleted once imported. Importing or deleting a set queues `hash_match` for every evidence item whose files were hashed.
- **Matching** (`hash_match`): a file in several sets takes the strongest kind (known bad, then notable, then known good) and lists every set it is in. Known-good files are hidden on the Files page by default; known-bad and notable files become `HASH_SET_MATCH` indicators (deleted files included), and a known-bad match notifies the case's investigator (on a re-match after a set changed, only when the number of known-bad files went up).
- **Finding the same content:** `GET /api/forensics/hash?case_id&digest` lists every file in the case with that MD5, SHA-1 or SHA-256, and the recovered, carved and extracted copies with that SHA-256. Keyword search accepts a hash.

### Content search and found data

- **Which text** (`app/forensic/textextract.py`), by the file's real type from `fileproc`: text files (text, scripts, email) are decoded (byte-order mark, UTF-8, UTF-16LE without a mark, else Windows-1252); PDFs with `pdftotext` (poppler, as an external tool with a timeout); Office Open XML (Word body, headers, footers, notes and comments; Excel shared and inline strings and values; PowerPoint slides and notes) and OpenDocument from their XML parts with defusedxml (DTDs and entities refused; parts over 32 MiB, or 96 MiB per document, are not expanded); RTF without control words, with escaped characters decoded; SQLite databases by reading their tables' text values, one per line, in a separate process (`app/forensic/sqlite_text.py`: read-only, immutable, `trusted_schema=OFF`, under `run_tool`'s timeout and memory limit), because their raw strings run one field into the next; everything else that may hold text (programs, registry hives, shortcuts, legacy Office, unknown data) as printable ASCII and UTF-16LE strings of at least 6 characters. Pictures, video, audio, archives, empty and encrypted files have no text here. A file is read at most 64 MiB deep and keeps at most 8 million characters; an evidence item keeps at most 1.5 billion.
- **Index** (`app/forensic/text_index.py`): one SQLite file per evidence with a `docs` table (path, inode, volume, deleted, method, encoding, byte-order mark, string spans) and an FTS5 table with the `trigram` tokenizer, so search is case-insensitive and matches parts of words (at least 3 characters). The index is built in a temporary file and renamed over the old one when complete, so searches keep working during a re-run; deleting the evidence deletes it.
- **Search** (`GET /api/forensics/content-search`): text mode finds the candidate files through the index and confirms every match in Python; regex mode uses RE2 (linear time; no backreferences), first narrowing the files by the longest literal of 3+ characters every match must contain (none when the pattern has an alternation or only optional or repeated parts), else scanning every file. A search stops after 15 seconds (or 20,000 candidate files) and says it is incomplete. Each file returns its match count and first 20 matches with 60 characters of context.
- **Byte offsets:** for decoded text the byte offset is the byte-order mark plus the length of the text before the match encoded in the file's encoding; for strings each run's byte offset and width (1 for ASCII, 2 for UTF-16LE) is stored; text taken out of PDF, Office, OpenDocument, RTF or SQLite files has no position in the file and says so. The viewer opens the hex view at an offset and highlights the match.
- **Found data** (`app/forensic/found_data.py`): email (domain with a 2-24 letter top-level label), URL (http, https, ftp with a host; trailing punctuation trimmed), IPv4 (each part 0-255; unspecified and reserved 240.0.0.0/4 such as netmasks left out; private or public), phone (international format with +, 8-15 digits), card (13-19 digits of a known brand's prefix and length, Luhn), IBAN (country length, mod-97), Bitcoin (Base58Check P2PKH/P2SH, Bech32/Bech32m `bc1`), Ethereum (0x + 40 hex; a mixed-case address must pass EIP-55, computed with an in-house Keccak-256), Aadhaar (4-4-4 digits, first 2-9, Verhoeff). One `entities` document per value per evidence item with its count, number of files and up to 100 occurrences (file, byte offset or text offset). Card and Aadhaar numbers are sensitive: lists, search and the report show them masked; `POST /api/forensics/entities/{id}/reveal` returns one in full and is audited (`SENSITIVE_VALUE_REVEALED`).
- **Every content search is audited** (`CONTENT_SEARCHED` with the query, mode and number of files).

### Evidence sources

`app/forensic/source.py` puts evidence content behind one interface: `TskImageSource` reads a disk image (or an E01's raw working copy) in-process with pytsk3, and `DirectorySource` reads a folder of loose files (later: unpacked triage packages). A volume is named by a `volume_id` (`p<start sector>`, `p0` for a bare file system; later `p<start>/vss<n>` and `pkg`); `fs_entries`, `FILE_MACB` events and the content, preview, raw and recover endpoints accept it next to the older `offset=`. The system tests check that pytsk3 reads every file (including deleted ones) byte for byte as `icat` does.

### Deleted file recovery

`GET /api/forensics/evidence/{id}/files?deleted=true` lists deleted entries from the index; `POST /api/forensics/evidence/{id}/recover?inode=&offset=` recovers one with `icat` (NTFS `64-128-2` addresses are accepted), hashes it, records it in the chain of custody and keeps the original filename. `GET /api/forensics/artifacts/{artifact_id}/download` returns the recovered copy with its SHA-256 in `X-DFIP-SHA256`. Signature carving of unallocated space (`/carve`) uses PhotoRec (all signatures except the noisy `dovecot` one) or Scalpel with `backend/rules/scalpel.conf`.

### File viewer

`GET /api/forensics/evidence/{id}/content|preview|raw?inode=&offset=` reads a file inside the image without writing a copy: `icat` is streamed and only the requested bytes are kept (hex pages of up to 64 KiB, up to 256 MiB into the file; recover the file to go further). The same three endpoints exist under `/api/forensics/artifacts/{artifact_id}/` for recovered, carved and extracted files. The type shown is decided from the first bytes (PNG, JPEG, GIF, WebP, BMP, PDF, text), never from the name; HTML and SVG are shown as text, and images and PDFs (up to 20 MB) are served with `nosniff`, `Content-Disposition: attachment` and a sandbox Content-Security-Policy. Each view is recorded in the audit log (`FILE_CONTENT_VIEWED`).

### Known limitations

- FAT times are converted with the computer's time zone from the SYSTEM hive (or the one the investigator sets); without either they are shown as recorded and flagged. FAT keeps only the date of the last access.
- Only allocated artifact files are parsed automatically; deleted browser databases or hives must be recovered and parsed manually (`/artifacts/{id}/browser-parse?kind=`).
- Chromium cookie values are not decrypted (DPAPI); Firefox downloads before version 26 (`downloads.sqlite`) are not read.
- The Celery hard time limit (`CELERY_TASK_TIME_LIMIT`, default 30 min) bounds analysis of very large images; raise it for multi-terabyte evidence.
- Multi-segment E01 sets (`.E02`...) are not supported by upload yet.
- An E01 needs free space for its raw working copy (the full media size) in `storage/analysis/working`. Partitions, file details and recovery for an E01 are available once its first analysis has prepared the copy.
- AFF/AFF4 uploads are accepted but have not been tested with this Sleuth Kit build.
- Jump Lists (`AutomaticDestinations-ms`) and shell-item (IDList) details of shortcuts are not parsed. Shortcut header times describe the target file, not when it was opened.
- Prefetch format version 31 (Windows 11 24H2) is read by libscca but has not been verified with DFIP; an unexpected version is reported as a warning.
- Encrypted volumes are recognised but not opened; unlocking BitLocker and LUKS with a key is a later addition. Encrypted files are flagged, never decrypted.
- Types come from the first 64 KiB of each file. File processing reads every file once; on very large disks the quick profile skips it.
- Content search covers files in the file index (allocated and deleted); unallocated space and archive members are later additions. Records deleted from SQLite databases are not read (only the tables' current values). Picture text (OCR) is not read yet.
- Values found in the strings of a binary file can run into the bytes next to them when nothing separates them.

## Test image

`scripts/test-image/make-test-image.sh` builds a 64 MiB MBR/FAT32 image with a Windows-like layout: SYSTEM, SOFTWARE and SAM hives for the scenario computer (LAPTOP-07, Windows 10 Pro, US Eastern time zone, user alice), written with hivex by `make_hives.py` from an empty base hive (`regf_base.py`), with the HP USB stick's keys copied from a real Windows 7 SYSTEM hive (regipy test data, MIT); FAT times written in US Eastern local time, as Windows would; a synthetic `setupapi.dev.log`, Chrome and Firefox history, a deleted CSV and a PowerShell script that triggers the YARA rule, plus Windows activity (a Prefetch file for SecureDelete.exe, a Recent shortcut to `E:payroll-export.csv` on the SanDisk drive and a Recycle Bin `$I`/`$R` pair for the payroll export, written by `backend/tests/fixtures/winfmt.py`), a PNG and a PDF for the file viewer, and files for file processing: the payroll export renamed `holiday.jpg`, an AES-encrypted ZIP (pyzipper), a password-protected Word document (msoffcrypto-tool), 2 MiB of random data (`vault.dat`, like an encrypted container) and the EICAR test file named `eicar.com` (assembled at build time), and documents for content search and found data: `contacts.txt` (UTF-8, with planted test identifiers and a mistyped card number that fails Luhn), a Word document, an RTF, a UTF-16LE note and an OpenDocument text. `scripts/test-image/write_manifest.py` writes `dfip-test-disk.manifest.json` next to it: every generated file with its size, SHA-256, stamped time and whether it was deleted, used by the tests as ground truth. `scripts/test-image/e2e_analysis.py` uploads it to a running stack, runs Full Analysis and prints the results.

Features that can't be built synthetically on Linux (Shadow Copies, BitLocker, virtual disks, split images, SRUM, Windows Search, `$MFT`/`$UsnJrnl`, PST, APFS) are tested on public samples from dfVFS, Plaso and python-evtx (Apache-2.0): `sh scripts/test-image/fetch-samples.sh` downloads them into `storage/test-images/samples/`, pinned by commit and SHA-256 in `scripts/test-image/samples.json`, with a NOTICE file. They are never committed.

## High-volume operation

Jobs run in the `celery_worker` service (Redis broker). Scale with more workers or `--concurrency`; consider retry policy, dead-letter queues and resource isolation for production.

## Specialist validation

Tool versions, parser configurations, timezone assumptions, hash algorithms, acquisition methods and examiner actions should be recorded in case SOPs and reports. Do not treat a parser output as a conclusion without examiner review.

## Integrated specialist pipeline

DFIP now wires the forensic orchestrator to an allow-listed tool runner. The Docker image installs Sleuth Kit, libewf, ExifTool, tshark, YARA, `strings`, and `file` where available in the base distribution. The application detects tool availability at runtime and never invokes a shell command through `shell=True`.

### Examination sequence

1. Acquire evidence and calculate SHA-256.
2. Preserve the original object read-only.
3. Run `mmls` to identify partition boundaries.
4. Run `fsstat` and recursive `fls` for filesystem examination.
5. Use `istat` for inode metadata.
6. Use `icat` to recover a selected inode into the controlled analysis area.
7. Hash recovered output before further analysis.
8. Run ExifTool, strings, YARA, tshark, or Volatility against recovered/appropriate artifacts.
9. Persist tool output and provenance as forensic artifacts.
10. Record investigator actions in audit and chain-of-custody records.

The original forensic image is never passed to a tool with a write flag. Recovery outputs are stored separately under `storage/analysis/recovered`.
