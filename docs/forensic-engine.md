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
9. **YARA** (module `yara`): user-profile scripts and executables (bounded: 200 files, 20 MB each) are extracted and scanned with `backend/rules/default.yar`; matches become `MALWARE_INDICATOR` artifacts.
10. **Tags** (runs after every job): tags on this evidence's items are re-linked to the new records by their natural key (see `app/services/tags.py`).
11. **Case analytics** (runs after every job): patterns and anomalies are recomputed for the case.

Everything written carries `analysis_job_id`, `pipeline_module` and `module_run_id` for provenance.

### Analysis modules and profiles

| Module | Needs | Writes |
|---|---|---|
| `fs_index` File system index | - | `fs_entries`, `FILE_MACB` events, facts `partitions`, `offsets`, `filesystems` |
| `artifacts` Browser, USB and Windows activity | `fs_index` | `EXTRACTED_FILE`, browser, USB and activity records and events |
| `yara` YARA scan | `fs_index` | `MALWARE_INDICATOR` |

- **Profiles:** `quick` (`fs_index`, `artifacts`), `standard` (all three; the default when the request has no body) and `full` (everything, including the slower content modules as they are added). A request may instead name `modules`.
- **Run plan:** the requested modules, plus any prerequisite that has not completed (or was written by an older module version), plus every module that depends on something being re-run and had completed before. Re-running `yara` runs only `yara`; re-running `fs_index` also refreshes `artifacts` and `yara`.
- **Own output only:** a module first deletes its previous documents (`pipeline_module=<name>`) and its facts; nothing else is touched, so the other modules' records keep their IDs. Output written before modules existed (no `pipeline_module`) is replaced as a whole by a standard run.
- **Status:** each module's status, version, run ID, counts and first warnings are kept on the evidence (`modules.<name>`); `analysis_summary` and the job summary merge the counts of every module's latest completed run, so a partial re-run still reports the whole evidence. All warnings go to `pipeline_warnings`; the job summary keeps the first 200 (`warnings_total` has the number).
- **Jobs:** one analysis per evidence at a time (another request returns 409). A worker claims a queued job atomically and sends heartbeats; a redelivered message for a job another worker owns, or that already finished, is ignored (`DUPLICATE_IGNORED`). If a worker dies, the job is taken over once its heartbeat is 10 minutes old and continues after the modules it had completed. The Celery visibility timeout is longer than the longest allowed analysis, so a long job is not redelivered while it runs.
- **External tools** run through `run_tool` (`app/forensic/modules/base.py`): no shell, an own process group, a 4 GiB address-space limit, a timeout, and a cancellation check every 2 seconds that kills the whole process group.
- **Work folders** (`storage/analysis/pipeline/<EVID>/<JOB>/`) of earlier jobs are removed once no module's current output refers to them.

### Evidence sources

`app/forensic/source.py` puts evidence content behind one interface: `TskImageSource` reads a disk image (or an E01's raw working copy) in-process with pytsk3, and `DirectorySource` reads a folder of loose files (later: unpacked triage packages). A volume is named by a `volume_id` (`p<start sector>`, `p0` for a bare file system; later `p<start>/vss<n>` and `pkg`); `fs_entries`, `FILE_MACB` events and the content, preview, raw and recover endpoints accept it next to the older `offset=`. The system tests check that pytsk3 reads every file (including deleted ones) byte for byte as `icat` does.

### Deleted file recovery

`GET /api/forensics/evidence/{id}/files?deleted=true` lists deleted entries from the index; `POST /api/forensics/evidence/{id}/recover?inode=&offset=` recovers one with `icat` (NTFS `64-128-2` addresses are accepted), hashes it, records it in the chain of custody and keeps the original filename. `GET /api/forensics/artifacts/{artifact_id}/download` returns the recovered copy with its SHA-256 in `X-DFIP-SHA256`. Signature carving of unallocated space (`/carve`) uses PhotoRec (all signatures except the noisy `dovecot` one) or Scalpel with `backend/rules/scalpel.conf`.

### File viewer

`GET /api/forensics/evidence/{id}/content|preview|raw?inode=&offset=` reads a file inside the image without writing a copy: `icat` is streamed and only the requested bytes are kept (hex pages of up to 64 KiB, up to 256 MiB into the file; recover the file to go further). The same three endpoints exist under `/api/forensics/artifacts/{artifact_id}/` for recovered, carved and extracted files. The type shown is decided from the first bytes (PNG, JPEG, GIF, WebP, BMP, PDF, text), never from the name; HTML and SVG are shown as text, and images and PDFs (up to 20 MB) are served with `nosniff`, `Content-Disposition: attachment` and a sandbox Content-Security-Policy. Each view is recorded in the audit log (`FILE_CONTENT_VIEWED`).

### Known limitations

- FAT timestamps are stored by Windows in local time; Sleuth Kit reports them as UTC unless told the zone, so FAT `FILE_MACB` times are local time. NTFS times are true UTC.
- Only allocated artifact files are parsed automatically; deleted browser databases or hives must be recovered and parsed manually (`/artifacts/{id}/browser-parse?kind=`).
- Chromium cookie values are not decrypted (DPAPI); Firefox downloads before version 26 (`downloads.sqlite`) are not read.
- The Celery hard time limit (`CELERY_TASK_TIME_LIMIT`, default 30 min) bounds analysis of very large images; raise it for multi-terabyte evidence.
- Multi-segment E01 sets (`.E02`...) are not supported by upload yet.
- An E01 needs free space for its raw working copy (the full media size) in `storage/analysis/working`. Partitions, file details and recovery for an E01 are available once its first analysis has prepared the copy.
- AFF/AFF4 uploads are accepted but have not been tested with this Sleuth Kit build.
- Jump Lists (`AutomaticDestinations-ms`) and shell-item (IDList) details of shortcuts are not parsed. Shortcut header times describe the target file, not when it was opened.
- Prefetch format version 31 (Windows 11 24H2) is read by libscca but has not been verified with DFIP; an unexpected version is reported as a warning.

## Test image

`scripts/test-image/make-test-image.sh` builds a 64 MiB MBR/FAT32 image with a Windows-like layout: a real Windows 7 SYSTEM hive (regipy test data, MIT) with a USB device, a synthetic `setupapi.dev.log`, Chrome and Firefox history, a deleted CSV and a PowerShell script that triggers the YARA rule, plus Windows activity (a Prefetch file for SecureDelete.exe, a Recent shortcut to `E:payroll-export.csv` on the SanDisk drive and a Recycle Bin `$I`/`$R` pair for the payroll export, written by `backend/tests/fixtures/winfmt.py`), a PNG and a PDF for the file viewer. `scripts/test-image/write_manifest.py` writes `dfip-test-disk.manifest.json` next to it: every generated file with its size, SHA-256, stamped time and whether it was deleted, used by the tests as ground truth. `scripts/test-image/e2e_analysis.py` uploads it to a running stack, runs Full Analysis and prints the results.

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
