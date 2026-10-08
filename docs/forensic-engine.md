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

`POST /api/jobs/analysis/{evidence_id}` queues a `FORENSIC_ANALYSIS` Celery job (`app/tasks.py`) that runs `app/forensic/pipeline.py`:

1. **Integrity**: re-hash the original image (SHA-256) and refuse to continue if it no longer matches the acquisition hash. The check is logged to the chain of custody.
   - **E01/EX01 only** (`app/forensic/working_image.py`): the Sleuth Kit build in the image (4.12 with libewf 20140816) crashes on EWF images, so the E01 is checked with `ewfverify`, exported once with `ewfexport` to a raw working copy in `storage/analysis/working/<EVID>.raw`, trimmed to the media size and compared with the MD5 stored in the E01. A corrupt E01 or a mismatch stops the analysis. The copy (read-only) is recorded in the chain of custody as `WORKING_COPY_CREATED` with its SHA-256, and every later tool (`mmls`, `fls`, `icat`, `istat`, carving) reads it. The uploaded E01 is never modified and is still what integrity checks hash.
2. **Partitions**: `mmls`; every non-meta, allocated, non-extended slot is examined. An image without a partition table is examined at offset 0.
3. **Filesystem index**: per partition, `fsstat` (filesystem type) and `fls -r -m /` written to a bodyfile under `storage/analysis/pipeline/<EVID>/<JOB>/`. Every entry, allocated or deleted, goes into the `fs_entries` collection (`app/forensic/filesystem.py`).
4. **Timeline**: one `FILE_MACB` event per distinct timestamp of each entry, labelled like `mactime` (`m.cb` etc.) (`app/forensic/timeline.py`). The bodyfile is kept so results can be re-checked with `mactime -b`.
5. **Artifact extraction** (`app/forensic/artifact_locator.py`): known paths are matched while the listing streams and copied out with `icat`, keeping their names and SQLite `-journal`/`-wal` sidecars:
   - Chrome / Edge / Brave / Chromium `.../User Data/<profile>/History`
   - Firefox `.../Profiles/<profile>/places.sqlite`
   - `Windows/System32/config/SYSTEM`
   - `Windows/INF/setupapi.dev*.log`
6. **Browser history** (`app/forensic/browser_artifacts.py`): visits and downloads (Chromium `urls`/`downloads`; Firefox `moz_places` and `moz_annos` download annotations), stored as `BROWSER_HISTORY` / `BROWSER_DOWNLOAD` artifacts and timeline events.
7. **USB history** (`app/forensic/usb.py`, using `regipy`): `Enum\USBSTOR` (vendor, product, revision, serial, friendly name), `Enum\USB` (VID/PID), `MountedDevices` (drive letter, volume GUID), and the device-property timestamps `0064` first install, `0065` last install, `0066` last arrival, `0067` last removal (Windows 7 and 8+ layouts). `setupapi.dev.log` first-install times are converted to UTC with the hive's `ActiveTimeBias`. Results go to `usb_artifacts` and `USB_ACTIVITY` timeline events.
8. **YARA**: user-profile scripts and executables (bounded: 200 files, 20 MB each) are extracted and scanned with `backend/rules/default.yar`; matches become `MALWARE_INDICATOR` artifacts.
9. **Case analytics**: patterns and anomalies are recomputed for the case.

Re-running the job replaces that evidence item's previous pipeline output. Everything written carries `analysis_job_id` for provenance.

### Deleted file recovery

`GET /api/forensics/evidence/{id}/files?deleted=true` lists deleted entries from the index; `POST /api/forensics/evidence/{id}/recover?inode=&offset=` recovers one with `icat` (NTFS `64-128-2` addresses are accepted), hashes it, records it in the chain of custody and keeps the original filename. `GET /api/forensics/artifacts/{artifact_id}/download` returns the recovered copy with its SHA-256 in `X-DFIP-SHA256`. Signature carving of unallocated space (`/carve`) uses PhotoRec (all signatures except the noisy `dovecot` one) or Scalpel with `backend/rules/scalpel.conf`.

### Known limitations

- FAT timestamps are stored by Windows in local time; Sleuth Kit reports them as UTC unless told the zone, so FAT `FILE_MACB` times are local time. NTFS times are true UTC.
- Only allocated artifact files are parsed automatically; deleted browser databases or hives must be recovered and parsed manually (`/artifacts/{id}/browser-parse?kind=`).
- Chromium cookie values are not decrypted (DPAPI); Firefox downloads before version 26 (`downloads.sqlite`) are not read.
- The Celery hard time limit (`CELERY_TASK_TIME_LIMIT`, default 30 min) bounds analysis of very large images; raise it for multi-terabyte evidence.
- Multi-segment E01 sets (`.E02`...) are not supported by upload yet.
- An E01 needs free space for its raw working copy (the full media size) in `storage/analysis/working`. Partitions, file details and recovery for an E01 are available once its first analysis has prepared the copy.
- AFF/AFF4 uploads are accepted but have not been tested with this Sleuth Kit build.

## Test image

`scripts/test-image/make-test-image.sh` builds a 64 MiB MBR/FAT32 image with a Windows-like layout: a real Windows 7 SYSTEM hive (regipy test data, MIT) with a USB device, a synthetic `setupapi.dev.log`, Chrome and Firefox history, a deleted CSV and a PowerShell script that triggers the YARA rule. `scripts/test-image/e2e_analysis.py` uploads it to a running stack, runs Full Analysis and prints the results.

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
