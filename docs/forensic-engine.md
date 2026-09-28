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

## High-volume operation

The durable MongoDB job queue supports `HASH_VERIFY` and `FORENSIC_ANALYSIS`. A production deployment should move the worker into a dedicated service/container and add horizontal worker scaling, retry policy, dead-letter queues and resource isolation.

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
