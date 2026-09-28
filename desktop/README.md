# DFIP Investigator Desktop

DFIP Investigator is the native trusted execution environment for local digital-forensics work. The desktop shell is Tauri 2 + React/TypeScript.

## Implemented native capabilities

- SHA-256 hashing of local evidence files.
- Non-destructive evidence copy/acquisition with create-new semantics and read-only destination preservation.
- Directory/file inventory for investigation workspaces.
- Native environment information (OS/architecture/version).
- Allow-listed forensic tool inventory.
- Native execution bridge for `fls`, `istat`, `fsstat`, `mmls`, `icat`, `exiftool`, `tshark`, `yara`, `vol`, `strings`, and `file`.
- No shell interpolation / `shell=true`; arguments are passed as process arguments.
- Read-only permission control for preserved originals.
- Platform application-data location.
- Existing DFIP web console UI reused inside the desktop shell.
- Desktop Operations page for native hashing/tooling.

## Investigation workflow

1. Select or connect the local evidence source.
2. Hash the source before processing.
3. Acquire to a new destination without overwriting.
4. Mark the preserved copy read-only.
5. Send the evidence to the DFIP case/backend.
6. Run specialist tools through the allow-list.
7. Store tool output, hashes, timestamps and provenance in the backend.
8. Continue examination, findings, reporting and chain-of-custody from the same case.

## Planned native integrations

The architecture leaves explicit adapter points for physical device acquisition, EWF/libewf workflows, Plaso, registry/SRUM/Jump Lists/Prefetch/Amcache parsers, mobile acquisition providers, hardware write blockers, signed updater packages and dedicated worker processes. These must be implemented and tested per platform before being advertised as supported acquisition capabilities.
