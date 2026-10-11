# Security Model

- Access tokens are short-lived JWTs.
- Refresh tokens are random, stored only as SHA-256 digests, rotatable and revocable.
- Passwords use PBKDF2-SHA256 with a configurable work factor and must be at least 12 characters.
- Sessions are kept in the client's session storage only: closing the desktop app or ending the browser session signs the user out, and every launch starts at the sign-in page.
- Self-service accounts (`REGISTRATION_MODE`): `approval` (default) creates them as PENDING with no access until an administrator approves them and assigns a role; `open` activates them as INVESTIGATOR (only cases they create or are assigned to); `disabled` turns sign-up off. Account status is only disclosed after a correct password, so sign-in errors do not reveal which emails exist.
- Backend permissions are enforced independently of UI visibility.
- CORS is explicitly configured.
- Uploaded evidence filenames are reduced to safe basenames.
- Upload size is bounded by configuration.
- Original evidence is chmod'd read-only after hashing.
- Audit records form a hash-linked chain with verification endpoint.
- Report downloads require `REPORT_READ` and access to the case.
- WebSockets require a valid access token, and live events (case, evidence, job, finding and report changes) are only delivered to members of the case concerned and to administrators.
- Offline changes synced from a workstation (`/desktop/sync/push`) go through the same case-access and permission checks as the online API; only whitelisted fields are written, workstation custody events are labelled `DESKTOP_*`, and offline audit events are appended to the hash chain under one fixed action name.
- The audit log shows administrators every record; other roles with `AUDIT_READ` see their own actions and actions on cases they can open.
- Evidence hashes are always computed by the server; a SHA-512 sent with an upload is only used to confirm the transfer, and a mismatch discards the upload.
- Internal `.local` email domains are accepted for accounts (common for on-premises directories).
- An image is registered once per case: an upload whose SHA-256 is already registered in the case is refused and discarded.
- Deleting evidence needs `EVIDENCE_DELETE` (administrators and investigators) and a reason, is refused while an analysis of the image runs, and is recorded in the chain of custody and the audit log; the item's history is kept.
- A case under legal hold (`LEGAL_HOLD_MANAGE`, administrators and investigators; a reason is required to place and to release it) blocks evidence deletion for everyone, administrators included (HTTP 423). Case edits and offline sync cannot change the hold.
- Tags need `FINDING_CREATE` and case access; adding, changing and removing them is audited.
- Hash sets are imported and deleted only with `HASHSET_MANAGE` (administrators); both are audited (`HASHSET_IMPORTED` with the source's SHA-256, `HASHSET_DELETED`). Server-side imports take a plain file name in `storage/hashsets/incoming` (no folders, no hidden files, no symbolic links). Every user can see which sets exist.
- Content search: every search is audited with its query; user regular expressions run in RE2 (linear time, bounded memory) under a 15-second limit. Text extraction never runs document code: Office and OpenDocument XML is parsed with defusedxml with size limits, PDFs go through `pdftotext` and SQLite databases through a separate read-only process, both under `run_tool` limits.
- Archives and embedded files are opened without trusting their member names: members are written under generated names, only regular files inside a fresh folder are taken from 7-Zip (links never followed), external tools run with a file-size limit, and size, expansion-ratio and total limits stop archive bombs. Encrypted members are listed, never decrypted. Unallocated space is streamed from `blkls` and never written to disk; reading raw volume bytes is audited.
- NTFS volumes are read by libfsntfs from the evidence's read-only image; alternate data streams are read for hashing and a text preview only (a stream's content is shown as text or hex, never run); journal paths come from the MFT, never from the evidence's own claims.
- Thumbnails are stored under their SHA-256 (never a name from the evidence), sniffed from their bytes, served only as images with `nosniff`, `attachment` and a sandbox CSP, and every view is audited (`FILE_CONTENT_VIEWED`). SQLite databases (ActivitiesCache.db, Windows.db) are opened read-only on copies; ESE databases are read by libesedb, never by Windows' own engine.
- Event logs are parsed, never executed or rendered: libevtx renders each record's XML and defusedxml parses it (entities refused); the event's XML is shown as text. Detection rules are YAML loaded with `safe_load`, validated when they load (unsupported modifiers, conditions or log sources are refused), and their regular expressions run in RE2. Event log search escapes the user's text before matching.
- Card and Aadhaar numbers found in evidence are shown masked in lists, search results and reports; showing one in full needs case access and is audited (`SENSITIVE_VALUE_REVEALED`, without the value).
- File processing reads evidence files in-process and never executes them or opens them with their own application: types come from libmagic, Office containers are parsed with olefile, ZIPs only have their central directory read, and YARA scans the bytes with a timeout per file. Encrypted files are flagged, never decrypted.
- File content shown in the viewer is read without writing a copy, typed from its first bytes (never from the name), never rendered as HTML, and served with `nosniff`, `attachment` and a sandbox CSP; each view is audited as `FILE_CONTENT_VIEWED`.

For production, add TLS, encrypted storage, secrets management, network segmentation, MFA/SSO, rate limiting at the edge, malware sandboxing, SIEM integration, backups, retention controls and periodic security assessment.
