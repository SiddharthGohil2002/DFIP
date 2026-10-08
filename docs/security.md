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

For production, add TLS, encrypted storage, secrets management, network segmentation, MFA/SSO, rate limiting at the edge, malware sandboxing, SIEM integration, backups, retention controls and periodic security assessment.
