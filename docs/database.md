# MongoDB

Collections: users, roles, cases, evidence, fs_entries, forensic_artifacts, timeline_events, usb_artifacts, patterns, anomalies, findings, tags, reports, chain_of_custody, audit_logs, notifications, jobs, job_sequences, desktop_devices, refresh_tokens.

- `forensic_artifacts` also holds the Windows activity records (`PROGRAM_RUN`, `RECENT_FILE`, `RECYCLE_BIN_ITEM`).
- `tags`: `{tag_id, case_id, evidence_id, item_type, item_id, match, key_hash, label, note, snapshot, created_by(_name), created_at}`; `match` is the item's natural key, so tags survive a re-analysis (unique on `case_id, item_type, key_hash`).
- `cases.legal_hold`: `{active, reason, set_by(_name), set_at, released_by(_name), released_at, release_reason}`, with every change appended to `cases.legal_hold_history`.

MongoDB is the source of truth. Evidence documents reference immutable original storage paths and SHA-256 acquisition hashes.
