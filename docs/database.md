# MongoDB

Collections: users, roles, cases, evidence, fs_entries, forensic_artifacts, timeline_events, usb_artifacts, patterns, anomalies, findings, tags, reports, chain_of_custody, audit_logs, notifications, jobs, job_sequences, desktop_devices, refresh_tokens, analysis_facts, pipeline_warnings.

- `forensic_artifacts` also holds the Windows activity records (`PROGRAM_RUN`, `RECENT_FILE`, `RECYCLE_BIN_ITEM`).
- Pipeline output (`fs_entries`, `timeline_events`, `forensic_artifacts`, `usb_artifacts`, `pipeline_warnings`) carries `pipeline: true`, `pipeline_module` (the analysis module that wrote it), `module_run_id` and `analysis_job_id`; each module replaces only its own documents (index on `evidence_id, pipeline_module`).
- `fs_entries` and `FILE_MACB` events carry `volume_id` (`p<start sector>`) next to `partition_offset`. Other timeline events carry `nk`, a stable natural key used to re-link tags.
- `evidence.modules.<name>`: `{status, job_id, run_id, version, counts, warnings, warnings_total, error, started_at, finished_at}` for each analysis module's latest run; `evidence.analysis_summary` merges the counts.
- `analysis_facts`: one document per evidence, `{evidence_id, <module>: {...}}`, with what one module tells the next (partitions, file systems, extracted artifacts).
- `pipeline_warnings`: every warning of every module run, `{evidence_id, case_id, message, created_at, pipeline_module, module_run_id}`.
- `jobs`: analysis jobs add `payload.profile` / `payload.modules`, and `worker`, `heartbeat_at`, `attempts` while a worker owns the job.
- `tags`: `{tag_id, case_id, evidence_id, item_type, item_id, match, key_hash, key_version, label, note, snapshot, created_by(_name), created_at}`; `match` is the item's natural key, so tags survive a re-analysis (unique on `case_id, item_type, key_hash`). Key version 2 uses `volume_id` and never a time that a time-zone correction could change; older tags are migrated at startup.
- `cases.legal_hold`: `{active, reason, set_by(_name), set_at, released_by(_name), released_at, release_reason}`, with every change appended to `cases.legal_hold_history`.

MongoDB is the source of truth. Evidence documents reference immutable original storage paths and SHA-256 acquisition hashes.
