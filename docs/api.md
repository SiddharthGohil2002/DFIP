# API

OpenAPI is exposed automatically by FastAPI at `/docs` and `/openapi.json`.

Core route groups: `/api/auth`, `/api/cases`, `/api/evidence`, `/api/forensics`, `/api/jobs`, `/api/findings`, `/api/tags`, `/api/chain`, `/api/notifications`, `/api/reports`, `/api/admin`, `/api/desktop`, plus `/ws`.

Recent additions:

| Route | Purpose |
|---|---|
| `POST /api/jobs/analysis/{id}` (optional body `{profile: quick\|standard\|full}` or `{modules: [...]}`) | Queue an analysis; no body = standard. 400 for an unknown profile or module, 409 while another analysis of the evidence is queued or running |
| `PUT /api/evidence/{id}/time-zone` (body `{zone: IANA name\|UTC\|null, reason}`) | Set the computer's time zone by hand (null: back to the SYSTEM hive's) and re-index; audited |
| `GET /api/forensics/computer?case_id&evidence_id` | Per evidence: computer name, Windows version, network, last shutdown, time zone and user accounts |
| `GET /api/jobs/analysis/modules` | The analysis modules (name, label, description, requirements, version) and profiles |
| `GET /api/forensics/evidence/{id}/files?category&renamed&encrypted&hash_status&hide_known&sha256` | File index filters: real type category, renamed (content contradicts the name), encrypted, hash-set status (`KNOWN_BAD`, `NOTABLE`, `KNOWN_GOOD`), hide known-good files, one SHA-256. Entries carry `md5`, `sha1`, `sha256`, `mime`, `magic`, `file_category`, `ext_mismatch`, `expected_type`, `entropy`, `encryption`, `hash_status`, `hash_sets` |
| `GET /api/forensics/hash?case_id&digest` | Every file in the case with this MD5, SHA-1 or SHA-256, and recovered, carved and extracted copies with this SHA-256; 400 if the value is not a hash |
| `GET /api/forensics/flagged?case_id&kind=renamed\|encrypted\|known_bad\|notable` | Flagged files of the case |
| `GET /api/hashsets` | Imported hash sets (every signed-in user): kind, status, format, counts per algorithm, invalid lines, source file and SHA-256 |
| `POST /api/hashsets` (multipart `file`, `name`, `kind`, `description`) | Import a hash set from an upload (`HASHSET_MANAGE`); queues a `HASHSET_IMPORT` job, then re-matches every processed evidence item |
| `GET /api/hashsets/incoming`, `POST /api/hashsets/import-local` (body `{filename, name, kind, description}`) | Large sets placed in `storage/hashsets/incoming` on the server: list and import by name (no folders) |
| `DELETE /api/hashsets/{set_id}` | Delete a set and its store, and re-match (409 while it is importing); returns the re-match job IDs |
| `GET /api/evidence/{id}` → `modules` | Each module's latest run: status, version, run ID, counts, warnings |
| `volume_id` (e.g. `p2048`) on `/forensics/evidence/{id}/files`, `/recover`, `/content`, `/preview`, `/raw` | Names the volume; the older `offset=` still works |
| `DELETE /api/evidence/{id}` (body `{reason}`) | Delete an evidence item and everything taken from it; refused (409) during an analysis and (423) under legal hold |
| `GET /api/forensics/activity?case_id&kind=PROGRAM_RUN|RECENT_FILE|RECYCLE_BIN_ITEM&search` | Windows activity records |
| `GET /api/forensics/evidence/{id}/content|preview|raw?inode&offset` and `/api/forensics/artifacts/{id}/content|preview|raw` | File viewer: hex pages (base64), type and text preview, image/PDF bytes |
| `GET/POST /api/tags`, `PATCH/DELETE /api/tags/{tag_id}` | Tags (Evidence, Notable, Follow up) on files, events, browser records, USB devices, activity records and recovered files |
| `GET /api/cases/{id}/dashboard?tz&scope=activity|all` | Activity heatmap (weekday x hour), events per day, top websites, file types, USB spans |
| `POST /api/cases/{id}/legal-hold` (body `{active, reason}`) | Place or release a legal hold |
