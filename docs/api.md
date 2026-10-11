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
| `GET /api/evidence/{id}` → `modules` | Each module's latest run: status, version, run ID, counts, warnings |
| `volume_id` (e.g. `p2048`) on `/forensics/evidence/{id}/files`, `/recover`, `/content`, `/preview`, `/raw` | Names the volume; the older `offset=` still works |
| `DELETE /api/evidence/{id}` (body `{reason}`) | Delete an evidence item and everything taken from it; refused (409) during an analysis and (423) under legal hold |
| `GET /api/forensics/activity?case_id&kind=PROGRAM_RUN|RECENT_FILE|RECYCLE_BIN_ITEM&search` | Windows activity records |
| `GET /api/forensics/evidence/{id}/content|preview|raw?inode&offset` and `/api/forensics/artifacts/{id}/content|preview|raw` | File viewer: hex pages (base64), type and text preview, image/PDF bytes |
| `GET/POST /api/tags`, `PATCH/DELETE /api/tags/{tag_id}` | Tags (Evidence, Notable, Follow up) on files, events, browser records, USB devices, activity records and recovered files |
| `GET /api/cases/{id}/dashboard?tz&scope=activity|all` | Activity heatmap (weekday x hour), events per day, top websites, file types, USB spans |
| `POST /api/cases/{id}/legal-hold` (body `{active, reason}`) | Place or release a legal hold |
