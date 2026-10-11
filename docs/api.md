# API

OpenAPI is exposed automatically by FastAPI at `/docs` and `/openapi.json`.

Core route groups: `/api/auth`, `/api/cases`, `/api/evidence`, `/api/forensics`, `/api/jobs`, `/api/findings`, `/api/tags`, `/api/chain`, `/api/notifications`, `/api/reports`, `/api/admin`, `/api/desktop`, plus `/ws`.

Recent additions:

| Route | Purpose |
|---|---|
| `DELETE /api/evidence/{id}` (body `{reason}`) | Delete an evidence item and everything taken from it; refused (409) during an analysis and (423) under legal hold |
| `GET /api/forensics/activity?case_id&kind=PROGRAM_RUN|RECENT_FILE|RECYCLE_BIN_ITEM&search` | Windows activity records |
| `GET /api/forensics/evidence/{id}/content|preview|raw?inode&offset` and `/api/forensics/artifacts/{id}/content|preview|raw` | File viewer: hex pages (base64), type and text preview, image/PDF bytes |
| `GET/POST /api/tags`, `PATCH/DELETE /api/tags/{tag_id}` | Tags (Evidence, Notable, Follow up) on files, events, browser records, USB devices, activity records and recovered files |
| `GET /api/cases/{id}/dashboard?tz&scope=activity|all` | Activity heatmap (weekday x hour), events per day, top websites, file types, USB spans |
| `POST /api/cases/{id}/legal-hold` (body `{active, reason}`) | Place or release a legal hold |
