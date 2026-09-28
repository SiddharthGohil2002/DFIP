# Changelog

## Unreleased

### Fixed
- `POST /api/forensics/demo/seed/{case_id}` could previously be called on any real case with evidence, injecting synthetic ("DEMO_DATA") timeline events and artifacts with no check that the case was actually a demo case. Now requires `DEMO_MODE=true` and that both the case and its evidence record are explicitly flagged `demo: true`.

### Added
- **Redis + Celery job pipeline.** Replaced the in-process `threading` worker loop with real Celery tasks (`app/tasks.py`) on a Redis broker/backend. Jobs now survive API process restarts and can scale across multiple worker processes. New `celery_worker` service in `docker-compose.yml`. Job cancellation now attempts real Celery task revocation.
- **Browser artifact parsing** (`app/forensic/browser_artifacts.py`): real SQLite parsers for Chromium (Chrome/Edge/Brave) `History`/`Cookies` and Firefox `places.sqlite`/`cookies.sqlite`. Always operates on a scratch copy, never the original evidence file. Chromium cookie *values* are intentionally not decrypted (OS-keychain-encrypted) — only metadata is extracted, to avoid fabricating a "decrypted" value.
- **File carving** (`app/forensic/carving.py`): real PhotoRec and Scalpel subprocess wrappers following the same allow-list/no-shell pattern as `forensic/tools.py`. Every recovered file is SHA-256 hashed and registered as a chain-of-custody-tracked artifact. New endpoint: `POST /api/forensics/evidence/{eid}/carve`.
- **Threat intelligence connectors** (`app/threatintel/client.py`): real HTTP clients for VirusTotal (hash lookup), AbuseIPDB (IP reputation), AlienVault OTX (indicator pulses), and URLhaus (host/URL lookup, no key required). Providers without a configured API key return an explicit `NOT_CONFIGURED` status rather than a fabricated verdict. Results are cached in MongoDB with full raw-response provenance. New router: `app/api/threatintel.py`.
- **Real ML anomaly detection** (`app/analysis/services.py::MLAnomalyService`): scikit-learn `IsolationForest` over per-event feature vectors. Requires at least 15 timeline events to run; below that threshold it returns `INSUFFICIENT_DATA` and the API falls back to the existing rule-based `AnomalyService` rather than presenting an unreliable ML score as if it were meaningful.
- **Real AI retrieval** (`app/ai/services.py::VectorSearchService`): TF-IDF + cosine similarity search over a case's forensic artifacts, replacing the previous no-op that always returned `[]`. Lexical rather than embedding-based, by design, so results stay fully auditable without requiring an external embedding API key.
- New frontend/desktop pages: Threat Intelligence lookup, File Carving trigger — wired to the endpoints above in both the web frontend and the Tauri desktop app.

### Known limitations (see README for full inventory)
- Threat intel and ML features require configuration/data to produce real results (see .env.example); this is intentional, not a bug.
- This phase was built and syntax-checked without Docker/network access in the build environment. Full integration testing (`docker compose up`, live job execution, live provider lookups) should be run in your own environment before relying on this in casework.
