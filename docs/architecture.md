# Architecture

React/TypeScript → FastAPI → service/repository layer → MongoDB.

Admin and Investigator use the same API and database. WebSocket events are user-scoped and used for notifications and important synchronization. Original evidence is stored separately from analysis outputs and reports.

Jobs run on Celery with Redis as the broker: the `celery_worker` service runs analysis and other jobs, and the `celery_beat` service starts scheduled work (the daily retention check at 02:00 UTC).

Future: Redis for caching/jobs, S3-compatible object storage for large evidence, and a vector database behind `VectorSearchService` for RAG.
