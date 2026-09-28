# Architecture

React/TypeScript → FastAPI → service/repository layer → MongoDB.

Admin and Investigator use the same API and database. WebSocket events are user-scoped and used for notifications and important synchronization. Original evidence is stored separately from analysis outputs and reports.

Future: Redis for caching/jobs, S3-compatible object storage for large evidence, and a vector database behind `VectorSearchService` for RAG.
