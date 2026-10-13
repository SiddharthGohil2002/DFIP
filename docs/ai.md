# AI architecture

AI is an investigation assistant, not the source of truth.

**Case summary** (`GET /api/cases/{id}/summary`, Case summary page): numbered facts (F1, F2 ...) built from the stored records alone, in sections (evidence; computers, phones and users; USB devices; files of interest; data leaving the computer; programs and malware indicators; when the computer was used; findings and tags), each citing the records it rests on, and paragraphs that join them. The same records always give the same summary; nothing is inferred.

**Claude mode** (optional, off for every case): when someone who may update the case turns it on, an investigator can tick facts of the summary and ask a question. Only those facts and the question are sent to Claude (`ANTHROPIC_MODEL`, default `claude-opus-5-5`, medium effort, through the official `anthropic` SDK with a server-side refusal fallback); the system prompt asks for answers drawn from the facts alone, each statement citing its facts. Citations of facts that were not sent are flagged; a refusal is reported as such. Every request is kept (`ai_requests`) with the exact prompt and its SHA-256 and audited (`AI_PROMPT_SENT`). `ANTHROPIC_BASE_URL` points requests at a proxy (the tests use a stand-in).

The older retrieval endpoint (`POST /api/forensics/ai`, TF-IDF over the case's records, no model) is unchanged. Future RAG flow: question → authorized MongoDB retrieval → optional vector semantic retrieval → model → evidence references. AI must not invent timestamps, hashes, files, IPs, users, or findings and should explicitly label interpretation.
