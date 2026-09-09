# Cyber Data Engine v1.0.0 — Deployment & Operations Guide

---

## 1. Production Readiness Assessment

### Strengths

| Area | Status |
|------|--------|
| **Zero-Hallucination Guard** | ✅ Strong — `ThreatScorer` + `PostValidator` + `AttackEvidenceExtractor` use deterministic rules. The LLM cannot override classification or attribution decisions. |
| **Backend Resilience** | ✅ Good — FastAPI with `ThreadPoolExecutor` keeps the API responsive during long processing jobs. |
| **Provider Failover** | ✅ Good — `ModelGateway` supports `PRIMARY_FALLBACK` strategy. Failed providers are retried then skipped. |
| **Error Isolation** | ✅ Good — LLM failures produce a failed `ValidationResult` (graceful degradation) rather than crashing the pipeline. All exceptions are logged to `logs/engine.log`. |
| **Cache Safety** | ✅ Fixed (v1.0.0) — SQLite + `threading.Lock` eliminates the JSON file race condition present in pre-release versions. |
| **CORS Security** | ✅ Fixed (v1.0.0) — Replaced wildcard `allow_origins=["*"]` + `allow_credentials=True` with explicit localhost origins. |

### Known Limitations

| Area | Risk | Mitigation |
|------|------|------------|
| **Global deduplication** | Records across multiple pipeline runs can be semantically duplicate | Use a clean `output/` directory per dataset; planned: Vector Store dedup |
| **In-memory session state** | `_jobs` and `_stats` are lost on server restart | Export data before restarting; planned: Redis/DB state |
| **Synchronous FileParser** | Large files (>50 MB) can block the processing thread | Keep `chunk_size` small; split large files before uploading |
| **Output append not locked** | Under extreme concurrent load, JSONL lines could interleave | Acceptable for single-user local use; add `threading.Lock` for multi-user deployments |

---

## 2. System Requirements

### Hardware

| Mode | CPU | RAM | GPU |
|------|-----|-----|-----|
| Cloud API (Groq / OpenAI-compatible) | 2+ cores | 4 GB | Not required |
| Local LLM — 7B model (Ollama) | 4+ cores | 16 GB | 8 GB VRAM minimum |
| Local LLM — 13B model | 8+ cores | 32 GB | 16 GB VRAM |
| Local LLM — 70B model | 16+ cores | 64 GB | 40+ GB VRAM (A100/H100) |

### Dependencies

Key packages from `requirements.txt`:

| Package | Purpose |
|---------|---------|
| `fastapi`, `uvicorn` | API server |
| `litellm` | Unified LLM client (Ollama, Groq, OpenAI, etc.) |
| `pdfplumber` | PDF text extraction |
| `python-docx` | DOCX parsing |
| `openpyxl` | Excel/XLSX parsing |
| `pydantic` | Schema validation |
| `chardet` | Encoding detection |

---

## 3. Running the Server

### Development Mode

```bash
# Recommended for development — auto-reload on file changes
uvicorn backend.main:app --host 127.0.0.1 --port 59919 --reload

# Windows quick-start
start_web.bat
```

### Production Mode (Linux / Docker)

**Do NOT use `--reload` in production.** Use Gunicorn with Uvicorn workers:

```bash
# Gunicorn with 4 workers, 300s timeout for long generation jobs
gunicorn backend.main:app \
  -k uvicorn.workers.UvicornWorker \
  -w 4 \
  --timeout 300 \
  --bind 127.0.0.1:59919
```

> **Important:** The `-t 300` / `--timeout 300` parameter prevents Gunicorn from killing a worker during long LLM generation tasks.

### Docker Deployment

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 59919
CMD ["gunicorn", "backend.main:app", "-k", "uvicorn.workers.UvicornWorker", "-w", "2", "--timeout", "300", "--bind", "0.0.0.0:59919"]
```

Mount persistent volumes for:
- `config/` — provider config and SQLite cache
- `output/` — generated datasets
- `logs/` — engine logs

```bash
docker run -p 59919:59919 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/logs:/app/logs \
  cyber-data-engine:latest
```

---

## 4. Provider Configuration

**Never hardcode API keys.** Use environment variables with the `${VAR}` syntax in `config/providers.json`:

```bash
# Set environment variables before starting
export GROQ_API_KEY="gsk_your_key_here"
export OPENAI_API_KEY="sk-your_key_here"
```

```json
[
  {
    "name": "groq-primary",
    "provider_type": "openai_compatible",
    "endpoint": "https://api.groq.com/openai/v1",
    "model": "llama-3.3-70b-versatile",
    "api_key": "${GROQ_API_KEY}",
    "temperature": 0.15,
    "max_tokens": 8000,
    "timeout": 60,
    "max_retries": 3,
    "enabled": true,
    "preferred_schemas": []
  }
]
```

> **Note:** `config/providers.json` is excluded from Git by `.gitignore`. Never commit this file.

---

## 5. Logging

The engine writes structured logs to `logs/engine.log`.

In production, set up log rotation to prevent disk exhaustion:

```bash
# Linux — using logrotate
cat > /etc/logrotate.d/cyber-data-engine << EOF
/path/to/app/logs/engine.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
EOF
```

Key log markers to monitor:

| Marker | Meaning |
|--------|---------|
| `[SKIP]` | File already cached — normal |
| `[IRRELEVANT]` | File blocked by relevance filter — expected |
| `[FAIL]` | Record rejected — check quality score or provider error |
| `[ERROR]` | LLM call failed — check provider connectivity |
| `Dispatching to` | Debug: schema dispatch log |

---

## 6. Data Management

| Path | Contents | Backup Priority |
|------|----------|-----------------|
| `output/all_records.jsonl` | Primary Alpaca training dataset | **Critical** |
| `output/all_rich_records.jsonl` | Rich metadata dataset | High |
| `config/providers.json` | Provider config (contains API key refs) | High |
| `config/cache.db` | Processed file hashes (SQLite) | Medium — can be rebuilt |
| `logs/engine.log` | Engine operation log | Low |

---

## 7. Roadmap — Enterprise-Grade Improvements

For scaling beyond single-user local use:

| Feature | Description | Priority |
|---------|-------------|----------|
| **Global Semantic Deduplication** | Replace chunk-level Jaccard dedup with a Vector Store (FAISS / ChromaDB) for cross-session similarity checking at `>85%` threshold | High |
| **Persistent Session State** | Move `_jobs` and `_stats` from in-memory to Redis or SQLite for crash-safe job resumption | High |
| **Depth Classifier** | Reject shallow CoT reasoning that merely paraphrases the question rather than providing genuine analytical insight | Medium |
| **Dataset Balance Report** | Auto-generate schema distribution, severity distribution, and task type diversity reports after each pipeline run | Medium |
| **LLM-as-Judge** | Use a stronger model to score outputs from weaker models — catches records that pass `min_quality=0.35` but contain low-value content | Low (resource-intensive) |
