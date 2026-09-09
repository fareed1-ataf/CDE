# Cyber Data Engine v1.0.0 — Core Modules Quick Reference

This is a compact API reference for all core modules. For detailed documentation see [module_reference.md](../module_reference.md).

---

## `backend/main.py`

**Purpose:** FastAPI application entry point and pipeline orchestrator.

**Key API Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/pipeline/start` | Launch a pipeline job (multipart file upload) |
| `GET` | `/api/v1/pipeline/stream/{job_id}` | SSE stream of job progress events |
| `GET` | `/api/v1/pipeline/status/{job_id}` | JSON status of a specific job |
| `GET` | `/api/v1/export/alpaca` | Download `all_records.jsonl` |
| `GET` | `/api/v1/export/llama3` | Download LLaMA-3 ChatML format |
| `GET` | `/api/v1/export/rich` | Download `all_rich_records.jsonl` |
| `GET` | `/api/v1/quality/report` | Session quality statistics |
| `GET` | `/api/v1/records/sample` | Preview last N records |

**Concurrency:** Pipeline jobs run in `ThreadPoolExecutor`. LLM tasks use `asyncio.Semaphore` (2 local / 10 cloud).

---

## `backend/core/classifier.py`

**Purpose:** 4-layer deterministic content classifier. No LLM involved.

**API:**
- `classify(filename: str, preview: str) → Classification`

**Behaviour:** Applies a Hard Type Lock — code is always `CODE`, binaries are always `ATTACK_ARTIFACT`. STIX2/SIGMA `.json` files are detected and routed to `ATTACK_ARTIFACT` instead of being blocked. Generic `.json` files with no threat intel signals are classified as `IRRELEVANT`.

---

## `shared_lib/threat_scorer.py`

**Purpose:** Hybrid threat scoring engine — deterministic, no LLM.

**API:**
- `assess_threat(filename: str, content: str) → ThreatAssessment`

**Behaviour:** Combines keyword frequency, Shannon entropy, and sliding-window contextual proximity. Sets `mitre_allowed`, `ioc_allowed`, `cot_allowed` flags. MITRE generation requires the MITRE Triple-Gate: attack action verbs + exploit signals + target signals.

---

## `shared_lib/parser.py`

**Purpose:** Universal file reader and semantic chunker.

**API:**
- `FileParser.read(file_obj: BytesIO, filename: str) → str`
- `FileParser.chunk(text: str) → list[str]`

**Supported formats:** `.pdf`, `.docx`, `.xlsx`, `.csv`, `.tsv`, `.exe`, `.dll`, `.elf`, `.zip`, STIX2 `.json`, plain text, source code.

**Behaviour:** 3-stage chunking — semantic boundaries → sliding window → force split. File size limit: 20 MB.

---

## `backend/core/multi_schema_generator.py`

**Purpose:** Central orchestrator — runs the full 4-stage pipeline per chunk.

**API:**
- `generate_stream(all_items) → AsyncGenerator` — pushes SSE progress events
- `generate(chunk, cls, filename, training_goal) → MultiSchemaResult`

**Behaviour:** For each chunk: assess threat → detect capabilities → plan schemas → generate → validate → post-validate. Rejects CoT if `cot_allowed=False`.

---

## `backend/core/strategy_planner.py`

**Purpose:** Maps cybersecurity skills to a prioritised list of output schemas.

**API:**
- `StrategyPlanner.plan(skills: list[CyberSkill], threat_level: ThreatLevel) → list[DataSchema]`

---

## `shared_lib/validator.py`

**Purpose:** LLM output validator, Pydantic parser, and quality gate.

**API:**
- `validate(raw: str, cls: Classification, source_file: str, source_chunk: str, min_quality: float) → ValidationResult`

**Behaviour:** 4-strategy JSON extraction → Pydantic validation → quality scoring → min_quality rejection. Falls back to Alpaca format on parse failure. All 13 schema validators accept `source_chunk` for grounding checks.

---

## `backend/core/providers.py`

**Purpose:** Unified Model Gateway via LiteLLM.

**API:**
- `ModelGateway.generate(system_prompt, user_prompt, schema) → str`

**Routing strategies:** `PRIMARY_FALLBACK`, `ROUND_ROBIN`, `FASTEST`, `SCHEMA_ROUTE`

**Supported backends:** Ollama, Groq, OpenAI-compatible APIs (vLLM, LM Studio, etc.)

---

## `backend/core/state_manager.py`

**Purpose:** Persistence layer — thread-safe cache and output writer.

**API:**
- `is_cached(text: str) → bool` — checks `config/cache.db` (SQLite, thread-safe)
- `add_to_cache(text: str) → None` — `INSERT OR IGNORE` under `threading.Lock`
- `append_to_output(source_filename: str, records: list[str], is_rich: bool) → None`
- `save_providers(providers: list[ProviderConfig]) → None`
- `load_providers() → list[ProviderConfig]`

**Cache backend:** SQLite (`config/cache.db`) — replaced JSON file in v1.0.0 to eliminate concurrent write race condition.

---

## `shared_lib/post_validator.py`

**Purpose:** Anti-hallucination post-processing.

**API:**
- `post_validate(result: ValidationResult, threat: ThreatAssessment, chunk: str) → PostValidationResult`

**Behaviour:** MITRE scrubbing, IOC scrubbing, severity normalisation, label contamination fix, confidence penalty.

---

## `shared_lib/attack_evidence_extractor.py`

**Purpose:** Validates MITRE IDs against actual evidence in source text.

**API:**
- `extract_evidence(mitre_ids: list[str], chunk: str) → tuple[list[str], list[str]]` — returns `(validated, stripped)`

**Behaviour:** 38+ regex patterns, one per MITRE technique. IDs with no regex match are classified as hallucinated.
