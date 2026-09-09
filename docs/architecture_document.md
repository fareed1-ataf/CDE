# Cyber Data Engine — System Architecture

## 1. Architectural Overview

**Cyber Data Engine** is a deterministic, multi-stage pipeline that converts raw cybersecurity files into high-quality instruction-tuning datasets for fine-tuning Large Language Models (LLMs). It is designed around three core principles:

- **Determinism Before LLM:** Rule-based algorithms (Regex, Jaccard, entropy scoring) classify and threat-assess content *before* it reaches an LLM. This prevents hallucination at the source.
- **Dynamic Schema Routing:** Content is routed to different output schemas (Chain-of-Thought, QA, Threat Hunting, etc.) based on detected capabilities, chosen training goal, and threat level.
- **Asynchronous Processing:** A `ThreadPoolExecutor` + `asyncio` architecture enables real-time Server-Sent Events (SSE) progress updates while jobs run in background threads.

---

## 2. System Layers

```
┌─────────────────────────────────────────────────────────┐
│                  Presentation Layer                      │
│       Vanilla JS SPA  ←→  SSE  ←→  REST API             │
├─────────────────────────────────────────────────────────┤
│                    API Layer                             │
│              FastAPI  (backend/main.py)                  │
├─────────────────────────────────────────────────────────┤
│                 Core Engine Layer                        │
│  Classifier → ThreatScorer → CapabilityDetector          │
│  SkillExtractor → StrategyPlanner → MultiSchemaGenerator │
│                 ModelGateway (LLM call)                  │
├─────────────────────────────────────────────────────────┤
│           Shared Libraries & Validation Layer            │
│  validator.py → post_validator.py → grounding_validator  │
│  attack_evidence_extractor.py  ←  schemas.py             │
├─────────────────────────────────────────────────────────┤
│               Persistence Layer                          │
│   state_manager.py  (SQLite cache + JSONL append)        │
└─────────────────────────────────────────────────────────┘
```

### 2.1 Presentation Layer
- Single-page application (SPA) built with Vanilla JavaScript and CSS.
- Location: `frontend/` (`index.html`, `app.js`, `style.css`)
- Communicates with the backend via REST APIs and Server-Sent Events for real-time progress display.

### 2.2 API Layer
- Built with **FastAPI** (`backend/main.py`).
- Endpoints: provider management, pipeline job submission, status monitoring, dataset export.
- Jobs run in `ThreadPoolExecutor` threads; progress is streamed via SSE (`/api/v1/pipeline/stream`).

### 2.3 Core Engine Layer
- Houses the classification and routing intelligence (`backend/core/`).
- See [module_reference.md](module_reference.md) for per-module details.

### 2.4 Shared Libraries & Validation Layer
- Pydantic models, threat scoring, grounding validation, and anti-hallucination scrubbing (`shared_lib/`).

### 2.5 Persistence Layer
- `state_manager.py`: SQLite-backed content-hash cache (thread-safe) + JSONL output appender.

---

## 3. Full Data Flow — 10 Stages

Every file uploaded to the system passes through the following stages in sequence:

| # | Stage | Module | Description |
|---|-------|--------|-------------|
| 1 | **Ingestion & Parsing** | `shared_lib/parser.py` | File is read and split into overlapping text chunks of configurable size. |
| 2 | **Cache Check** | `state_manager.py` | MD5 hash of the full file is checked against `cache.db`. Already-processed files are skipped instantly. |
| 3 | **Relevance Filtering** | `classifier.py` | Cyber-keyword density is scored. Files scoring < 0.12 are classified as `IRRELEVANT` and dropped. |
| 4 | **Content Classification** | `classifier.py` | Assigns `DataType` (CODE, ATTACK_ARTIFACT, DATA, etc.), initial `DataSchema`, and `TaskType` per chunk. |
| 5 | **Threat Assessment** | `shared_lib/threat_scorer.py` | Determines if content is BENIGN, SUSPICIOUS, or MALICIOUS. Controls whether MITRE IDs, IOCs, and CoT reasoning are permitted in output. |
| 6 | **Capability Detection** | `backend/core/capability_detector.py` | Identifies what the chunk can teach: code review, log analysis, forensics, threat hunting, etc. |
| 7 | **Skill Extraction & Strategy Planning** | `skill_extractor.py` + `strategy_planner.py` | Maps detected capabilities + training goal to a list of `DataSchema` targets to generate. |
| 8 | **LLM Generation** | `multi_schema_generator.py` + `providers.py` | Builds schema-specific prompts and calls the LLM via `ModelGateway`. Runs up to 10 concurrent requests in cloud mode. |
| 9 | **Schema Validation & Quality Scoring** | `shared_lib/validator.py` | Parses raw LLM output into Pydantic models. Calculates a quality score. Records scoring below `min_quality` (default: 0.35) are rejected. |
| 10 | **Post-Validation & Anti-Hallucination** | `shared_lib/post_validator.py` | Scrubs hallucinated MITRE IDs (not evidenced in source chunk). Normalises severity for BENIGN content. Appends valid records to `output/all_records.jsonl`. |

---

## 4. Module Call Sequence (Actual Code Path)

```
main.py  ──►  _parse_and_classify_sync()
               │
               ├─► FileParser.chunk()
               ├─► ContentClassifier.classify()
               │
               └─► MultiSchemaGenerator.generate()
                    │
                    ├─► assess_threat()
                    ├─► DeepContentAnalyzer.analyze()
                    ├─► CapabilityDetector.detect()
                    ├─► SkillExtractor.extract_skills()
                    ├─► StrategyPlanner.plan()
                    │
                    └─► [per schema]
                         ├─► ModelGateway.generate()   →  LLM
                         ├─► validator.validate()
                         └─► post_validator.post_validate()
                              ├─► GroundingValidator
                              └─► AttackEvidenceExtractor
```

---

## 5. Concurrency Model

| Mode | Semaphore Limit | Notes |
|------|-----------------|-------|
| Local (Ollama / vLLM) | 2 concurrent tasks | Prevents GPU VRAM exhaustion |
| Cloud (Groq / OpenAI-compatible) | 10 concurrent tasks | Rate-limited by provider |

- Pipeline jobs run in `ThreadPoolExecutor` threads.
- SQLite cache uses `threading.Lock` to prevent concurrent write races.
- SSE events are pushed to per-job `queue.Queue` objects consumed by the frontend.

---

## 6. Known Architectural Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Global deduplication is per-session only | Duplicate records may appear across pipeline runs | Use the `is_cached()` file-level check; re-run on a clean `output/` directory |
| In-memory job state (`_jobs`, `_stats`) | Stats are lost on server restart | Export via `/api/v1/quality/report` before restarting |
| `FileParser` runs synchronously (blocking) | Large files (>50MB) will block the thread | Set `chunk_size` smaller to reduce per-chunk processing time |
| Output append is not lock-protected | Write interleaving possible under extreme load | Single-threaded `append_to_output` is safe for normal use; add `threading.Lock` for high-throughput deployments |
