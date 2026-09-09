# Cyber Data Engine v1.0.0 — Architecture Overview

## 1. System Design Pattern

Cyber Data Engine is a **concurrent, multi-stage processing pipeline** with an asynchronous FastAPI backend and a stateless, deterministic intelligence core. It ingests raw cybersecurity files and outputs structured, hallucination-free instruction-tuning datasets for LLM fine-tuning.

---

## 2. Core Layers

### Input Layer
**Files:** `backend/main.py`, `shared_lib/parser.py`

- **API Server:** FastAPI handles HTTP requests and streams real-time progress via Server-Sent Events (SSE).
- **Universal Parser:** Extracts plain text from PDFs, DOCX, CSVs, Executables (PE/ELF), STIX2/SIGMA JSON, and plain text/code files. Applies semantic chunking with configurable overlap.

### Intelligence Core (Deterministic — No LLM)
**Files:** `backend/core/classifier.py`, `shared_lib/threat_scorer.py`

- **Classifier:** 4-layer inspection (extension → filename signals → keyword patterns → entropy scoring) that assigns a Hard Type Lock (`DataType`, `DataSchema`, `TaskType`).
- **Threat Scorer:** Hybrid scoring engine using Shannon entropy, keyword density, and sliding-window context proximity. Gates MITRE attribution, IOC extraction, and CoT usage based on threat level.
- **Capability Detector → Skill Extractor → Strategy Planner:** Determines what training schemas to generate based on content capabilities and the user's chosen Training Goal.

### Generation Layer (LLM)
**Files:** `backend/core/strategy_planner.py`, `backend/core/providers.py`, `backend/core/multi_schema_generator.py`

- **Strategy Planner:** Selects optimal schemas based on detected skills and training goal.
- **Model Gateway:** Manages local (Ollama, vLLM) and cloud LLMs (Groq, OpenAI-compatible) via LiteLLM. Supports ROUND_ROBIN, FASTEST, PRIMARY_FALLBACK, and SCHEMA_ROUTE strategies.
- **Multi-Schema Generator:** Async orchestration of concurrent LLM tasks per chunk. Semaphore-limited (2 local / 10 cloud).

### Output & Validation Layer
**Files:** `shared_lib/validator.py`, `shared_lib/post_validator.py`, `backend/core/state_manager.py`

- **Validator:** 4-stage JSON extraction (direct parse → regex repair → brace extraction → Alpaca fallback). Pydantic validation per schema. Quality scoring (grounding, diversity). Rejects records below `min_quality=0.35`.
- **Post-Validator:** Scrubs hallucinated MITRE IDs, removes ungrounded IOCs, normalises severity on BENIGN content.
- **State Manager:** SQLite-backed MD5 content-hash cache (`config/cache.db`) with `threading.Lock`. Atomic JSONL appends to `output/`.

---

## 3. Data Flow Diagram

```
[Raw File Upload]
       │
       ▼
[FileParser] ──► semantic chunking with overlap
       │
       ▼
[Cache Check] ── MD5 hash → skip if already in cache.db
       │
       ▼
[ContentClassifier] ── 4-layer deterministic classification
       │
       ├──────────────────────────┐
       ▼                          ▼
[ThreatScorer]           [CapabilityDetector]
gates MITRE/IOC/CoT      detects teachable content
       │                          │
       └──────────────────────────┘
                    │
                    ▼
           [StrategyPlanner]
        selects DataSchema list
                    │
                    ▼
       [MultiSchemaGenerator]
                    │
                    ▼
           [ModelGateway] ──► LLM (Ollama / Groq / etc.)
                    │
                    ▼
             [Validator]
         JSON extract + quality score
                    │
                    ▼
           [PostValidator]
       MITRE scrub + severity fix
                    │
                    ▼
          [StateManager I/O]
    output/all_records.jsonl
    output/all_rich_records.jsonl
```

---

## 4. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Deterministic classification (no LLM) | Prevents hallucination at the routing stage |
| Threat-gated MITRE attribution | Ensures MITRE IDs are only generated when evidenced by attack signals in the source |
| SQLite cache over JSON file | Eliminates race condition between concurrent workers |
| Streaming file reads | Prevents OOM errors when processing large datasets |
| Restricted CORS origins | Local-only tool — wildcard CORS with credentials is a security violation |
