# Cyber Data Engine v1.0.0 — Pipeline Walkthrough

This document traces the exact path a file takes from upload to generated dataset records, referencing the actual source files at each stage.

---

## Stage 1: Ingestion & Chunking

**Files:** `backend/main.py`, `shared_lib/parser.py`, `backend/core/state_manager.py`

1. The user uploads a file via the FastAPI endpoint `POST /api/v1/pipeline/start`.
2. The file bytes and configuration are passed to `_parse_and_classify_sync()`, which runs inside a `ThreadPoolExecutor` thread to avoid blocking the async event loop.
3. `FileParser.read()` determines the file format (PDF, DOCX, binary, code, STIX2 JSON, etc.) and extracts a raw Unicode string.
4. `state_manager.is_cached(text)` computes the MD5 hash and checks `config/cache.db`. If the file has already been processed, a `warning` SSE event is pushed and processing stops.
5. `FileParser.chunk()` splits the text using semantic boundaries (functions, paragraphs, code blocks), falling back to a sliding window with configurable `overlap`.

---

## Stage 2: Deterministic Classification

**Files:** `backend/core/classifier.py`

1. For each chunk, `ContentClassifier.classify()` runs a 4-layer deterministic inspection:
   - **Layer 1 — Extension Lock:** `.py`, `.c`, `.js` → `CODE`; `.exe`, `.dll` → `ATTACK_ARTIFACT`
   - **Layer 2 — Filename Signals:** Known malware filenames, CVE patterns in filename
   - **Layer 3 — Keyword Pattern Scoring:** Cyber term density threshold `≥ 0.12`
   - **Layer 4 — Entropy & Structural Scoring:** Binary entropy, code structure signals
2. Assigns `DataType` (e.g., `EDUCATIONAL`, `ATTACK_ARTIFACT`, `CODE`), initial `DataSchema`, and `TaskType`.
3. A **Hard Type Lock** is applied: code remains code, logs remain logs — no LLM can override this.
4. `.json` files are inspected for STIX2/SIGMA/Suricata/OpenIOC signals (≥3 matching keys) before being classified. Generic JSON is blocked as `IRRELEVANT`.

---

## Stage 3: Threat Assessment & Capability Detection

**Files:** `backend/core/multi_schema_generator.py`, `shared_lib/threat_scorer.py`, `backend/core/capability_detector.py`

1. The chunk enters `MultiSchemaGenerator.generate()`.
2. `assess_threat()` computes threat level using Shannon entropy, keyword density, and sliding-window context proximity.
3. Three permission flags are set:
   - `mitre_allowed` — only True if MITRE Triple-Gate passes (action + exploit + target signals present)
   - `ioc_allowed` — only True for SUSPICIOUS or MALICIOUS content
   - `cot_allowed` — only True if content has sufficient complexity
4. If `cot_allowed=False` and `CHAIN_OF_THOUGHT` was planned, it is removed from the schema list.
5. `CapabilityDetector.detect()` analyses the chunk and sets capability flags (code review, log analysis, forensics, threat hunting, etc.).

---

## Stage 4: Skill Extraction & Strategy Planning

**Files:** `backend/core/skill_extractor.py`, `backend/core/strategy_planner.py`

1. `SkillExtractor.extract_skills()` maps detected capabilities + the user's `TrainingGoal` to a list of `CyberSkill` values (e.g., `LOG_ANALYSIS`, `SECURE_CODING`).
2. `StrategyPlanner.plan()` translates skills into a prioritised list of `DataSchema` targets (e.g., `[THREAT_HUNTING, MULTI_STEP_DECISION, QA]`).
3. If `multi_schema_enabled=False`, only the primary schema is used.

---

## Stage 5: LLM Generation

**Files:** `backend/core/providers.py`, `backend/core/prompts.py`

1. For each planned schema, `prompts.py` builds a schema-specific `(system_prompt, user_prompt)` pair that embeds the chunk and requests strict JSON output.
2. `ModelGateway.generate()` routes the request to the best available provider using the configured strategy (`ROUND_ROBIN`, `FASTEST`, `PRIMARY_FALLBACK`, or `SCHEMA_ROUTE`).
3. On failure, the provider is marked as failed and the next in line is tried (up to `max_retries`).
4. If the primary schema fails after fallback, a QA schema is attempted as the last resort.

---

## Stage 6: Schema Validation & Quality Scoring

**Files:** `shared_lib/validator.py`

1. `validate()` receives the raw LLM string and runs 4 progressive JSON extraction strategies:
   - Direct `json.loads()`
   - Regex-based code block extraction (` ```json ... ``` `)
   - Brace boundary extraction (find outermost `{...}`)
   - Alpaca fallback (treat the whole response as the `output` field)
2. The extracted JSON is validated against the Pydantic model for the target schema.
3. A quality score is computed from grounding (token overlap with source chunk), vocabulary diversity, structural completeness, and schema-specific bonuses.
4. Records scoring below `min_quality` (default: `0.35`) are rejected — `result.ok = False`.
5. Near-duplicate records (Jaccard similarity ≥ 0.65 vs. already-accepted records in this chunk) are rejected.

---

## Stage 7: Post-Validation & Anti-Hallucination

**Files:** `shared_lib/post_validator.py`, `shared_lib/grounding_validator.py`, `shared_lib/attack_evidence_extractor.py`

1. `post_validate()` applies threat-aware scrubbing:
   - **MITRE Scrubbing:** If `mitre_allowed=False`, all MITRE IDs are removed from the record.
   - **IOC Scrubbing:** If `ioc_allowed=False`, extracted IOC fields are cleared.
   - **Severity Normalisation:** BENIGN content is forced to `severity=INFO` regardless of LLM claim.
   - **Label Contamination Fix:** `malware_analysis` task type is replaced with `general_cyber` for BENIGN content.
2. `AttackEvidenceExtractor` validates each MITRE ID against 38+ regex patterns in the source chunk. IDs with no evidence are stripped.
3. `GroundingValidator` checks IOCs and key claims for evidence in the original text. Unsupported claims are removed.

---

## Stage 8: Persistence

**Files:** `backend/core/state_manager.py`

1. Valid records are converted to Alpaca JSONL format and appended to `output/all_records.jsonl`.
2. Full rich metadata records are appended to `output/all_rich_records.jsonl`.
3. The MD5 hash of the processed file is inserted into `config/cache.db` via `add_to_cache()` — protected by `threading.Lock` to prevent race conditions.
4. An SSE `record` event is pushed to the frontend for each accepted record, updating the live counter.
