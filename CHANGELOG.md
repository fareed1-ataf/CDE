# Changelog

All notable changes to Cyber Data Engine are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.1.0] — 2026-09-10

### Security
- **CRITICAL:** Cleared 4 live Groq API keys from `config/providers.json`
- Added `config/providers.json` and `config/cache.db` to `.gitignore`
- Created `config/providers.json.example` with `${ENV_VAR}` placeholders
- Fixed CORS misconfiguration: replaced `allow_origins=["*"]` + `allow_credentials=True` with explicit localhost origins

### Fixed
- **NameError crash** on `GET /api/v1/quality/report` — `_STATS` renamed to `_stats` to match module-level definition
- **Deduplication logic** — `final_result_to_append = final` on rejected duplicates changed to `= None`; duplicate records no longer inflate `_stats["ok"]` or appear in `all_records.jsonl`
- **Validator signature mismatch** — Added `source_chunk: str = ""` parameter to 9 validator functions (`_val_qa`, `_val_chat`, `_val_playbook`, `_val_tool_usage`, `_val_threat_hunting`, `_val_multi_step_decision`, `_val_detection_engineering`, `_val_forensic_timeline`, `_val_negative_example`); eliminated per-call `TypeError` overhead in dispatch block
- **Log analysis false positive** — Removed `or "json" in content_lower` from `capability_detector.py`; Python files with `import json` no longer incorrectly trigger SOC Analyst schemas
- **CoT quality gate inoperative** — Lowered `_score_cot` floor from `0.35` → `0.10`; poor Chain-of-Thought records can now fail the `min_quality=0.35` gate
- **`import json` in hot loop** — Moved `import json` from inside `generate()` coroutine to module-level imports in `multi_schema_generator.py`
- **JSON files globally blocked** — `classifier.py` now detects STIX2 / SIGMA / Suricata / OpenIOC signals before blocking `.json` files; threat intel JSON routes to `ATTACK_ARTIFACT + CoT`
- **Race condition in cache** — Replaced `cache.json` read/write with SQLite (`cache.db`) + `threading.Lock`; eliminated write-race between concurrent workers
- **OOM on large datasets** — Replaced `read_text().splitlines()` in `_all_alpaca_lines()` and `_all_rich_lines()` with line-by-line streaming; `get_sample_records()` now uses `deque(maxlen=n)` — O(n) memory only

### Added
- `LICENSE` file (MIT License)
- `.gitignore` covering secrets, outputs, logs, bytecode, virtual environments
- `CONTRIBUTING.md` — development setup, test guide, PR checklist
- `SECURITY.md` — responsible disclosure policy and best practices
- `CHANGELOG.md` — this file
- `_stream_alpaca_lines()` generator in `main.py` for future streaming export support
- QA answer grounding check in `_val_qa`: answers with `< 15%` token overlap with source chunk are flagged as ungrounded

### Architecture
- Cache backend migrated from JSON file to SQLite with `threading.Lock`
- `load_cache()` function removed (dead code after SQLite migration)
- `CACHE_FILE` constant replaced with `CACHE_DB`

---

## [3.0.0] — 2026-Q1

### Added
- Phase 3 schemas: `TOOL_USAGE`, `THREAT_HUNTING`, `MULTI_STEP_DECISION`, `DETECTION_ENGINEERING`, `FORENSIC_TIMELINE`, `NEGATIVE_EXAMPLE`
- Skill-based training goal routing (11 cybersecurity roles)
- MITRE Triple-Gate hallucination prevention
- LLaMA-3 ChatML formatter
- 38+ behavioral pattern extractors for MITRE validation
- `DeepContentAnalyzer` for structural complexity scoring
- `CapabilityDetector` for dynamic schema routing based on content type

### Fixed
- Grounding threshold raised from `0.25` → `0.40`
- Empty `alpaca_lines` after grounding now correctly fails validation

---

## [2.0.0] — 2025-Q3

### Added
- Multi-provider `ModelGateway` with Round Robin, Fastest, and Primary Fallback routing strategies
- `PostValidator` for anti-hallucination scrubbing
- `GroundingValidator` for evidence-based MITRE attribution
- Semantic chunking with configurable overlap
- Real-time SSE progress streaming

---

## [1.0.0] — 2025-Q1

### Added
- Initial release of Cyber Data Engine
- Support for `.pdf`, `.docx`, `.py`, `.exe`, `.csv` input types
- Chain-of-Thought and Alpaca JSONL output schemas
- Ollama local LLM integration
- FastAPI backend + Vanilla JS frontend
