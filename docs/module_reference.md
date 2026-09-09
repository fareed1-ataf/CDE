# Cyber Data Engine — Module Reference

This document is the authoritative reference for every module in the system: its purpose, inputs, outputs, and inter-module dependencies.

---

## 1. API Layer

### `backend/main.py`
| Property | Detail |
|----------|--------|
| **Role** | FastAPI application entry point and pipeline orchestrator |
| **Key Endpoints** | `POST /api/v1/pipeline/start`, `GET /api/v1/pipeline/stream/{job_id}`, `GET /api/v1/export/alpaca`, `GET /api/v1/quality/report` |
| **Inputs** | HTTP requests (file upload, provider config, job control) |
| **Outputs** | JSON responses, Server-Sent Events (SSE), JSONL file downloads |
| **Dependencies** | `MultiSchemaGenerator`, `ModelGateway`, `state_manager`, `FileParser` |
| **Notes** | Pipeline jobs run in `ThreadPoolExecutor` threads. Job state (`_jobs`) and session statistics (`_stats`) are in-memory and reset on server restart. |

---

## 2. Core Engine Layer (`backend/core/`)

### `classifier.py`
| Property | Detail |
|----------|--------|
| **Role** | Deterministic content classifier — assigns `DataType`, `DataSchema`, `TaskType` |
| **Inputs** | `filename: str`, `preview: str` (first 4,000 chars of content) |
| **Outputs** | `Classification` dataclass |
| **Logic** | 4-layer pipeline: Extension Lock → Code Lock → Structured Data Lock → Document scoring |
| **Special Cases** | `.json` files: detects STIX2/SIGMA/Suricata/OpenIOC signals before deciding to block or route |

### `multi_schema_generator.py`
| Property | Detail |
|----------|--------|
| **Role** | Central orchestrator — manages the full generation lifecycle per chunk |
| **Inputs** | `chunk: str`, `Classification`, `filename: str`, `TrainingGoal` |
| **Outputs** | `MultiSchemaResult` containing all successful `ValidationResult` objects |
| **Dependencies** | `ModelGateway`, `DeepContentAnalyzer`, `CapabilityDetector`, `SkillExtractor`, `StrategyPlanner`, `validator`, `post_validator` |
| **Concurrency** | Uses `asyncio.Semaphore` — max 2 tasks (local), max 10 tasks (cloud) |

### `capability_detector.py`
| Property | Detail |
|----------|--------|
| **Role** | Detects what the chunk is capable of teaching |
| **Inputs** | `chunk: str`, `ContentDimensions`, `ThreatAssessment` |
| **Outputs** | `Capabilities` dataclass (boolean flags: `supports_code_review`, `supports_log_analysis`, etc.) |
| **Key Logic** | Log analysis requires ≥2 log keywords (`event`, `sysmon`, `splunk`, etc.) — `import json` alone does NOT trigger this flag |

### `skill_extractor.py`
| Property | Detail |
|----------|--------|
| **Role** | Maps detected capabilities + training goal to a list of cybersecurity skills |
| **Inputs** | `Capabilities`, `TrainingGoal` (e.g., `SOC_ANALYST`, `THREAT_HUNTER`, `MALWARE_ANALYST`) |
| **Outputs** | `list[CyberSkill]` (e.g., `[LOG_ANALYSIS, THREAT_HUNTING]`) |

### `strategy_planner.py`
| Property | Detail |
|----------|--------|
| **Role** | Converts skill list to a prioritised list of schemas to generate |
| **Inputs** | `list[CyberSkill]`, `ThreatLevel` |
| **Outputs** | `list[DataSchema]` (e.g., `[THREAT_HUNTING, MULTI_STEP_DECISION, QA]`) |

### `content_analyzer.py`
| Property | Detail |
|----------|--------|
| **Role** | Deep structural analysis of the chunk |
| **Inputs** | `chunk: str`, `filename: str` |
| **Outputs** | `ContentDimensions` (code ratio, log ratio, structural complexity, semantic density) |

### `providers.py`
| Property | Detail |
|----------|--------|
| **Role** | Multi-provider LLM gateway with routing strategies |
| **Inputs** | `system_prompt: str`, `user_prompt: str`, `schema: DataSchema` |
| **Outputs** | Raw string response from the LLM |
| **Routing Strategies** | `ROUND_ROBIN`, `FASTEST`, `PRIMARY_FALLBACK` |
| **Supported Backends** | Ollama, Groq, OpenAI-compatible APIs (via `litellm`) |

### `prompts.py`
| Property | Detail |
|----------|--------|
| **Role** | Builds schema-specific system and user prompts |
| **Inputs** | `chunk: str`, `Classification`, `schema: DataSchema` |
| **Outputs** | `tuple[str, str]` — `(system_prompt, user_prompt)` |

---

## 3. Shared Libraries (`shared_lib/`)

### `schemas.py`
| Property | Detail |
|----------|--------|
| **Role** | System-wide data contracts — all Pydantic models and Enums |
| **Key Models** | `ChainOfThoughtEntry`, `QABatchEntry`, `ThreatHuntingEntry`, `DetectionEngineeringEntry`, `ForensicTimelineEntry`, `NegativeExampleEntry`, `ValidationResult` |
| **Key Enums** | `DataSchema`, `DataType`, `TaskType`, `ThreatLevel`, `Severity` |

### `validator.py`
| Property | Detail |
|----------|--------|
| **Role** | Parses raw LLM output into validated Pydantic models; calculates initial quality score |
| **Inputs** | `raw: str`, `Classification`, `source_file: str`, `source_chunk: str` |
| **Outputs** | `ValidationResult` with `ok: bool`, `quality: float`, `alpaca_lines: list[str]` |
| **Dispatch** | Schema → validator function mapping with direct 4-arg call (no `TypeError` fallback) |
| **Fallback** | Any schema that fails parsing falls back to `_val_alpaca()` |
| **Quality Gate** | Records with `quality < min_quality` (default 0.35) are rejected (`ok=False`) |

### `threat_scorer.py`
| Property | Detail |
|----------|--------|
| **Role** | Deterministic threat classification engine — no LLM involved |
| **Inputs** | `filename: str`, `preview: str` (first 4,000 chars) |
| **Outputs** | `ThreatAssessment` with `level: ThreatLevel`, `cot_allowed: bool`, `mitre_allowed: bool`, `ioc_allowed: bool` |

### `post_validator.py`
| Property | Detail |
|----------|--------|
| **Role** | Anti-hallucination post-processing — runs after `validator.py` |
| **Inputs** | `ValidationResult`, `ThreatAssessment`, `chunk: str` |
| **Outputs** | `PostValidationResult` with cleaned record |
| **Actions** | Strips unsupported MITRE IDs, removes ungrounded IOCs, corrects severity to `INFO` on BENIGN content |

### `grounding_validator.py`
| Property | Detail |
|----------|--------|
| **Role** | Verifies that claims in the generated output are evidenced in the source text |
| **Inputs** | `reasoning: str`, `evidence: str` (source chunk) |
| **Outputs** | Grounding score `float[0.0, 1.0]` — threshold: `< 0.20` rejects CoT, `< 0.15` rejects QA answers |

### `attack_evidence_extractor.py`
| Property | Detail |
|----------|--------|
| **Role** | Validates MITRE technique IDs against actual attack evidence in the source text |
| **Inputs** | `mitre_ids: list[str]`, `chunk: str` |
| **Outputs** | Two lists: `validated_ids` (evidenced) and `stripped_ids` (hallucinated) |
| **Method** | 38+ Regex patterns matching behavioural indicators per MITRE technique |

### `parser.py`
| Property | Detail |
|----------|--------|
| **Role** | File ingestion and semantic chunking |
| **Inputs** | File object (BytesIO), `filename: str`, `chunk_size: int`, `overlap: int` |
| **Outputs** | `list[str]` — text chunks |
| **Supported Formats** | `.pdf` (pdfplumber), `.docx` (python-docx), `.xlsx`/`.csv`/`.tsv` (openpyxl/csv), `.exe`/`.elf`/`.dll` (binary string extraction), `.zip` (manifest), plain text/code (UTF-8 heuristic) |

### `state_manager.py`
| Property | Detail |
|----------|--------|
| **Role** | Persistence and caching layer |
| **Cache Backend** | SQLite (`config/cache.db`) with `threading.Lock` — race-condition-free |
| **Key Functions** | `is_cached(text)`, `add_to_cache(text)`, `append_to_output(filename, records)`, `save_providers()`, `load_providers()` |
| **Output Files** | `output/all_records.jsonl` (Alpaca), `output/all_rich_records.jsonl` (Rich) |

---

## 4. Frontend (`frontend/`)

| File | Role |
|------|------|
| `index.html` | SPA shell and UI layout |
| `app.js` | All interaction logic, SSE consumer, UI state management |
| `style.css` | Full UI styling |
