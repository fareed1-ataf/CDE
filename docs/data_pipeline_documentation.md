# Cyber Data Engine v1.0.0 — Data Pipeline Documentation

This document describes every filtering and validation layer the pipeline applies before and after LLM generation, ensuring intelligence-grade output quality.

---

## 1. Pre-Generation Gating Layers

### Filter 0 — Relevance Filter
**File:** `backend/core/classifier.py`

**Purpose:** Block non-cybersecurity files (e.g., recipes, CVs, financial reports) from consuming LLM resources.

**Logic:**
- Code files (`.py`, `.js`, `.c`, etc.) and binaries (`.exe`, `.dll`, `.elf`) bypass this filter automatically — they are always relevant.
- Text documents (`.pdf`, `.txt`, `.md`) are scored on **Cyber Keyword Density** and **Technical Pattern Density**.
- Acceptance threshold: `_RELEVANCE_THRESHOLD = 0.12` (minimum 12% cyber signal density).
- Files below the threshold are classified as `DataType.IRRELEVANT` and never reach the LLM.

**Special case — `.json` files:**
Checked for structured threat intel signals before blocking:
- **STIX2:** `spec_version`, `objects`, `attack-pattern`, `malware`, `indicator` (≥3 present → route to `ATTACK_ARTIFACT`)
- **SIGMA:** `title`, `logsource`, `detection`, `condition` (≥3 present → route to `ATTACK_ARTIFACT`)
- **Suricata:** `alert`, `flow`, `payload`, `app_proto` (≥3 present → route to `ATTACK_ARTIFACT`)
- Generic JSON with no signals → blocked as `IRRELEVANT`

---

### Filter 1 — Threat Level Engine
**File:** `shared_lib/threat_scorer.py`

**Purpose:** Deterministically classify content as BENIGN, SUSPICIOUS, or MALICIOUS — with no LLM involvement.

**Logic:**
1. **Extension scoring:** `.exe` increases malicious probability; `.pdf` increases benign probability.
2. **Regex pattern scoring:** Categorised rule sets (Malicious, Suspicious, Benign) scored against the content.
3. **MITRE Action Verbs Gate:** MITRE IDs are only permitted if the text contains attack action verbs (e.g., `exploit`, `bypass`, `inject`) in genuine offensive context. Without this, MITRE generation is blocked.
4. **Output:** `ThreatAssessment` object with `level: ThreatLevel` and three permission flags:
   - `mitre_allowed` — whether MITRE ATT&CK IDs may be generated
   - `ioc_allowed` — whether Indicators of Compromise may be extracted
   - `cot_allowed` — whether Chain-of-Thought deep reasoning is permitted

---

### Filter 2 — Capability & Strategy Layer
**Files:** `backend/core/capability_detector.py`, `backend/core/skill_extractor.py`, `backend/core/strategy_planner.py`

**Purpose:** Determine which schemas are appropriate for this chunk.

**Logic:**
1. `CapabilityDetector` identifies what the chunk can teach: code review, log analysis, forensics, threat hunting, etc.
   - Log analysis requires ≥2 log keywords (`event`, `sysmon`, `splunk`, etc.). The presence of `import json` alone does **not** trigger log analysis.
2. `SkillExtractor` maps capabilities + `TrainingGoal` to a `list[CyberSkill]` (e.g., `SECURE_CODING`, `LOG_ANALYSIS`).
3. `StrategyPlanner` translates skills into a `list[DataSchema]` to generate (e.g., `[THREAT_HUNTING, MULTI_STEP_DECISION, QA]`).

---

## 2. Generation Layer

**Files:** `backend/core/providers.py`, `backend/core/multi_schema_generator.py`, `backend/core/prompts.py`

**Prompting:**
- The source chunk is embedded inside a schema-specific system prompt that explicitly instructs the LLM to:
  - Output strict JSON only
  - Not fabricate MITRE IDs, CVEs, or IOCs not present in the source
  - Limit reasoning to what the text supports

**Model Gateway:**
- Abstraction layer over LiteLLM supporting Ollama, vLLM, LM Studio, and any OpenAI-compatible API.
- Handles retries with exponential backoff.
- Concurrency: max 2 tasks (local providers) / max 10 tasks (cloud providers) via `asyncio.Semaphore`.

---

## 3. Post-Generation Validation Layers

These layers run **after** the LLM responds and are the primary quality assurance mechanism.

### 3.1 Schema & Structural Validator
**File:** `shared_lib/validator.py`

**Logic:**
1. Attempts to extract JSON from the raw LLM string using 4 progressive strategies.
2. Validates the extracted JSON against the Pydantic model for the target schema.
3. Computes a quality score based on:
   - Grounding: token overlap between generated content and source chunk
   - Vocabulary diversity: unique words / total words (anti-repetition)
   - Structural completeness: required fields populated with non-trivial content
   - Schema-specific bonuses (e.g., MITRE count, IOC count for CoT)
4. Records below `min_quality=0.35` are rejected (`ok=False`).
5. If JSON parsing fails entirely, falls back to generic Alpaca format.

**CoT quality floor:** The `_score_cot()` function uses `max(score, 0.10)` as its minimum — not 0.35. Records from CoT that score between 0.10 and 0.35 still fail the `min_quality` gate and are rejected.

---

### 3.2 Post-Validator (Anti-Hallucination Scrubber)
**File:** `shared_lib/post_validator.py`

**Logic:**
1. **MITRE Scrubbing:** If `mitre_allowed=False`, all MITRE ID fields are cleared and any MITRE references are removed from the output text.
2. **Severity Normalisation:** BENIGN content is forced to `severity=INFO` regardless of LLM output.
3. **Label Contamination Prevention:** The task type `malware_analysis` is replaced with `general_cyber` on BENIGN content to prevent mislabelled training data.
4. **Confidence Penalty:** The quality score is multiplied by the threat assessment confidence. Ambiguous content (SUSPICIOUS with low confidence) receives a lower effective quality.

---

### 3.3 Grounding Validator
**File:** `shared_lib/grounding_validator.py`

**Logic:**
- Extracts 4-character-minimum tokens from both the LLM-generated reasoning and the source chunk.
- Computes token overlap: `len(reasoning_tokens ∩ source_tokens) / len(source_tokens) × 2`.
- Three grounding levels:
  - **EXACT** (score ≥ 0.8): Verbatim evidence present — accepted.
  - **SEMANTIC** (score ≥ 0.4): Sufficient token overlap — accepted.
  - **UNSUPPORTED** (score < 0.4): Claim has no basis in source text — removed.
- CoT records with grounding score < 0.20 are rejected outright.
- QA answers with grounding score < 0.15 are flagged as ungrounded.

---

### 3.4 Attack Evidence Extractor
**File:** `shared_lib/attack_evidence_extractor.py`

**Logic:**
- For each MITRE ATT&CK technique ID in the generated record (e.g., `T1059.001`), runs a dedicated regex pattern against the source chunk.
- Example: `T1059.001` requires evidence of `powershell`, `powershell.exe`, or `pwsh` in the chunk.
- **38+ patterns** cover the most commonly hallucinated MITRE techniques.
- IDs with no regex evidence are classified as hallucinated and stripped from the record.

---

## 4. Persistence

**File:** `backend/core/state_manager.py`

After passing all filters and exceeding `min_quality=0.35`:

1. Records are written to `output/all_records.jsonl` in Alpaca format (`instruction`, `input`, `output`).
2. Full rich records with metadata (quality score, provider, MITRE IDs, IOCs, severity) are written to `output/all_rich_records.jsonl`.
3. The file's MD5 hash is stored in `config/cache.db` (SQLite, thread-safe) via `add_to_cache()` to prevent reprocessing in future runs.

> **Note:** The cache operates at **file level** (whole-file MD5), not chunk level. Running the pipeline twice on the same file skips it entirely on the second run.
