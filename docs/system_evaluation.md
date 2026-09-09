# Cyber Data Engine v1.0.0 — System Evaluation & Critical Audit

This document is an honest technical audit of the system from the perspective of its primary goal: **generating high-quality training datasets for fine-tuning cybersecurity-specialised LLMs** (malware analysis, threat hunting, log analysis, incident response, vulnerability research, secure coding, and forensics — with no hallucination).

---

## 1. Evaluation Summary

| Component | Status | Assessment |
|-----------|--------|------------|
| Schema Routing (Skill-Based) | ✅ Implemented | Covers 11 training goals and 13 output schemas |
| Threat Assessment & MITRE Gating | ✅ Implemented | Deterministic, LLM-independent |
| Anti-Hallucination (Post-Validation) | ✅ Implemented | MITRE scrubbing + grounding + evidence extraction |
| Multi-Provider Gateway | ✅ Implemented | Round Robin, Fastest, Primary Fallback, Schema Route |
| Cache Safety | ✅ Fixed (v1.0.0) | SQLite + threading.Lock |
| CORS Security | ✅ Fixed (v1.0.0) | Explicit localhost origins |
| Chunk-Level Deduplication | ✅ Implemented | Jaccard similarity ≥ 0.65 blocks near-duplicates within a chunk |
| Global Cross-Session Dedup | ⚠️ Not implemented | Risk of semantic duplicates across pipeline runs |
| In-Memory State | ⚠️ Accepted limitation | Stats lost on restart — acceptable for v1.0.0 |
| Depth Classifier | ⚠️ Not implemented | Shallow outputs can pass `min_quality=0.35` |
| LLM-as-Judge | ⚠️ Not implemented | Planned for future version |

---

## 2. Component-Level Analysis

### 2.1 Skill & Schema Routing

**Current state:** The skill extraction and strategy planning pipeline is fully implemented. The system reads the chunk, detects capabilities, maps them to cybersecurity skills based on the Training Goal, and requests generation in multiple specialised schemas (ThreatHunting, IncidentPlaybook, ToolUsage, ForensicTimeline, etc.).

**Strengths:**
- Eliminates the static routing problem that previously forced log-schema generation from code files.
- The 13 specialised schemas cover all major cybersecurity analyst roles.
- Hard Type Lock prevents schema cross-contamination.

**Gap (planned for v1.1.0):**
The capability detector operates on keyword presence and structural signals. It does not assess **depth of knowledge** in the chunk. A shallow one-paragraph summary of a malware technique will route the same schemas as a deep 10-page technical report. A **Depth Classifier** that scores reasoning depth in the `reasoning` field of CoT records would prevent trivial records from polluting the dataset.

---

### 2.2 Threat Assessment & Anti-Hallucination

**Current state:** 4-layer deterministic threat assessment (`threat_scorer.py`) gates MITRE and IOC generation. Post-validation (`post_validator.py`, `grounding_validator.py`, `attack_evidence_extractor.py`) scrubs hallucinations after generation.

**Strengths:**
- MITRE Triple-Gate (action + exploit + target) prevents MITRE IDs on benign educational content — this prevents a major category of label contamination.
- Attack Evidence Extractor's 38+ regex patterns validate each MITRE ID individually.
- Severity forced to `INFO` on BENIGN content prevents inflated threat labelling.

**Gap (planned for v1.1.0):**
The grounding validator uses token-level overlap. In cybersecurity, the same tokens can appear in a sentence with opposite semantics (e.g., "the attacker **connected from** 192.168.1.1" vs. "the server **connected to** 192.168.1.1"). A relation-aware grounding model would catch these inversions. This is a low-priority gap for v1.0.0 since IOCs are validated by regex exact-match in most cases.

---

### 2.3 Multi-Provider Gateway & Concurrency

**Current state:** `ModelGateway` abstracts all LLM calls through LiteLLM. Supports four routing strategies. `asyncio.Semaphore` limits concurrency per provider type.

**Strengths:**
- Provider failover ensures pipeline continuity when a provider is rate-limited or down.
- Schema-based routing (`SCHEMA_ROUTE`) can direct CoT to a stronger model and QA to a faster one.

**Gap (planned for future):**
There is no quality feedback loop between providers. A Llama-3 8B response that scores `quality=0.36` (just above the rejection threshold) is accepted equally to a quality=0.95 record from a stronger model. An **LLM-as-Judge** layer using a stronger model to score outputs from weaker models would significantly improve dataset quality, at the cost of additional API calls.

---

### 2.4 Deduplication

**Current state:** `multi_schema_generator.py` uses Jaccard similarity (threshold 0.65) to detect near-duplicate records **within a single chunk processing cycle**. The SQLite cache prevents the same **file** from being reprocessed.

**Strengths:** Effective at preventing 5–10 trivially similar records from the same chunk.

**Critical Gap — Global Deduplication (highest priority for v1.1.0):**

If 500 APT29 reports covering overlapping techniques are fed to the pipeline, the output may contain thousands of semantically identical records phrased slightly differently. Semantic duplication in training data causes:
- **Overfitting** to specific threat actor TTPs
- **Reduced generalisation** across novel attack patterns
- **Model memorisation** rather than learned reasoning

**Recommended solution:** Replace the in-memory `accepted_tokens_list` per chunk with a persistent Vector Store (FAISS or ChromaDB) that checks new records for cosine similarity > 0.85 against all previously accepted records across all sessions.

---

## 3. Dataset Quality Considerations

When using the generated dataset for fine-tuning, verify the following before training:

| Check | Command / Method |
|-------|-----------------|
| Schema distribution | `cat output/all_rich_records.jsonl \| jq '.schema' \| sort \| uniq -c \| sort -rn` |
| Task type distribution | `cat output/all_rich_records.jsonl \| jq '.task_type' \| sort \| uniq -c` |
| Quality score histogram | `cat output/all_rich_records.jsonl \| jq '.quality_score' \| sort -n \| uniq -c` |
| Average quality | `cat output/all_rich_records.jsonl \| jq '.quality_score' \| awk '{sum+=$1; n++} END {print sum/n}'` |
| Severity distribution | `cat output/all_rich_records.jsonl \| jq '.rich_data.severity' \| sort \| uniq -c` |

**Recommended minimum dataset composition for a balanced cybersecurity model:**

| Schema | Minimum % | Notes |
|--------|-----------|-------|
| `chain_of_thought` | 25% | Core reasoning capability |
| `threat_hunting` | 15% | Proactive detection skill |
| `analysis` | 15% | Threat intel reporting |
| `qa` | 15% | RAG and evaluation compatibility |
| `code_gen` + `code_review` | 10% | Tool development and vuln research |
| `incident_playbook` + `forensic_timeline` | 10% | IR and forensics |
| Others | 10% | Negative examples, multi-step decision, etc. |

---

## 4. Mandatory Next Steps for v1.1.0

| Priority | Feature | Impact |
|----------|---------|--------|
| 🔴 **Critical** | Global Semantic Deduplication (Vector Store) | Prevents dataset poisoning from repetitive source files |
| 🟠 **High** | Depth Classifier for CoT records | Rejects shallow reasoning that passes quality threshold |
| 🟠 **High** | Persistent session state (Redis / SQLite) | Job recovery after server restart |
| 🟡 **Medium** | Dataset Balance Report (auto-generated) | Ensures schema/severity/task diversity |
| 🟢 **Low** | LLM-as-Judge scoring layer | Improves dataset quality at cost of extra API calls |
