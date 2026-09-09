# core/multi_schema_generator.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# MULTI-SCHEMA GENERATOR — Intelligence Architecture
#
# v1.0.0 Changes (AI Data Engineering Architecture):
#   BEFORE: Static schema routing table → same schemas for everything
#   AFTER:  Dynamic routing via ThreatLevelEngine + TaskRouter + PostValidator
#
# New Pipeline per chunk:
#   1. ThreatLevelEngine assesses content (BENIGN/SUSPICIOUS/MALICIOUS)
#   2. TaskRouter maps ThreatLevel → appropriate schemas
#   3. For BENIGN: routes to QA/Summary with no-MITRE prompts
#   4. For MALICIOUS: routes to full CoT/Analysis/QA pipeline
#   5. PostValidator scrubs any hallucinated MITRE/IOCs after generation
#
# Result: Zero MITRE hallucination on benign content, full fidelity on threats.
# =============================================================================
"""
multi_schema_generator.py  —  Central Orchestration Engine

For each text chunk, runs a four-stage intelligence pipeline:

  Stage 1 — Threat Assessment:
      assess_threat() scores the chunk. For non-ATTACK_ARTIFACT types, threat
      is hard-coded to BENIGN (Hard Type Lock — no security assessment needed).

  Stage 2 — Skill-Based Strategy Planning (Phase 2):
      DeepContentAnalyzer  → content dimensions (complexity, richness, ...)
      CapabilityDetector   → what the chunk is capable of teaching
      SkillExtractionLayer → which skills align with the training goal
      StrategyPlanner      → which DataSchemas to generate

  Stage 3 — Generation + Validation:
      For each planned schema:
        ModelGateway.generate()  → raw LLM JSON string
        validate()               → Pydantic-validated ValidationResult

  Stage 4 — Post-Validation + Deduplication:
      post_validate()            → MITRE/IOC scrubbing, severity normalisation
      Semantic dedup             → Jaccard similarity on token sets

Concurrency:
    generate_stream() uses asyncio.Semaphore to bound concurrent LLM tasks.
    Local providers: max 2 concurrent tasks.
    Cloud providers: max 10 concurrent tasks.
"""

from __future__ import annotations

import logging
import asyncio
import json
from dataclasses import dataclass, field
from typing import AsyncGenerator

from shared_lib.schemas import DataSchema, TaskType, DataType, Classification
from .providers import ModelGateway
from shared_lib.validator import validate, ValidationResult
from shared_lib.threat_scorer import assess_threat, ThreatScore as ThreatAssessment, ThreatLevel

# Phase 2 imports
from backend.core.training_goal import TrainingGoal
from backend.core.content_analyzer import DeepContentAnalyzer
from backend.core.capability_detector import CapabilityDetector
from backend.core.skill_extractor import SkillExtractionLayer
from backend.core.strategy_planner import StrategyPlanner

from shared_lib.post_validator import post_validate

logger = logging.getLogger("CDE.MultiSchema")


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MultiSchemaResult:
    """Results from processing one chunk across multiple schemas."""
    chunk_index:    int
    source_file:    str
    primary_schema: str
    threat_level:   str   = "unknown"     # benign / suspicious / malicious
    results:        list[ValidationResult] = field(default_factory=list)

    @property
    def total_records(self) -> int:
        return sum(r.record_count for r in self.results if r.ok)

    @property
    def all_alpaca_lines(self) -> list[str]:
        lines = []
        for r in self.results:
            if r.ok:
                lines.extend(r.alpaca_lines)
        return lines

    @property
    def all_rich_lines(self) -> list[str]:
        return [r.rich_line for r in self.results if r.ok and r.rich_line]

    @property
    def schemas_produced(self) -> list[str]:
        return [r.schema_used for r in self.results if r.ok]

    @property
    def avg_quality(self) -> float:
        qs = [r.quality for r in self.results if r.ok and r.quality > 0]
        return round(sum(qs) / len(qs), 3) if qs else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Multi-Schema Generator v1.0.0
# ─────────────────────────────────────────────────────────────────────────────

class MultiSchemaGenerator:
    """
    Intelligence-grade multi-schema data generator.

    v1.0.0 Architecture:
        ThreatLevelEngine → TaskRouter → LLM → PostValidator

    The ThreatLevelEngine is the first filter — it determines whether content
    is benign (educational), suspicious (ambiguous), or malicious (attack artifact).
    This decision drives every downstream schema and prompt selection.
    """

    def __init__(
        self,
        gateway:        ModelGateway,
        max_schemas:    int  = 3,
        enabled:        bool = True,
        training_goal:  TrainingGoal = TrainingGoal.GENERAL_CYBER_ASSISTANT,
        min_quality:    float = 0.35,
    ):
        self.gateway     = gateway
        self.max_schemas = max_schemas
        self.enabled     = enabled
        self.training_goal = training_goal
        self.min_quality = min_quality
        
        # Phase 2 components
        self.content_analyzer = DeepContentAnalyzer()
        self.capability_detector = CapabilityDetector()
        self.skill_extractor = SkillExtractionLayer()
        self.strategy_planner = StrategyPlanner()

    def _override_cls_schema(
        self, cls: Classification, new_schema: DataSchema
    ) -> Classification:
        """Creates a copy of Classification with a different schema."""
        from dataclasses import replace
        try:
            return replace(cls, schema=new_schema)
        except TypeError:
            new_cls = cls.__class__.__new__(cls.__class__)
            for attr in vars(cls):
                setattr(new_cls, attr, getattr(cls, attr))
            new_cls.schema = new_schema
            return new_cls

    # GENERATE — run the full 4-stage pipeline for a single text chunk.
    # Args:    chunk: str       — text chunk to process.
    #          cls: Classification — result from ContentClassifier.
    #          filename: str    — source file name (for logging and threat scoring).
    #          chunk_index: int — zero-based index within the file's chunk list.
    # Returns: MultiSchemaResult with all ValidationResult objects for this chunk.
    # Side effects: calls ModelGateway (network I/O), logs progress/errors.
    async def generate(
        self,
        chunk:       str,
        cls:         Classification,
        filename:    str,
        chunk_index: int = 0,
    ) -> MultiSchemaResult:
        """
        Process one chunk through the full v1.0.0 intelligence pipeline.
        """
        # P1.5: Short-circuit for irrelevant content — never reaches the LLM.
        if cls.data_type == DataType.IRRELEVANT:
            logger.info(
                f"  ⊘ [{filename}] Skipped by Relevance Filter: {cls.reasoning}"
            )
            return MultiSchemaResult(
                chunk_index    = chunk_index,
                source_file    = filename,
                primary_schema = cls.schema.value,
                threat_level   = "irrelevant",
            )

        # ── Stage 1: Threat Level Assessment (Security Pipeline Guard) ───────
        if cls.data_type == DataType.ATTACK_ARTIFACT:
            threat: ThreatAssessment = assess_threat(filename, chunk, cls.confidence)
            logger.debug(
                f"  🔍 [{filename}][{chunk_index}] ThreatLevel={threat.level.value.upper()} "
                f"conf={threat.confidence:.2f} MITRE={'✓' if threat.mitre_allowed else '✗'} "
                f"signals=[{','.join(threat.signals[:5])}]"
            )
        # WHY bypass for non-ATTACK_ARTIFACT types:
        # The Hard Type Lock means CODE, DATA, and EDUCATIONAL content has already
        # been confirmed safe by the classifier. Running the full threat scorer
        # on a Python tutorial would waste compute and risk false positives.
        # Forcing BENIGN with mitre_allowed=False ensures the post_validator
        # does not inject any MITRE IDs into educational output.
        else:
            threat = ThreatAssessment(
                keyword_score=0.0,
                entropy_score=0.0,
                context_score=0.0,
                final_score=0.0,
                has_action_verbs=False,
                has_exploit_context=False,
                has_system_target=False,
                level=ThreatLevel.BENIGN,
                confidence=1.0,
                mitre_allowed=False,
                ioc_allowed=False,
                cot_allowed=False,
                signals=["hard_type_lock"],
                reasoning=f"Bypassed security assessment. Locked to {cls.data_type.value}.",
            )

        # ── Stage 2: Skill-Based Strategy Planning (Phase 2) ────────────────
        # 1. Analyze deep content dimensions
        dims = self.content_analyzer.analyze(chunk, filename)
        
        # 2. Detect capabilities
        caps = self.capability_detector.detect(chunk, dims, threat)
        
        # 3. Extract skills based on capabilities and goal
        skills = self.skill_extractor.extract_skills(caps, self.training_goal, dims.overall_richness)
        
        # 4. Plan strategy (schemas to run)
        schemas_to_run = self.strategy_planner.plan(skills, dims.overall_richness, threat.level.value, self.max_schemas)
        
        if not schemas_to_run:
            schemas_to_run = [cls.schema]
            
        logger.debug(f"  🧠 Skills: {[s.name for s in skills]} -> Strategy: {[s.value for s in schemas_to_run]}")

        result = MultiSchemaResult(
            chunk_index    = chunk_index,
            source_file    = filename,
            primary_schema = cls.schema.value,
            threat_level   = threat.level.value,
        )

        # If multi-schema disabled, only run primary
        if not self.enabled:
            schemas_to_run = [cls.schema]
            
        # Phase 3: Enforce cot_allowed gate
        if not threat.cot_allowed and DataSchema.CHAIN_OF_THOUGHT in schemas_to_run:
            schemas_to_run = [s for s in schemas_to_run if s != DataSchema.CHAIN_OF_THOUGHT]
            logger.debug(f"CoT blocked by threat.cot_allowed=False for {filename}")

        # ── Stage 3: Generate + Validate + Post-Check ─────────────────────────
        # WHY check accepted_tokens_list per schema:
        # Different schemas (CoT, QA, Analysis) can produce semantically identical
        # outputs for the same chunk. Pre-computing token sets for each accepted
        # output and using Jaccard similarity (threshold 0.75) prevents near-duplicate
        # records from polluting the training dataset.
        # This is O(N) per schema using pre-computed sets, not O(N²) per token.
        accepted_tokens_list: list[set] = []
        
        for schema in schemas_to_run:
            schemas_to_try = [schema]
            # If the primary planned schema fails, QA is the most robust fallback for teaching models.
            if schema != DataSchema.QA:
                schemas_to_try.append(DataSchema.QA)

            final_result_to_append = None

            for attempt_idx, attempt_schema in enumerate(schemas_to_try):
                schema_cls = (
                    cls if attempt_schema == cls.schema
                    else self._override_cls_schema(cls, attempt_schema)
                )

                try:
                    if attempt_idx > 0:
                        logger.info(f"  ↻ [{filename}][{chunk_index}] Retrying with fallback schema: {attempt_schema.value}")
                        
                    raw, provider_used = await self.gateway.generate(chunk, schema_cls, filename)
                    vresult = validate(raw, schema_cls, filename, provider_used, self.min_quality)

                    # ── Stage 4: Post-Validation (MITRE/IOC Scrubbing & Injection) ───────────
                    post = post_validate(vresult, threat, chunk, filename)
                    final = post.result

                    if final.ok:
                        # Global Semantic Deduplication (Cross-Schema)
                        is_duplicate = False
                        schema_outputs_tokens = []
                        for line in final.alpaca_lines:
                            try:
                                # FIX: Use instruction instead of output for semantic dedup
                                parsed = json.loads(line)
                                dedup_text = parsed.get("instruction", parsed.get("question", ""))
                                tokens = set(dedup_text.lower().split())
                                if not tokens: continue
                                
                                for acc_tokens in accepted_tokens_list:
                                    if not acc_tokens: continue
                                    sim = len(tokens & acc_tokens) / len(tokens | acc_tokens)
                                    if sim >= 0.75:
                                        is_duplicate = True
                                        break
                                
                                if is_duplicate:
                                    break
                                schema_outputs_tokens.append(tokens)
                            except Exception:
                                pass
                                
                        if is_duplicate:
                            logger.info(f"  ⊘ [{provider_used}] {filename}[{chunk_index}] → {attempt_schema.value} REJECTED (Semantic Duplicate)")
                            # Duplicate means we already extracted this knowledge — do NOT append.
                            # Previously: final_result_to_append = final (BUG — inflated stats)
                            final_result_to_append = None
                            break
                            
                        accepted_tokens_list.extend(schema_outputs_tokens)
                        
                        if post.cleaned:
                            logger.info(
                                f"  ✓ [{provider_used}] {filename}[{chunk_index}] "
                                f"→ {attempt_schema.value} Q={final.quality:.2f} "
                                f"[CLEANED: {','.join(post.changes)}]"
                            )
                        else:
                            logger.info(
                                f"  ✓ [{provider_used}] {filename}[{chunk_index}] "
                                f"→ {attempt_schema.value} Q={final.quality:.2f}"
                            )
                        
                        final_result_to_append = final
                        break  # Success! Break retry loop.
                    else:
                        logger.warning(
                            f"  ✗ {filename}[{chunk_index}] schema={attempt_schema.value}: "
                            f"{final.error[:80]}"
                        )
                        final_result_to_append = final

                except Exception as exc:
                    # P1.2: Log full traceback AND record the failure so files never
                    # disappear silently. The failed ValidationResult is visible in
                    # pipeline stats and in the engine.log file.
                    logger.error(
                        f"  ✗ {filename}[{chunk_index}] schema={attempt_schema.value} "
                        f"EXCEPTION [{type(exc).__name__}]: {exc}",
                        exc_info=True,
                    )
                    from shared_lib.validator import ValidationResult as _VR
                    final_result_to_append = _VR(
                        ok=False,
                        error=f"{type(exc).__name__}: {exc}",
                        schema_used=attempt_schema.value,
                        quality=0.0,
                        record_count=0,
                    )

            if final_result_to_append:
                result.results.append(final_result_to_append)

        return result

    # STREAM — async generator that processes all chunks concurrently.
    # Yields (completed_count, total_chunks, MultiSchemaResult) for each chunk
    # as it completes, allowing real-time SSE progress updates to the client.
    # Concurrency is bounded by asyncio.Semaphore (2 for local, 10 for cloud).
    # Args:    all_items: list[tuple[str, str, Classification]]
    #              Each tuple is (chunk_text, source_filename, classification).
    # Returns: AsyncGenerator yielding (int, int, MultiSchemaResult).
    # Side effects: spawns asyncio tasks, calls ModelGateway (network I/O).
    async def generate_stream(
        self,
        all_items: list[tuple[str, str, Classification]],
    ) -> AsyncGenerator[tuple[int, int, MultiSchemaResult], None]:
        """
        Generator that yields (completed_count, total, MultiSchemaResult) for each chunk,
        processing multiple chunks concurrently for massive speedups.
        """
        total = len(all_items)
        if total == 0:
            return

        try:
            active_providers = self.gateway.providers
            has_cloud = any(
                getattr(p, "provider_type", "").value not in ("ollama",)
                for p in active_providers if getattr(p, "enabled", True)
            )
        except Exception:
            has_cloud = False

        if has_cloud:
            max_workers = min(10, total)
        else:
            max_workers = min(2, total)

        logger.debug(
            f"Asyncio: {max_workers} concurrent tasks "
            f"({'cloud+local' if has_cloud else 'local-only'}) for {total} chunks"
        )

        semaphore = asyncio.Semaphore(max_workers)

        async def _bounded_generate(c_chunk, c_filename, c_cls, c_ci):
            async with semaphore:
                return await self.generate(c_chunk, c_cls, c_filename, c_ci)

        tasks = [
            asyncio.create_task(_bounded_generate(chunk, filename, cls, ci))
            for ci, (chunk, filename, cls) in enumerate(all_items)
        ]

        completed = 0
        for future in asyncio.as_completed(tasks):
            completed += 1
            try:
                mresult = await future
                yield completed - 1, total, mresult
            except Exception as exc:
                logger.error(f"Critical error in Asyncio tasks: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────

# FACTORY — create a fully configured MultiSchemaGenerator instance.
# Args:    gateway: ModelGateway    — initialised provider gateway.
#          enabled: bool            — if False, only primary schema is generated.
#          max_schemas: int         — schema budget cap per chunk.
#          training_goal: str       — TrainingGoal enum value as string.
#          min_quality: float       — quality threshold; records below this are rejected.
# Returns: MultiSchemaGenerator ready for use.
# Raises:  ValueError silently handled; falls back to GENERAL_CYBER_ASSISTANT goal.
def make_multi_schema_generator(
    gateway:      ModelGateway,
    enabled:      bool = True,
    max_schemas:  int  = 3,
    training_goal: str = "general_cyber_assistant",
    min_quality:  float = 0.35,
) -> MultiSchemaGenerator:
    """
    Factory function to create a MultiSchemaGenerator v1.0.0 (Skill-based).
    """
    try:
        goal = TrainingGoal(training_goal)
    except ValueError:
        goal = TrainingGoal.GENERAL_CYBER_ASSISTANT
    return MultiSchemaGenerator(
        gateway     = gateway,
        max_schemas = max_schemas,
        enabled     = enabled,
        training_goal = goal,
        min_quality = min_quality,
    )
