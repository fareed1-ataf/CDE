# core/task_router.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# INTELLIGENT TASK ROUTER
#
# The router is the decision layer that sits between the classifier and the
# multi-schema generator. It answers one question:
#   "Given this ThreatLevel + Classification, which schemas should we generate?"
#
# Design Principles:
#   1. BENIGN content NEVER gets malware analysis schemas → kills hallucination
#   2. MALICIOUS content gets full intelligence pipeline
#   3. SUSPICIOUS gets conservative schemas with context-aware selection
#   4. Schema selection is deterministic — no LLM involved
#
# Schema Budget Per ThreatLevel:
#   BENIGN:     QA + Summary only (2 schemas max)
#   SUSPICIOUS: QA + limited CoT/Analysis (2 schemas)
#   MALICIOUS:  CoT + QA + Analysis + Chat (full 4-schema pipeline)
# =============================================================================
"""
task_router.py  —  Deterministic Schema Router

Maps a Classification (specifically its DataType) to an ordered list of
DataSchema values that should be generated for that content.

Architecture Note:
    In the v1.0.0 (Skill-based) pipeline, MultiSchemaGenerator uses
    StrategyPlanner instead of TaskRouter for schema selection. TaskRouter
    is retained for backward compatibility, direct API consumers, and tests.
    See Phase 2 flag M3 for details.

Usage:
    from backend.core.task_router import route_task
    decision = route_task(classification, max_schemas=3)
    schemas  = decision.schemas   # list[DataSchema]
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from shared_lib.schemas import DataSchema, TaskType, DataType

if TYPE_CHECKING:
    from .classifier import Classification


# ─────────────────────────────────────────────────────────────────────────────
# Routing Table (Architecture v1.0.0 - Hard Type Lock)
# ─────────────────────────────────────────────────────────────────────────────

# Maps DataType → list of schemas to generate
# Ordered by priority (best schema first)
_ROUTING_TABLE: dict[DataType, list[DataSchema]] = {
    # ── EDUCATIONAL: Documentation, guides, articles ──────────────────────────
    # Rule: Safe Mode. Only QA and Alpaca.
    DataType.EDUCATIONAL: [DataSchema.QA, DataSchema.ALPACA],

    # ── CODE: Scripts, application code, tools ────────────────────────────────
    # Rule: Code processing. Code Gen and Code Review.
    DataType.CODE: [DataSchema.CODE_GEN, DataSchema.CODE_REVIEW],

    # ── DATA: Databases, JSON, Logs, Configs ──────────────────────────────────
    # Rule: Data extraction. QA and Alpaca.
    DataType.DATA: [DataSchema.QA, DataSchema.ALPACA],

    # ── ATTACK_ARTIFACT: Confirmed exploits, malware, pcaps ───────────────────
    # Rule: Full intelligence pipeline.
    DataType.ATTACK_ARTIFACT: [
        DataSchema.CHAIN_OF_THOUGHT,
        DataSchema.ANALYSIS,
        DataSchema.QA,
        DataSchema.CHAT,
    ],
}

# Default fallback
_DEFAULT_SCHEMAS = [DataSchema.QA, DataSchema.ALPACA]


# ─────────────────────────────────────────────────────────────────────────────
# Route Result
# ─────────────────────────────────────────────────────────────────────────────

# RESULT — immutable container returned by TaskRouter.route().
@dataclass
class RouteDecision:
    # Ordered list of schemas to generate; first entry is the primary schema.
    schemas:      list[DataSchema]
    # DataType that drove this routing decision.
    data_type:    DataType
    # Human-readable explanation of the routing decision for logging/debugging.
    reasoning:    str

    @property
    def primary_schema(self) -> DataSchema:
        return self.schemas[0] if self.schemas else DataSchema.QA


# ─────────────────────────────────────────────────────────────────────────────
# Task Router
# ─────────────────────────────────────────────────────────────────────────────

class TaskRouter:
    """
    Deterministic task router that maps ThreatLevel + Classification
    to the appropriate set of generation schemas.
    
    Never uses an LLM. Entirely rule-based for reliability.
    """

    def __init__(self):
        pass

    # ROUTE — map a Classification to an ordered schema list.
    # Args:    cls: Classification   — result from ContentClassifier.classify().
    #          max_schemas: int      — maximum number of schemas to return (budget cap).
    # Returns: RouteDecision containing the selected schemas and reasoning string.
    # Side effects: None. Purely deterministic lookup — no I/O, no LLM.
    def route(
        self,
        cls: "Classification",
        max_schemas: int = 3,
    ) -> RouteDecision:
        """
        Determine which schemas to generate based ONLY on DataType.
        
        Args:
            cls: Primary classification from ContentClassifier
            max_schemas: Maximum number of schemas to return
            
        Returns:
            RouteDecision with ordered list of schemas to generate
        """
        # Look up routing table
        schemas = _ROUTING_TABLE.get(cls.data_type, _DEFAULT_SCHEMAS)

        # Enforce budget cap
        schemas = list(schemas[:max_schemas])

        reasoning = (
            f"Route: {cls.data_type.value.upper()} "
            f"→ {[s.value for s in schemas]} "
        )

        return RouteDecision(
            schemas   = schemas,
            data_type = cls.data_type,
            reasoning = reasoning,
        )


# ── Module-level singleton ────────────────────────────────────────────────────
_router = TaskRouter()


# ROUTE — public module-level API wrapping the singleton TaskRouter.
# Args:    cls: Classification   — result from ContentClassifier.classify().
#          max_schemas: int      — schema budget cap (default 3).
# Returns: RouteDecision with ordered schema list and routing reasoning.
def route_task(cls: "Classification", max_schemas: int = 3) -> RouteDecision:
    """Public API — route classification to schema list."""
    return _router.route(cls, max_schemas=max_schemas)
