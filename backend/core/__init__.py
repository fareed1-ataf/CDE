# backend/core/__init__.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# Exports from backend/core (LLM Orchestration + Routing)
# and re-exports shared_lib symbols for backward-compat with frontend.
# =============================================================================

# ── Backend Core (LLM integrations, routing, generation) ─────────────────────
from .classifier import ContentClassifier, Classification
from .prompts    import build_prompt
from .providers  import (
    ModelGateway, ProviderConfig, ProviderType, RoutingStrategy,
    make_ollama_provider, make_lmstudio_provider,
    make_vllm_provider, make_openai_provider,
)
from .multi_schema_generator import (
    MultiSchemaGenerator, MultiSchemaResult, make_multi_schema_generator
)
from .state_manager import (
    save_providers, load_providers, is_cached, add_to_cache, append_to_output
)
from shared_lib.threat_scorer import ThreatLevel, ThreatScore as ThreatAssessment, score_threat as assess_threat
from .task_router    import TaskRouter, RouteDecision, route_task
from .benign_prompts import build_benign_prompt

# ── Shared Library (no circular risk — shared_lib never imports backend) ──────
from shared_lib.schemas    import (
    DataSchema, TaskType, Severity,
    ChainOfThoughtEntry, StructuredAnalysisEntry, QABatchEntry,
    ChatMLEntry, CodeGenEntry, CodeReviewEntry,
    IncidentPlaybookEntry, AlpacaEntry,
)
from shared_lib.parser     import FileParser
from shared_lib.validator  import validate, ValidationResult
from shared_lib.formatter  import (
    format_for_llama3, format_dataset, format_jsonl_line,
    MitreValidator, NegativeExampleGenerator,
    sort_by_curriculum, apply_curriculum_to_jsonl,
)
from shared_lib.post_validator import PostValidator, PostValidationResult, post_validate

__all__ = [
    # Schemas (from shared_lib)
    "DataSchema","TaskType","Severity",
    "ChainOfThoughtEntry","StructuredAnalysisEntry","QABatchEntry",
    "ChatMLEntry","CodeGenEntry","CodeReviewEntry",
    "IncidentPlaybookEntry","AlpacaEntry",
    # Classification
    "ContentClassifier","Classification",
    # Prompts
    "build_prompt","build_benign_prompt",
    # Parsing (from shared_lib)
    "FileParser",
    # Providers
    "ModelGateway","ProviderConfig","ProviderType","RoutingStrategy",
    "make_ollama_provider","make_lmstudio_provider",
    "make_vllm_provider","make_openai_provider",
    # Validation (from shared_lib)
    "validate","ValidationResult",
    # Formatting (from shared_lib)
    "format_for_llama3","format_dataset","format_jsonl_line",
    "MitreValidator","NegativeExampleGenerator",
    "sort_by_curriculum","apply_curriculum_to_jsonl",
    # Post-validation (from shared_lib)
    "PostValidator","PostValidationResult","post_validate",
    # Generation
    "MultiSchemaGenerator","MultiSchemaResult","make_multi_schema_generator",
    # State Management
    "save_providers","load_providers","is_cached","add_to_cache","append_to_output",
    # v1.0.0 Intelligence Architecture
    "ThreatLevel","ThreatAssessment","assess_threat",
    "TaskRouter","RouteDecision","route_task",
]
__version__ = "4.0.0"
