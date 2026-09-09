# shared_lib/__init__.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# Standalone shared library — zero dependency on backend.
# Safe to import from any external project (RAG, Chatbot, pipeline scripts).
# =============================================================================

from .schemas        import (
    DataSchema, TaskType, Severity,
    ChainOfThoughtEntry, StructuredAnalysisEntry, QABatchEntry,
    ChatMLEntry, CodeGenEntry, CodeReviewEntry,
    IncidentPlaybookEntry, AlpacaEntry,
)
from .parser         import FileParser
from .validator      import validate, ValidationResult
from .post_validator import PostValidator, PostValidationResult, post_validate
from .formatter      import (
    format_for_llama3, format_dataset, format_jsonl_line,
    MitreValidator, NegativeExampleGenerator,
    sort_by_curriculum, apply_curriculum_to_jsonl,
)
from .rag_processor  import RAGProcessor, RAGDocument
from .threat_scorer import score_threat as assess_threat, ThreatScore as ThreatAssessment, ThreatLevel

__all__ = [
    "DataSchema","TaskType","Severity",
    "ChainOfThoughtEntry","StructuredAnalysisEntry","QABatchEntry",
    "ChatMLEntry","CodeGenEntry","CodeReviewEntry",
    "IncidentPlaybookEntry","AlpacaEntry",
    "FileParser",
    "validate","ValidationResult",
    "PostValidator","PostValidationResult","post_validate",
    "format_for_llama3","format_dataset","format_jsonl_line",
    "MitreValidator","NegativeExampleGenerator",
    "sort_by_curriculum","apply_curriculum_to_jsonl",
    "RAGProcessor","RAGDocument",
    "ThreatAssessment","ThreatLevel","assess_threat",
]
__version__ = "1.0.0"
