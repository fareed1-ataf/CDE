# shared_lib/rag_processor.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# UNIFIED RAG & CHATBOT DOCUMENT PROCESSOR
#
# Purpose:
#   Single entry point for any external project (Chatbot, Vector DB, etc.)
#   that wants to ingest a raw file and get back clean, validated, semantically
#   chunked text — ready for embedding.
#
# Key Properties:
#   ✓ Zero dependency on backend (no circular imports)
#   ✓ Applies the same quality gate used in the main training pipeline
#   ✓ Strips hallucinated MITRE IDs / CVEs / IPs from chunks
#   ✓ Works with PDF, DOCX, TXT, CSV, XLSX, JSON, LOG files
#
# Usage:
#   from shared_lib.rag_processor import RAGProcessor
#
#   processor = RAGProcessor(chunk_size=1000, overlap=150)
#   with open("threat_report.pdf", "rb") as f:
#       docs = processor.process_file(f, "threat_report.pdf")
#   for doc in docs:
#       vector_db.add(doc.content, metadata=doc.metadata)
# =============================================================================

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from io import BytesIO
from typing import List, Dict, Any

from shared_lib.parser       import FileParser
from shared_lib.post_validator import PostValidator

logger = logging.getLogger("CDE.RAGProcessor")


@dataclass
class RAGDocument:
    """A single clean, validated text chunk ready for Vector DB insertion."""
    chunk_id:  int
    content:   str
    metadata:  Dict[str, Any] = field(default_factory=dict)


class RAGProcessor:
    """
    End-to-end file → clean chunks pipeline for RAG and Chatbot integration.

    Architecture:
        File  →  FileParser (read + semantic chunk)
              →  PostValidator (scrub hallucinations)
              →  List[RAGDocument]
    """

    def __init__(self, chunk_size: int = 1200, overlap: int = 150):
        self.parser        = FileParser(chunk_size=chunk_size, overlap=overlap)
        self.post_validator = PostValidator()

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def process_file(
        self,
        file_obj: BytesIO,
        filename: str,
        extra_metadata: Dict[str, Any] | None = None,
    ) -> List[RAGDocument]:
    
        """
        Ingest a file and return a list of clean RAGDocument chunks.

        Args:
            file_obj:       File-like object (e.g., open("report.pdf", "rb")).
            filename:       Original filename (used for format detection + metadata).
            extra_metadata: Optional dict merged into each chunk's metadata.

        Returns:
            List[RAGDocument] — empty list if file yielded no usable content.
        """
        # 1. Extract raw text
        try:
            raw_text = self.parser.read(file_obj, filename)
        except Exception as e:
            logger.warning(f"[RAGProcessor] Failed to read '{filename}': {e}")
            return []

        if not raw_text or not raw_text.strip():
            logger.info(f"[RAGProcessor] '{filename}' produced no text.")
            return []

        # 2. Assess Threat Level (tag the document)
        from .threat_scorer import assess_threat
        threat = assess_threat(filename, raw_text, confidence=1.0)

        # 3. Semantic chunking (respects code blocks, headers, log lines)
        raw_chunks: List[str] = self.parser.chunk(raw_text)
        if not raw_chunks:
            return []

        # 4. Build RAG Documents
        documents: List[RAGDocument] = []
        base_meta = {
            "source": filename,
            "threat_level": threat.level.value,
            "mitre_allowed": threat.mitre_allowed
        }
        if extra_metadata:
            base_meta.update(extra_metadata)

        for idx, chunk in enumerate(raw_chunks):
            chunk = chunk.strip()
            if not chunk:
                continue

            cleaned = self._sanitize(chunk, filename, threat)
            if not cleaned:
                continue

            doc = RAGDocument(
                chunk_id=idx,
                content=cleaned,
                metadata={
                    **base_meta,
                    "chunk_id":   idx,
                    "char_length": len(cleaned),
                },
            )
            documents.append(doc)

        logger.info(
            f"[RAGProcessor] '{filename}' → {len(documents)} chunks "
            f"(Threat: {threat.level.value})"
        )
        return documents

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _sanitize(self, text: str, filename: str, threat) -> str:
        """Pass text through PostValidator to strip hallucinations using the threat assessment."""
        try:
            record = {"output": text, "source_file": filename}
            cleaned_record = self.post_validator.sanitize_record(record, threat=threat)
            return cleaned_record.get("output", text).strip()
        except Exception:
            # If post-validator fails, return the original chunk (safe degradation)
            return text.strip()
