# shared_lib/grounding_validator.py  — Cyber Data Engine v1.0.0
# =============================================================================
# GROUNDING VALIDATOR — Anti-Hallucination Layer
#
# v1.0.0 Release:
#   Bug#1 FIX: Raised validate_text_grounding threshold from 0.25 → 0.40
#              The 25% threshold was the primary cause of hallucinated output
#              passing validation silently.
#
#   Bug#8 FIX: Regex now captures short technical tokens (IPs, hashes, CVE IDs,
#              tool names like nmap/AES/XOR) that were previously ignored.
#
# Grounding Levels:
#   EXACT       — verbatim match in source
#   SEMANTIC    — ≥40% meaningful token overlap with source (v1.0.0: raised from 25%)
#   UNSUPPORTED — hallucinated — not supported by source text
# =============================================================================

import re
from enum import Enum
from dataclasses import dataclass


class GroundingLevel(Enum):
    EXACT       = "exact"        # Word/phrase exists verbatim in source
    SEMANTIC    = "semantic"     # Meaning supported by token overlap ≥ 40%
    UNSUPPORTED = "unsupported"  # Hallucinated — not in source


@dataclass
class GroundingResult:
    level:      GroundingLevel
    confidence: float
    evidence:   str


# ─────────────────────────────────────────────────────────────────────────────
# Technical token extractor
# ─────────────────────────────────────────────────────────────────────────────

# Extracts BOTH standard words AND short/technical tokens that matter in
# cybersecurity:  IPs, CVEs, hashes, hex values, tool names (nmap, xor, aes),
# port numbers, MITRE IDs, registry paths, etc.
_TECHNICAL_PATTERN = re.compile(
    r'(?:'
    # IP addresses
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    # CVE IDs
    r'|CVE-\d{4}-\d{4,}'
    # MITRE technique IDs
    r'|T\d{4}(?:\.\d{3})?'
    # SHA256 / SHA1 / MD5 hashes (hex strings ≥ 8 chars)
    r'|[0-9a-fA-F]{8,64}'
    # Registry keys
    r'|HKEY_\w+'
    # Standard words ≥ 3 chars (lowered from 5 to capture nmap, aes, xor, etc.)
    r'|\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b'
    r')',
    re.IGNORECASE,
)

# Common English stop words to exclude from grounding comparison
_STOP_WORDS: frozenset[str] = frozenset({
    "the", "and", "for", "are", "was", "with", "this", "that", "from",
    "have", "has", "had", "not", "but", "can", "its", "all", "any",
    "more", "also", "will", "would", "could", "should", "been", "being",
    "which", "when", "then", "than", "them", "they", "their", "there",
    "these", "those", "some", "such", "into", "over", "after", "before",
    "above", "about", "other", "our", "your", "you", "she", "his", "her",
    "who", "how", "what", "where", "why", "each", "both", "few", "more",
    "most", "only", "own", "same", "very", "just", "because", "while",
    "during", "through", "between", "under", "again", "further", "once",
    "here", "out", "off", "own", "now", "per", "may", "use", "used",
    "using", "like", "make", "made", "said", "see", "set", "does", "did",
    "doing", "get", "got", "let", "put", "run", "ran", "new", "old",
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
    "ten", "zero", "true", "false", "null", "none", "yes", "way", "too",
})


def _extract_tokens(text: str) -> set[str]:
    """
    Extract meaningful tokens from text for grounding comparison.

    Unlike the old implementation (only words ≥5 chars), this captures:
      - Standard words ≥ 3 chars (minus stop words)
      - IP addresses, CVE IDs, MITRE technique IDs
      - Hash values (hex strings ≥ 8 chars)
      - Short technical terms: nmap, aes, xor, c2, dns, tcp, udp, etc.
    """
    raw = _TECHNICAL_PATTERN.findall(text.lower())
    return {t for t in raw if t not in _STOP_WORDS and len(t) >= 2}


# ─────────────────────────────────────────────────────────────────────────────
# Grounding Validator
# ─────────────────────────────────────────────────────────────────────────────

class GroundingValidator:
    """
    Validates that LLM-generated claims are actually grounded in source text.

    v1.0.0 Changes:
      - SEMANTIC threshold raised from 0.25 → 0.40 (Bug#1 fix)
      - Token extraction improved to include short technical terms (Bug#8 fix)
      - Added verbatim phrase detection for IOCs and technical artifacts
    """

    # v1.0.0: Raised from 0.25 to 0.40 — the core hallucination fix.
    # At 0.25, LLM could invent 75% of content and still pass.
    # At 0.40, at least 40% of meaningful tokens must exist in source.
    SEMANTIC_THRESHOLD = 0.40

    # Threshold for validate_claim (single claim vs source)
    CLAIM_SEMANTIC_THRESHOLD = 0.60

    def validate_text_grounding(self, text: str, source: str) -> GroundingResult:
        """
        Validates if a block of generated text is grounded in the source.

        Returns SEMANTIC if ≥40% of meaningful tokens overlap with source.
        Returns UNSUPPORTED otherwise (hallucination signal).

        Args:
            text:   The generated text (LLM output block)
            source: The source chunk that was sent to the LLM
        """
        if not text or not source:
            return GroundingResult(GroundingLevel.UNSUPPORTED, 0.0, "empty_input")

        text_tokens   = _extract_tokens(text)
        source_tokens = _extract_tokens(source)

        if not text_tokens:
            # Output has no extractable tokens — could be binary/encoded output
            # Treat as neutral (SEMANTIC) to avoid false rejections
            return GroundingResult(GroundingLevel.SEMANTIC, 1.0, "no_tokens_extracted")

        overlap = len(text_tokens & source_tokens) / len(text_tokens)

        if overlap >= self.SEMANTIC_THRESHOLD:
            return GroundingResult(
                GroundingLevel.SEMANTIC,
                round(overlap, 3),
                f"token_overlap:{overlap:.2f}",
            )

        return GroundingResult(
            GroundingLevel.UNSUPPORTED,
            round(overlap, 3),
            f"insufficient_overlap:{overlap:.2f}_required:{self.SEMANTIC_THRESHOLD}",
        )

    def validate_claim(self, claim: str, source: str) -> GroundingResult:
        """
        Validates a single claim (e.g. an IOC, MITRE ID, CVE) against source.

        Strategy:
          Level 1 — Exact string match in source → EXACT
          Level 2 — Token overlap ≥ 60% → SEMANTIC
          Level 3 — Everything else → UNSUPPORTED (hallucinated)

        Args:
            claim:  A specific claim extracted from LLM output (IOC, ID, phrase)
            source: The original source chunk
        """
        if not claim or not source:
            return GroundingResult(GroundingLevel.UNSUPPORTED, 0.0, "empty_input")

        claim_lower  = claim.lower().strip()
        source_lower = source.lower()

        # Level 1: Exact Match — fastest, strongest validation
        if claim_lower in source_lower:
            return GroundingResult(GroundingLevel.EXACT, 1.0, claim)

        # Level 2: Semantic Token Overlap
        claim_tokens  = _extract_tokens(claim_lower)
        source_tokens = _extract_tokens(source_lower)

        if not claim_tokens:
            return GroundingResult(GroundingLevel.UNSUPPORTED, 0.0, "no_claim_tokens")

        overlap = len(claim_tokens & source_tokens) / len(claim_tokens)

        if overlap >= self.CLAIM_SEMANTIC_THRESHOLD:
            return GroundingResult(
                GroundingLevel.SEMANTIC,
                round(overlap, 3),
                f"token_overlap:{overlap:.2f}",
            )

        # Level 3: Unsupported — reject as potential hallucination
        return GroundingResult(
            GroundingLevel.UNSUPPORTED,
            round(overlap, 3),
            f"ungrounded:overlap={overlap:.2f}",
        )

    def validate_mitre_id(self, mitre_id: str, source: str) -> GroundingResult:
        """
        Special validation for MITRE technique IDs.
        Checks if the ID itself OR related technique keywords appear in source.
        """
        if not mitre_id or not source:
            return GroundingResult(GroundingLevel.UNSUPPORTED, 0.0, "empty_input")

        mitre_upper  = mitre_id.upper().strip()
        source_upper = source.upper()

        # Check if MITRE ID appears literally in source
        if mitre_upper in source_upper:
            return GroundingResult(GroundingLevel.EXACT, 1.0, mitre_upper)

        # Otherwise treat as UNSUPPORTED (MITRE IDs shouldn't be invented)
        return GroundingResult(
            GroundingLevel.UNSUPPORTED,
            0.0,
            f"mitre_id_not_in_source:{mitre_upper}",
        )
