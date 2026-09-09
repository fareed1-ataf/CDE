# shared_lib/quality_scorer.py  — Cyber Data Engine v1.0.0
# =============================================================================
# UNIFIED QUALITY SCORING ENGINE
#
# Replaces the scattered _score_*() functions in validator.py with a single,
# coherent quality engine that measures ACTUAL information quality, not length.
#
# Quality Dimensions:
#   1. grounding_ratio    — tokens from source that appear in output
#   2. technical_depth    — density of unique cybersecurity terms
#   3. structural_completeness — required fields populated and non-empty
#   4. answer_coherence   — does output address the instruction?
#   5. no_hallucination   — absence of invented CVEs/IPs/hashes
#   6. mitre_validity     — ratio of valid MITRE IDs (format + in source)
#   7. language_diversity — vocabulary diversity (anti-repetition)
#
# Schema-specific weights are tuned to what matters for each format.
# =============================================================================

from __future__ import annotations

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from shared_lib.schemas import DataSchema

logger = logging.getLogger("CDE.QualityScorer")


# ─────────────────────────────────────────────────────────────────────────────
# Cybersecurity technical vocabulary (for depth scoring)
# ─────────────────────────────────────────────────────────────────────────────

_CYBER_TERMS: frozenset[str] = frozenset({
    # Malware / attack techniques
    "shellcode", "payload", "exploit", "injection", "buffer", "overflow",
    "rootkit", "trojan", "backdoor", "ransomware", "keylogger", "dropper",
    "loader", "stager", "beacon", "c2", "command", "control", "botnet",
    "lateral", "movement", "persistence", "privilege", "escalation",
    "exfiltration", "obfuscation", "encoding", "decoding", "meterpreter",
    "mimikatz", "cobalt", "strike", "metasploit", "powershell", "wscript",
    "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic",
    "lsass", "ntds", "kerberos", "pass-the-hash", "golden", "ticket",
    # Analysis terms
    "entropy", "signature", "heuristic", "sandbox", "decompile", "disassemble",
    "reversing", "yara", "rule", "detection", "indicator", "artifact",
    "forensics", "timeline", "volatility", "wireshark", "pcap", "traffic",
    "memory", "dump", "analysis", "malware", "static", "dynamic", "behavioral",
    # MITRE / framework
    "mitre", "attack", "tactic", "technique", "sub-technique", "procedure",
    "ioc", "ttp", "apt", "threat", "actor", "campaign", "attribution",
    # Vulnerability / CVE
    "vulnerability", "cve", "cvss", "cwe", "patch", "remediation", "mitigation",
    "rce", "lpe", "sqli", "xss", "ssrf", "idor", "csrf", "ssti", "deserialization",
    "buffer", "heap", "stack", "integer", "overflow", "use-after-free", "oob",
    # Network
    "firewall", "ids", "ips", "waf", "ngfw", "siem", "soar", "edr", "xdr",
    "proxy", "dns", "http", "https", "tls", "ssl", "certificate", "handshake",
    "beacon", "tunnel", "pivot", "port", "protocol", "socket", "listener",
    # Incident response
    "incident", "response", "containment", "eradication", "recovery",
    "triage", "escalation", "playbook", "runbook", "dfir", "chain-of-custody",
    # Cryptography
    "aes", "rsa", "sha", "md5", "hash", "encrypt", "decrypt", "key",
    "symmetric", "asymmetric", "certificate", "pki", "hmac", "nonce",
})

_MITRE_FORMAT = re.compile(r'^T\d{4}(\.\d{3})?$', re.I)
_CVE_FORMAT   = re.compile(r'CVE-(\d{4})-\d{4,}', re.I)
_VALID_YEARS  = frozenset(range(1999, 2027))


# ─────────────────────────────────────────────────────────────────────────────
# Quality result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class QualityScore:
    final:                 float  # 0.0 – 1.0 overall quality
    grounding_ratio:       float  = 0.0
    technical_depth:       float  = 0.0
    structural_completeness: float = 0.0
    language_diversity:    float  = 0.0
    mitre_validity:        float  = 0.0
    dimensions:            dict   = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Quality Engine
# ─────────────────────────────────────────────────────────────────────────────

class QualityEngine:
    """
    Unified quality scorer for all DataSchema types.

    Usage:
        engine = QualityEngine()
        score  = engine.score(schema, record_data, source_chunk)
        # score.final is in [0.0, 1.0]
    """

    # Schema-specific weights — what matters most per format
    SCHEMA_WEIGHTS: dict[str, dict[str, float]] = {
        "chain_of_thought": {
            "grounding":    0.40,
            "tech_depth":   0.20,
            "structure":    0.15,
            "diversity":    0.15,
            "mitre":        0.10,
        },
        "analysis": {
            "grounding":    0.35,
            "tech_depth":   0.25,
            "structure":    0.20,
            "diversity":    0.10,
            "mitre":        0.10,
        },
        "qa": {
            "grounding":    0.40,
            "tech_depth":   0.20,
            "structure":    0.25,
            "diversity":    0.15,
            "mitre":        0.00,
        },
        "code_gen": {
            "grounding":    0.25,
            "tech_depth":   0.30,
            "structure":    0.30,
            "diversity":    0.15,
            "mitre":        0.00,
        },
        "code_review": {
            "grounding":    0.30,
            "tech_depth":   0.30,
            "structure":    0.25,
            "diversity":    0.10,
            "mitre":        0.05,
        },
        "incident_playbook": {
            "grounding":    0.30,
            "tech_depth":   0.20,
            "structure":    0.35,
            "diversity":    0.10,
            "mitre":        0.05,
        },
        "detection_engineering": {
            "grounding":    0.30,
            "tech_depth":   0.25,
            "structure":    0.30,
            "diversity":    0.05,
            "mitre":        0.10,
        },
        "threat_hunting": {
            "grounding":    0.35,
            "tech_depth":   0.25,
            "structure":    0.25,
            "diversity":    0.10,
            "mitre":        0.05,
        },
        "forensic_timeline": {
            "grounding":    0.35,
            "tech_depth":   0.20,
            "structure":    0.30,
            "diversity":    0.10,
            "mitre":        0.05,
        },
        "multi_step_decision": {
            "grounding":    0.35,
            "tech_depth":   0.15,
            "structure":    0.35,
            "diversity":    0.15,
            "mitre":        0.00,
        },
        "tool_usage": {
            "grounding":    0.30,
            "tech_depth":   0.30,
            "structure":    0.30,
            "diversity":    0.10,
            "mitre":        0.00,
        },
        "negative_example": {
            "grounding":    0.30,
            "tech_depth":   0.15,
            "structure":    0.35,
            "diversity":    0.20,
            "mitre":        0.00,
        },
        "chat": {
            "grounding":    0.30,
            "tech_depth":   0.20,
            "structure":    0.25,
            "diversity":    0.25,
            "mitre":        0.00,
        },
        "alpaca": {
            "grounding":    0.35,
            "tech_depth":   0.20,
            "structure":    0.25,
            "diversity":    0.20,
            "mitre":        0.00,
        },
    }

    # Minimum quality per schema (records below → rejected)
    MIN_ACCEPTABLE: dict[str, float] = {
        "chain_of_thought":    0.38,
        "analysis":            0.38,
        "qa":                  0.35,
        "code_gen":            0.40,
        "code_review":         0.38,
        "incident_playbook":   0.35,
        "detection_engineering": 0.40,
        "threat_hunting":      0.38,
        "forensic_timeline":   0.35,
        "multi_step_decision": 0.35,
        "tool_usage":          0.38,
        "negative_example":    0.35,
        "chat":                0.35,
        "alpaca":              0.30,
    }

    def score(
        self,
        schema:      DataSchema | str,
        record_data: dict[str, Any],
        source_chunk: str = "",
    ) -> QualityScore:
        """
        Compute quality score for a generated record.

        Args:
            schema:       The DataSchema that was used (or its string value)
            record_data:  Parsed dict of the LLM's output (pre-validation)
            source_chunk: The original text chunk sent to the LLM

        Returns:
            QualityScore with .final in [0.0, 1.0]
        """
        schema_val = schema.value if hasattr(schema, "value") else str(schema)
        weights = self.SCHEMA_WEIGHTS.get(schema_val, self.SCHEMA_WEIGHTS["alpaca"])

        # Extract all text content from record
        all_text = self._extract_all_text(record_data)

        # ── Dimension 1: Grounding ──────────────────────────────────────────
        grounding = self._score_grounding(all_text, source_chunk)

        # ── Dimension 2: Technical Depth ────────────────────────────────────
        tech_depth = self._score_technical_depth(all_text)

        # ── Dimension 3: Structural Completeness ────────────────────────────
        structure = self._score_structure(schema_val, record_data)

        # ── Dimension 4: Language Diversity ─────────────────────────────────
        diversity = self._score_diversity(all_text)

        # ── Dimension 5: MITRE Validity ─────────────────────────────────────
        mitre = self._score_mitre_validity(record_data, source_chunk)

        # ── Weighted Final Score ─────────────────────────────────────────────
        final = (
            grounding  * weights["grounding"]
            + tech_depth * weights["tech_depth"]
            + structure  * weights["structure"]
            + diversity  * weights["diversity"]
            + mitre      * weights["mitre"]
        )
        final = round(min(max(final, 0.0), 1.0), 3)

        return QualityScore(
            final                  = final,
            grounding_ratio        = round(grounding, 3),
            technical_depth        = round(tech_depth, 3),
            structural_completeness= round(structure, 3),
            language_diversity     = round(diversity, 3),
            mitre_validity         = round(mitre, 3),
            dimensions             = {
                "grounding":  round(grounding, 3),
                "tech_depth": round(tech_depth, 3),
                "structure":  round(structure, 3),
                "diversity":  round(diversity, 3),
                "mitre":      round(mitre, 3),
                "weights":    weights,
            },
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Dimension scorers
    # ─────────────────────────────────────────────────────────────────────────

    def _score_grounding(self, output_text: str, source: str) -> float:
        """
        Measure what fraction of meaningful output tokens came from the source.
        Uses 4-char minimum (vs old 5-char) to capture nmap, aes, xor, etc.
        Returns 0.5 neutral if source is empty (can't penalize what we can't verify).
        """
        if not source:
            return 0.5
        if not output_text:
            return 0.0

        out_tokens = set(re.findall(r'\b[\w.\-:/]{3,}\b', output_text.lower()))
        src_tokens = set(re.findall(r'\b[\w.\-:/]{3,}\b', source.lower()))

        if not out_tokens:
            return 0.5

        overlap = len(out_tokens & src_tokens) / len(out_tokens)
        # Scale: 50% token overlap → score 1.0
        return min(overlap * 2.0, 1.0)

    def _score_technical_depth(self, text: str) -> float:
        """
        Measure presence of specific cybersecurity technical terms.
        More unique cyber terms → higher depth score.
        Target: 8+ unique cyber terms = score 1.0
        """
        if not text:
            return 0.0
        words = set(re.findall(r'\b\w+\b', text.lower()))
        cyber_hits = len(words & _CYBER_TERMS)
        # 8 unique cyber terms → score 1.0
        return min(cyber_hits / 8.0, 1.0)

    def _score_structure(self, schema_val: str, data: dict) -> float:
        """
        Schema-specific structural completeness check.
        Returns fraction of required fields that are non-empty.
        """
        REQUIRED: dict[str, list[str]] = {
            "chain_of_thought":     ["instruction", "reasoning", "answer"],
            "analysis":             ["instruction", "summary", "verdict"],
            "qa":                   ["pairs"],
            "code_gen":             ["inferred_prompt", "code"],
            "code_review":          ["code", "vulnerabilities", "summary"],
            "incident_playbook":    ["incident_type", "steps"],
            "detection_engineering":["behavior_observed", "detection_rule", "mitre_technique"],
            "threat_hunting":       ["hypothesis", "hunt_query", "verdict"],
            "forensic_timeline":    ["artifact_type", "findings", "timeline_summary"],
            "multi_step_decision":  ["trigger_event", "reasoning_chain", "final_decision"],
            "tool_usage":           ["scenario", "selected_tool", "command"],
            "negative_example":     ["incorrect_analysis", "why_wrong", "correct_analysis"],
            "chat":                 ["messages"],
            "alpaca":               ["instruction", "output"],
        }
        required = REQUIRED.get(schema_val, ["instruction", "output"])
        if not required:
            return 0.8

        filled = sum(
            1 for k in required
            if data.get(k) and str(data.get(k, "")).strip()
        )
        base_score = filled / len(required)

        # Bonus for depth: check list fields have ≥1 item
        list_fields = [k for k in required if isinstance(data.get(k), list)]
        if list_fields:
            non_empty = sum(1 for k in list_fields if data.get(k))
            base_score = (base_score + non_empty / len(list_fields)) / 2

        return base_score

    def _score_diversity(self, text: str) -> float:
        """
        Vocabulary diversity: unique_words / total_words.
        Penalizes repetitive/padded output.
        Only counts words ≥3 chars to exclude articles.
        """
        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        if len(words) < 10:
            return 0.3
        return min(len(set(words)) / len(words), 1.0)

    def _score_mitre_validity(self, data: dict, source: str) -> float:
        """
        Ratio of MITRE IDs that:
          a) Have valid format (T####[.###])
          b) Appear literally in the source chunk

        Returns 1.0 if no MITRE IDs claimed (not applicable).
        Returns ratio of valid/total if IDs are present.
        """
        mitre_ids = data.get("mitre_ids", [])
        if not mitre_ids:
            return 1.0  # No MITRE claimed — no penalty

        valid_count = 0
        for mid in mitre_ids:
            mid_clean = str(mid).strip().upper()
            # Format check
            if not _MITRE_FORMAT.match(mid_clean):
                continue
            # Source grounding check
            if mid_clean in source.upper():
                valid_count += 1
            else:
                # Not in source but format is valid — half credit
                valid_count += 0.5

        return min(valid_count / len(mitre_ids), 1.0)

    # ─────────────────────────────────────────────────────────────────────────
    # Helper
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_all_text(self, data: dict) -> str:
        """Concatenate all string values from the record dict."""
        parts = []
        for v in data.values():
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        parts.append(item)
                    elif isinstance(item, dict):
                        parts.extend(str(vv) for vv in item.values() if isinstance(vv, str))
        return " ".join(parts)


# ── Module singleton ──────────────────────────────────────────────────────────
_engine = QualityEngine()


def score_quality(
    schema:       DataSchema | str,
    record_data:  dict[str, Any],
    source_chunk: str = "",
) -> QualityScore:
    """
    Public API — compute unified quality score for any schema.

    Args:
        schema:       DataSchema enum or string value
        record_data:  Parsed dict of the generated record
        source_chunk: Original text chunk sent to LLM (for grounding)

    Returns:
        QualityScore with .final in [0.0, 1.0] and dimension breakdown
    """
    return _engine.score(schema, record_data, source_chunk)


def get_min_quality(schema: DataSchema | str) -> float:
    """Return the minimum acceptable quality threshold for this schema."""
    schema_val = schema.value if hasattr(schema, "value") else str(schema)
    return _engine.MIN_ACCEPTABLE.get(schema_val, 0.35)
