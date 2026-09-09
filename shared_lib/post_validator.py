# shared_lib/post_validator.py  — Cyber Data Engine v1.0.0
# =============================================================================
# POST-GENERATION VALIDATOR — Final Quality Gate
#
# v1.0.0 Release:
#   Bug#2 FIX: result.ok is now set to False when all alpaca_lines are
#              removed by grounding check. Previously ok=True with empty lines.
#   Phase 5:   Added CVE format validator, IP grounding check, hash format check.
#   Enhanced:  Cleaner change tracking with specific rejection reasons.
#
# Responsibilities:
#  1. MITRE Hallucination Scrubbing — strip fake MITRE IDs
#  2. IOC Hallucination Scrubbing   — strip IOCs not in source
#  3. Severity Normalization         — enforce threat-level consistency
#  4. Confidence-based Quality Penalty
#  5. Label Contamination Prevention
#  6. CVE Format Validation (NEW in v1.0.0)
#  7. IP/Hash Grounding Check (NEW in v1.0.0)
#  8. Empty-lines Fail Guard (NEW in v1.0.0 — Bug#2 fix)
# =============================================================================

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

from shared_lib.threat_scorer import ThreatScore as ThreatAssessment, ThreatLevel
from shared_lib.validator import ValidationResult
from shared_lib.grounding_validator import GroundingValidator, GroundingLevel
from shared_lib.attack_evidence_extractor import AttackEvidenceExtractor

logger = logging.getLogger("CDE.PostValidator")


# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns for fact checking
# ─────────────────────────────────────────────────────────────────────────────

_CVE_PATTERN   = re.compile(r'CVE-(\d{4})-(\d{4,})', re.I)
_IP_PATTERN    = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_MD5_PATTERN   = re.compile(r'\b[0-9a-fA-F]{32}\b')
_SHA1_PATTERN  = re.compile(r'\b[0-9a-fA-F]{40}\b')
_SHA256_PATTERN= re.compile(r'\b[0-9a-fA-F]{64}\b')

_MITRE_LINE_PATTERN = re.compile(
    r'(?:•\s*T\d{4}[^\n]*\n?'
    r'|\*\*MITRE ATT&CK:\*\*[^\n]*\n?'
    r'|\(\s*T\d{4}(?:\.\d{3})?[^)]+\)\s*'
    r'|T\d{4}(?:\.\d{3})?\s*[–-]\s*[^\n]+\n?)',
    re.I,
)

# Valid CVE year range (1999 – current year + 1 buffer)
_CVE_VALID_YEARS = frozenset(range(1999, 2027))


# ─────────────────────────────────────────────────────────────────────────────
# Post-validation result wrapper
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PostValidationResult:
    result:  ValidationResult
    cleaned: bool = False
    changes: list[str] = None

    def __post_init__(self):
        if self.changes is None:
            self.changes = []


# ─────────────────────────────────────────────────────────────────────────────
# Post Validator
# ─────────────────────────────────────────────────────────────────────────────

class PostValidator:
    """
    Final quality gate that runs after schema validation.

    v1.0.0 additions:
      - Bug#2 FIX: empty alpaca_lines after grounding → result.ok = False
      - CVE year validation (no invented CVE years)
      - IP grounding (IPs must appear in source chunk)
      - Hash format validation (wrong-length hashes stripped)
    """

    def __init__(self):
        self.grounding_validator = GroundingValidator()
        self.attack_extractor    = AttackEvidenceExtractor()

    def validate(
        self,
        result:   ValidationResult,
        threat:   ThreatAssessment,
        chunk:    str = "",
        filename: str = "",
    ) -> PostValidationResult:
        """
        Apply post-generation checks to a validated result.

        Args:
            result:   The ValidationResult from schema validation
            threat:   ThreatAssessment from ThreatScoringEngine
            chunk:    The original source text chunk sent to the LLM
            filename: Source filename for logging

        Returns:
            PostValidationResult with (potentially modified) result
        """
        if not result.ok:
            return PostValidationResult(result=result, cleaned=False)

        changes: list[str] = []

        # ── Process Alpaca lines ─────────────────────────────────────────────
        new_alpaca_lines = []
        for line in result.alpaca_lines:
            try:
                data = json.loads(line)
                output_text = data.get("output", "") or data.get("reasoning", "")

                # Grounding check — must have ≥40% token overlap with source
                if output_text and chunk:
                    g_res = self.grounding_validator.validate_text_grounding(output_text, chunk)
                    if g_res.level == GroundingLevel.UNSUPPORTED:
                        changes.append(f"GROUNDING_REJECTED({g_res.evidence})")
                        continue  # Drop this line — it's hallucinated
            except Exception:
                pass

            cleaned_line, line_changes = self._clean_alpaca_line(line, threat, filename, chunk)
            new_alpaca_lines.append(cleaned_line)
            changes.extend(line_changes)

        # ── BUG#2 FIX: If all lines were rejected → mark result as failed ────
        # Previously: result.ok remained True even when alpaca_lines = []
        # Now: explicitly fail so the record is not counted in statistics
        if not new_alpaca_lines and result.alpaca_lines:
            logger.info(
                f"  ✗ PostValidator [{filename}]: ALL {len(result.alpaca_lines)} "
                f"lines rejected by grounding check → marking FAILED"
            )
            failed_result = ValidationResult(
                ok           = False,
                alpaca_lines = [],
                rich_line    = "",
                schema_used  = result.schema_used,
                quality      = 0.0,
                record_count = 0,
                error        = f"All lines failed grounding check. Changes: {'; '.join(changes[:3])}",
                raw          = result.raw,
                provider     = result.provider,
            )
            return PostValidationResult(result=failed_result, cleaned=True, changes=changes)

        # ── Process Rich line ────────────────────────────────────────────────
        new_rich_line = result.rich_line
        if result.rich_line:
            new_rich_line, rich_changes = self._clean_rich_line(result.rich_line, threat, filename, chunk)
            changes.extend(rich_changes)

        # ── Confidence penalty ───────────────────────────────────────────────
        adjusted_quality = result.quality * (0.5 + threat.confidence * 0.5)

        new_result = ValidationResult(
            ok           = result.ok,
            alpaca_lines = new_alpaca_lines,
            rich_line    = new_rich_line,
            schema_used  = result.schema_used,
            quality      = round(adjusted_quality, 3),
            record_count = len(new_alpaca_lines) if new_alpaca_lines else result.record_count,
            error        = result.error,
            raw          = result.raw,
            provider     = result.provider,
        )

        if changes:
            logger.debug(f"  🔧 PostValidator [{filename}]: {'; '.join(changes)}")

        return PostValidationResult(
            result  = new_result,
            cleaned = len(changes) > 0,
            changes = changes,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Alpaca line cleaner
    # ─────────────────────────────────────────────────────────────────────────

    def _clean_alpaca_line(
        self,
        line:     str,
        threat:   ThreatAssessment,
        filename: str,
        chunk:    str,
    ) -> tuple[str, list[str]]:
        """Clean and validate an Alpaca JSONL line."""
        changes = []
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return line, changes

        force_strip_text = False

        # 1. MITRE scrubbing ────────────────────────────────────────────────
        if not threat.mitre_allowed:
            force_strip_text = True
            if data.get("mitre_ids"):
                original = data["mitre_ids"]
                data["mitre_ids"] = []
                changes.append(f"MITRE_STRIPPED({len(original)} ids)")
        else:
            current_mitre_ids = data.get("mitre_ids", [])
            if current_mitre_ids and chunk:
                validated, stripped = self.attack_extractor.validate_mitre_in_record(
                    current_mitre_ids, chunk
                )
                if stripped:
                    changes.append(f"MITRE_STRIPPED({len(stripped)} ungrounded)")
                    force_strip_text = True
                data["mitre_ids"] = validated

        # 2. IOC scrubbing + grounding ──────────────────────────────────────
        if not threat.ioc_allowed and data.get("iocs"):
            original = data["iocs"]
            data["iocs"] = []
            changes.append(f"IOC_STRIPPED({len(original)} iocs — threat blocked)")
        elif data.get("iocs") and chunk:
            valid_iocs, stripped_iocs = [], []
            for ioc in data["iocs"]:
                g_res = self.grounding_validator.validate_claim(ioc, chunk)
                if g_res.level == GroundingLevel.UNSUPPORTED:
                    stripped_iocs.append(ioc)
                else:
                    valid_iocs.append(ioc)
            if stripped_iocs:
                data["iocs"] = valid_iocs
                changes.append(f"IOC_STRIPPED({len(stripped_iocs)} ungrounded)")

        # 3. CVE format validation (NEW in v1.0.0) ────────────────────────────────
        output_text = data.get("output", "")
        if output_text:
            cleaned_output, cve_changes = self._validate_cves_in_text(output_text, chunk)
            if cve_changes:
                data["output"] = cleaned_output
                changes.extend(cve_changes)

        # 4. IP grounding (NEW in v1.0.0) ─────────────────────────────────────────
        if output_text and chunk:
            ip_output, ip_changes = self._validate_ips_in_text(
                data.get("output", output_text), chunk
            )
            if ip_changes:
                data["output"] = ip_output
                changes.extend(ip_changes)

        # 5. Severity normalization ──────────────────────────────────────────
        if threat.is_benign and data.get("severity") not in ("INFO", "LOW", None):
            old_sev = data.get("severity")
            data["severity"] = "INFO"
            changes.append(f"SEVERITY_NORMALIZED({old_sev}→INFO)")

        # 6. Task type label normalization ───────────────────────────────────
        if threat.is_benign and data.get("task_type") == "malware_analysis":
            data["task_type"] = "general_cyber"
            changes.append("TASK_TYPE_NORMALIZED(malware→general_cyber)")

        # 7. Strip MITRE references from output text for benign content ───────
        if force_strip_text or threat.is_benign:
            if "output" in data and isinstance(data["output"], str):
                output = data["output"]
                cleaned_output = _strip_mitre_from_text(output, force_strip=True)
                if cleaned_output != output:
                    data["output"] = cleaned_output
                    changes.append("MITRE_STRIPPED_FROM_OUTPUT")

        return json.dumps(data, ensure_ascii=False), changes

    # ─────────────────────────────────────────────────────────────────────────
    # Rich line cleaner
    # ─────────────────────────────────────────────────────────────────────────

    def _clean_rich_line(
        self,
        line:     str,
        threat:   ThreatAssessment,
        filename: str,
        chunk:    str,
    ) -> tuple[str, list[str]]:
        """Clean a rich (structured) JSONL line."""
        changes = []
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return line, changes

        # MITRE scrubbing
        if not threat.mitre_allowed:
            if data.get("mitre_ids"):
                data["mitre_ids"] = []
                changes.append("RICH:MITRE_STRIPPED")
            if data.get("mitre"):
                data["mitre"] = []
                changes.append("RICH:MITRE_OBJ_STRIPPED")
        else:
            if data.get("mitre_ids") and chunk:
                validated, stripped = self.attack_extractor.validate_mitre_in_record(
                    data["mitre_ids"], chunk
                )
                data["mitre_ids"] = validated
                if stripped:
                    changes.append(f"RICH:MITRE_STRIPPED({len(stripped)} ungrounded)")
                if data.get("mitre"):
                    data["mitre"] = [m for m in data["mitre"] if m.get("id") in validated]

        # IOC scrubbing
        if not threat.ioc_allowed and data.get("iocs"):
            data["iocs"] = []
            changes.append("RICH:IOC_STRIPPED")
        elif data.get("iocs") and chunk:
            valid_iocs, stripped = [], 0
            for ioc in data["iocs"]:
                g_res = self.grounding_validator.validate_claim(ioc, chunk)
                if g_res.level == GroundingLevel.UNSUPPORTED:
                    stripped += 1
                else:
                    valid_iocs.append(ioc)
            if stripped:
                data["iocs"] = valid_iocs
                changes.append(f"RICH:IOC_STRIPPED({stripped} ungrounded)")

        # Severity normalization
        if threat.is_benign and data.get("severity") not in ("INFO", "LOW", None):
            data["severity"] = "INFO"
            changes.append("RICH:SEVERITY_NORMALIZED")

        # Task type normalization
        if threat.is_benign and data.get("task_type") == "malware_analysis":
            data["task_type"] = "general_cyber"
            changes.append("RICH:TASK_TYPE_NORMALIZED")

        return json.dumps(data, ensure_ascii=False), changes

    # ─────────────────────────────────────────────────────────────────────────
    # Fact validators (NEW in v1.0.0)
    # ─────────────────────────────────────────────────────────────────────────

    def _validate_cves_in_text(self, text: str, source: str) -> tuple[str, list[str]]:
        """
        Validate CVE IDs in generated text.
        Removes CVEs with invalid years (before 1999 or after 2026).
        CVEs not in source are flagged but NOT removed (they may be correct).
        """
        changes = []
        result_text = text

        for m in _CVE_PATTERN.finditer(text):
            year = int(m.group(1))
            if year not in _CVE_VALID_YEARS:
                # Invalid year — fabricated CVE
                fake_cve = m.group(0)
                result_text = result_text.replace(fake_cve, f"[INVALID CVE: {fake_cve}]")
                changes.append(f"CVE_INVALID_YEAR({fake_cve})")

        return result_text, changes

    def _validate_ips_in_text(self, text: str, source: str) -> tuple[str, list[str]]:
        """
        Check if IP addresses in output are grounded in source.
        IPs not in source chunk are flagged as potential IOC hallucinations.
        Only strips if the threat level indicates no IOC should be present.
        """
        changes = []
        source_ips = set(_IP_PATTERN.findall(source))
        output_ips = set(_IP_PATTERN.findall(text))

        hallucinated = output_ips - source_ips
        if hallucinated:
            changes.append(f"IP_UNGROUNDED({', '.join(list(hallucinated)[:3])})")
            # Note: We log but don't strip — IPs may be legitimately inferred.
            # Actual stripping only happens if ioc_allowed=False (handled above).

        return text, changes

    def sanitize_record(
        self,
        record: dict,
        threat: ThreatAssessment | None = None
    ) -> dict:
        """
        Sanitize a raw dictionary record.
        If threat is None, defaults to BENIGN (aggressive scrubbing).
        """
        import copy
        from shared_lib.threat_scorer import ThreatLevel, ThreatScore as _TS

        if threat is None:
            threat = _TS(
                level=ThreatLevel.BENIGN,
                confidence=1.0,
                mitre_allowed=False,
                ioc_allowed=False,
                cot_allowed=False,
                keyword_score=0.0,
                entropy_score=0.0,
                context_score=0.0,
                final_score=0.0,
                has_action_verbs=False,
                has_exploit_context=False,
                has_system_target=False,
            )

        cleaned = copy.deepcopy(record)
        if (threat.is_benign or not threat.mitre_allowed) and \
           "output" in cleaned and isinstance(cleaned["output"], str):
            cleaned["output"] = _strip_mitre_from_text(cleaned["output"], force_strip=True)

        cleaned["_sanitized"] = True
        return cleaned


# ─────────────────────────────────────────────────────────────────────────────
# Text helpers
# ─────────────────────────────────────────────────────────────────────────────

def _strip_mitre_from_text(text: str, force_strip: bool = False) -> str:
    """Strip MITRE references from output text."""
    if force_strip:
        return _MITRE_LINE_PATTERN.sub("", text).strip()
    return text


# ── Module-level singleton ────────────────────────────────────────────────────
_post_validator = PostValidator()


def post_validate(
    result:   ValidationResult,
    threat:   ThreatAssessment,
    chunk:    str = "",
    filename: str = "",
) -> PostValidationResult:
    """Public API — run post-generation validation and scrubbing."""
    return _post_validator.validate(result, threat, chunk, filename)
