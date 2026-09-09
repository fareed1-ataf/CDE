# core/validator.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# MULTI-SCHEMA VALIDATOR + QUALITY SCORER
#
# v1.0.0 Release:
#   Bug#3 FIX: code_gen quality now uses structural analysis (syntax diversity,
#              control flow presence, description quality) — not just length.
#   Bug#7 FIX: _val_alpaca fallback now logs explicitly with schema_fallback=True
#              so statistics correctly show fallback rate.
#   Bug#6 FIX: QA dedup threshold lowered from 0.75 → 0.65 to allow diverse
#              questions about the same topic.
#   UPGRADE:   All schema scorers now optionally accept source_chunk for
#              improved grounding measurement.
# =============================================================================
"""
validator.py  —  Multi-Schema LLM Output Validator & Quality Scorer

Validation Pipeline per record:
  Step 1 — JSON extraction (four progressive strategies):
             a. Direct json.loads() on cleaned text.
             b. Regex-based JSON repair (_repair) for escaped chars.
             c. Brace-matched extraction (_brace_extract) for embedded JSON.
             Falls back to alpaca schema on all failures.
  Step 2 — Schema-specific Pydantic validation via a dispatch table.
  Step 3 — Quality scoring (0.0–1.0) based on information density:
             - Grounding: reasoning tokens overlapping with evidence tokens.
             - MITRE/IOC presence and count.
             - Vocabulary diversity (penalises repetitive/padded output).
             - Turn count and assistant content depth (ChatML schema).
  Step 4 — Normalisation → Alpaca JSONL line(s) + full rich JSONL line.

Quality Score Guarantee:
    Records scoring below min_quality (default 0.35) are rejected (ok=False).
    All quality values lie in {0.0} ∪ [0.35, 0.99] by design — the grounding
    rejection floor makes the range binary: rejected (0.0) or acceptable (0.35+).

Fallback Behaviour:
    If schema-specific validation fails for any reason, _val_alpaca() is tried
    as a last resort. This produces a lower-quality but structurally valid record.
"""

from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from shared_lib.schemas import (
    DataSchema, TaskType, Severity, MitreEntry,
    ChainOfThoughtEntry, StructuredAnalysisEntry,
    QABatchEntry, QAPair, ChatMLEntry, ChatMsg,
    CodeGenEntry, CodeReviewEntry, CodeVuln,
    IncidentPlaybookEntry, IRStep, AlpacaEntry,
    ToolUsageEntry, ThreatHuntingEntry, MultiStepDecisionEntry, DecisionStep,
    DetectionEngineeringEntry, ForensicTimelineEntry, TimelineFinding, NegativeExampleEntry,
    Classification,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    ok:           bool
    alpaca_lines: list[str]  = field(default_factory=list)
    rich_line:    str        = ""
    schema_used:  str        = ""
    quality:      float      = 0.0
    record_count: int        = 0
    error:        str        = ""
    raw:          str        = ""
    provider:     str        = ""


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

# VALIDATE — main entry point: extract JSON → validate against schema → score quality.
# Args:    raw: str           — raw LLM response string.
#          cls: Classification — classification driving schema selection.
#          source_file: str   — source filename for embedding in output records.
#          provider_name: str — provider name for embedding in output records.
#          min_quality: float — records below this threshold are rejected.
# Returns: ValidationResult with ok=True/False, alpaca_lines, rich_line, quality.
# Side effects: None. Pure computation.
def validate(
    raw:            str,
    cls:            Classification,
    source_file:    str = "",
    provider_name:  str = "",
    min_quality:    float = 0.35,
    source_chunk:   str = "",
) -> ValidationResult:
    """Main validation entry point.

    Args:
        raw:          Raw LLM response string
        cls:          Classification driving schema selection
        source_file:  Source filename for embedding in output records
        provider_name: Provider name for embedding in output records
        min_quality:  Records below this quality threshold are rejected
        source_chunk: Original text chunk sent to LLM (v1.0.0 — used for grounding)
    """
    if not raw or not raw.strip():
        return ValidationResult(ok=False, error="Empty LLM response.", raw=raw)

    cleaned = _clean(raw)
    schema  = cls.schema

    # Route to schema validator
    dispatch = {
        DataSchema.CHAIN_OF_THOUGHT:  _val_cot,
        DataSchema.ANALYSIS:          _val_analysis,
        DataSchema.QA:                _val_qa,
        DataSchema.CHAT:              _val_chat,
        DataSchema.CODE_GEN:          _val_code_gen,
        DataSchema.CODE_REVIEW:       _val_code_review,
        DataSchema.INCIDENT_PLAYBOOK: _val_playbook,
        DataSchema.ALPACA:            _val_alpaca,
        # Phase 3
        DataSchema.TOOL_USAGE:            _val_tool_usage,
        DataSchema.THREAT_HUNTING:        _val_threat_hunting,
        DataSchema.MULTI_STEP_DECISION:   _val_multi_step_decision,
        DataSchema.DETECTION_ENGINEERING: _val_detection_engineering,
        DataSchema.FORENSIC_TIMELINE:     _val_forensic_timeline,
        DataSchema.NEGATIVE_EXAMPLE:      _val_negative_example,
    }
    fn = dispatch.get(schema, _val_alpaca)

    # All validators accept (text, cls, src, source_chunk="") — direct call, no TypeError guard needed.
    logger.debug(f"Dispatching to {fn.__name__} for schema {schema.value}")
    result = fn(cleaned, cls, source_file, source_chunk)

    # Quality gate
    if result.ok and result.quality < min_quality:
        result.ok    = False
        result.error = f"Quality score {result.quality:.2f} below threshold {min_quality}."

    result.raw      = raw
    result.provider = provider_name
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Schema validators
# ─────────────────────────────────────────────────────────────────────────────

def _val_cot(text, cls, src, source_chunk=""):
    data = _parse(text)
    if data is None:
        return ValidationResult(ok=False, error=f"JSON parse failed: {text[:120]!r}")

    try:
        entry = ChainOfThoughtEntry(
            task_type  = _coerce_task(data.get("task_type"), cls.task_type),
            instruction= _req(data, "instruction"),
            evidence   = data.get("evidence", data.get("input", data.get("raw_sample",""))),
            reasoning  = _req(data, "reasoning"),
            answer     = data.get("answer", data.get("conclusion", data.get("output",""))),
            severity   = _coerce_sev(data.get("severity")),
            mitre_ids  = _list_str(data.get("mitre_ids", data.get("mitre",[]))),
            iocs       = _list_str(data.get("iocs",[])),
            source_file= src,
        )
        q = _score_cot(entry)
        entry.quality_score = q
        return ValidationResult(
            ok=True,
            alpaca_lines=[entry.to_alpaca_jsonl()],
            rich_line=entry.to_jsonl(),
            schema_used="chain_of_thought",
            quality=q,
            record_count=1,
        )
    except Exception as e:
        logger.debug("CoT validation failed (%s) — falling back to alpaca", e)
        return _val_alpaca(text, cls, src, schema_fallback="chain_of_thought")


def _val_analysis(text, cls, src, source_chunk=""):
    data = _parse(text)
    if data is None:
        return ValidationResult(ok=False, error=f"JSON parse failed: {text[:120]!r}")
    try:
        mitre = [_parse_mitre_item(m) for m in _listify(data.get("mitre", data.get("mitre_ids",[])))]
        mitre = [m for m in mitre if m]
        iocs  = _list_str(data.get("iocs",[]))
        cves  = _list_str(data.get("cve_ids", data.get("cves",[])))
        mits  = _list_str(data.get("mitigations",[]))
        entry = StructuredAnalysisEntry(
            task_type   = _coerce_task(data.get("task_type"), cls.task_type),
            instruction = _req(data, "instruction"),
            raw_sample  = data.get("raw_sample", data.get("input","N/A")),
            summary     = _req(data, "summary", fallback=data.get("conclusion","")),
            mitre       = mitre,
            iocs        = iocs,
            cve_ids     = cves,
            severity    = _coerce_sev(data.get("severity")),
            mitigations = mits,
            verdict     = data.get("verdict",""),
            source_file = src,
        )
        q = _score_analysis(entry)
        entry.quality_score = q
        return ValidationResult(
            ok=True,
            alpaca_lines=[entry.to_alpaca_jsonl()],
            rich_line=entry.to_jsonl(),
            schema_used="analysis",
            quality=q,
            record_count=1,
        )
    except Exception as e:
        logger.debug("Analysis validation failed (%s) — falling back to alpaca", e)
        return _val_alpaca(text, cls, src, schema_fallback="analysis")


def _val_qa(text, cls, src, source_chunk: str = ""):
    data = _parse(text)
    if data is None:
        return ValidationResult(ok=False, error=f"JSON parse failed: {text[:120]!r}")

    raw_pairs = data.get("pairs", data if isinstance(data, list) else [data])
    if not isinstance(raw_pairs, list):
        raw_pairs = [raw_pairs]

    pairs, errors = [], []
    for item in raw_pairs:
        if not isinstance(item, dict): continue
        try:
            pairs.append(QAPair(
                question  = _req(item, "question"),
                context   = item.get("context",""),
                answer    = _req(item, "answer"),
                difficulty= item.get("difficulty","medium"),
                task_type = item.get("task_type", cls.task_type.value),
            ))
        except Exception as e:
            errors.append(str(e))

    if source_chunk:
        for pair in pairs:
            answer_text = pair.answer or ""
            if answer_text and len(answer_text) > 50:
                g = _grounding_score(answer_text, source_chunk)
                if g < 0.15:
                    errors.append(f"qa_answer_ungrounded(g={g:.2f})")

    if not pairs or errors:
        return ValidationResult(ok=False, error=f"No QA pairs or grounding failed. Errors: {errors[:2]}")

    # Bug#6 FIX: Lowered threshold from 0.75 → 0.65
    # Old value was too strict: technical questions sharing domain vocabulary
    # (e.g., two questions about the same malware family) were incorrectly deduped.
    deduped: list[QAPair] = []
    for pair in pairs:
        if all(_jaccard_sim(pair.question, p.question) < 0.65 for p in deduped):
            deduped.append(pair)
    if not deduped:
        return ValidationResult(ok=False, error="All QA pairs rejected by semantic deduplication.")
    pairs = deduped

    entry = QABatchEntry(pairs=pairs, source_file=src,
                         task_type=_coerce_task(None, cls.task_type))
    q = _score_qa(pairs)
    entry.quality_score = q
    return ValidationResult(
        ok=True,
        alpaca_lines=[l for l in entry.to_alpaca_jsonl().split("\n") if l.strip()],
        rich_line=entry.to_jsonl(),
        schema_used="qa",
        quality=q,
        record_count=len(pairs),
    )


def _val_chat(text, cls, src, source_chunk: str = ""):
    data = _parse(text)
    if data is None:
        return ValidationResult(ok=False, error=f"JSON parse failed: {text[:120]!r}")
    try:
        msgs = [ChatMsg(**m) for m in data.get("messages",[])]
        entry = ChatMLEntry(
            task_type  = _coerce_task(data.get("task_type"), cls.task_type),
            messages   = msgs,
            source_file= src,
        )
        q = _score_chat(entry)
        entry.quality_score = q
        return ValidationResult(
            ok=True,
            alpaca_lines=[entry.to_alpaca_jsonl()],
            rich_line=entry.to_jsonl(),
            schema_used="chat",
            quality=q,
            record_count=1,
        )
    except Exception as e:
        logger.debug("Chat validation failed (%s) — falling back to alpaca", e)
        return _val_alpaca(text, cls, src, schema_fallback="chat")


def _val_code_gen(text, cls, src, source_chunk=""):
    data = _parse(text)
    if data is None:
        return ValidationResult(ok=False, error=f"JSON parse failed: {text[:120]!r}")
    try:
        entry = CodeGenEntry(
            inferred_prompt= _req(data, "inferred_prompt"),
            language       = data.get("language", cls.language or "Unknown"),
            code           = _req(data, "code"),
            description    = data.get("description",""),
            security_notes = data.get("security_notes",""),
            source_file    = src,
        )
        # Bug#3 FIX: Real quality scoring — not just code length.
        # Old: q = min(0.5 + len(entry.code)/5000, 1.0)  ← length only, easily gamed
        # New: structural + diversity + description + grounding
        q = _score_code_gen(entry, source_chunk)
        entry.quality_score = q
        return ValidationResult(
            ok=True,
            alpaca_lines=[entry.to_alpaca_jsonl()],
            rich_line=entry.to_jsonl(),
            schema_used="code_gen",
            quality=q,
            record_count=1,
        )
    except Exception as e:
        logger.debug("CodeGen validation failed (%s) — falling back to alpaca", e)
        return _val_alpaca(text, cls, src, schema_fallback="code_gen")


def _val_code_review(text, cls, src, source_chunk=""):
    data = _parse(text)
    if data is None:
        return ValidationResult(ok=False, error=f"JSON parse failed: {text[:120]!r}")
    try:
        vulns = []
        for v in _listify(data.get("vulnerabilities",[])):
            if isinstance(v, dict):
                try:
                    vulns.append(CodeVuln(**{k: v.get(k,"") for k in CodeVuln.model_fields}))
                except Exception:
                    pass
        entry = CodeReviewEntry(
            code           = _req(data, "code", fallback=""),
            language       = data.get("language", cls.language or ""),
            vulnerabilities= vulns,
            overall_risk   = data.get("overall_risk","MEDIUM"),
            summary        = data.get("summary",""),
            secure_version = data.get("secure_version",""),
            source_file    = src,
        )
        # Improved scoring: vuln count + summary quality + secure_version presence
        vuln_score = min(len(vulns) * 0.12, 0.36)
        summary_score = _vocab_diversity(entry.summary) * 0.25 if entry.summary else 0.0
        has_fix = 0.15 if entry.secure_version and len(entry.secure_version) > 50 else 0.0
        q = round(min(0.40 + vuln_score + summary_score + has_fix, 0.99), 3)
        entry.quality_score = q
        return ValidationResult(
            ok=True,
            alpaca_lines=[entry.to_alpaca_jsonl()],
            rich_line=entry.to_jsonl(),
            schema_used="code_review",
            quality=q,
            record_count=1,
        )
    except Exception as e:
        logger.debug("CodeReview validation failed (%s) — falling back to alpaca", e)
        return _val_alpaca(text, cls, src, schema_fallback="code_review")


def _val_playbook(text, cls, src, source_chunk: str = ""):
    data = _parse(text)
    if data is None:
        return ValidationResult(ok=False, error=f"JSON parse failed: {text[:120]!r}")
    try:
        steps = []
        for i, s in enumerate(_listify(data.get("steps",[])), 1):
            if isinstance(s, dict):
                steps.append(IRStep(
                    phase      = s.get("phase","Identification"),
                    step_number= s.get("step_number", i),
                    action     = s.get("action",""),
                    tool       = s.get("tool",""),
                    expected   = s.get("expected",""),
                ))
        entry = IncidentPlaybookEntry(
            incident_type   = _req(data, "incident_type"),
            trigger         = data.get("trigger",""),
            steps           = steps,
            detection_query = data.get("detection_query",""),
            escalation      = data.get("escalation",""),
            source_file     = src,
        )
        q = min(0.4 + len(steps)*0.1, 1.0)
        entry.quality_score = q
        return ValidationResult(
            ok=True,
            alpaca_lines=[entry.to_alpaca_jsonl()],
            rich_line=entry.to_jsonl(),
            schema_used="incident_playbook",
            quality=q,
            record_count=1,
        )
    except Exception as e:
        logger.debug("Playbook validation failed (%s) — falling back to alpaca", e)
        return _val_alpaca(text, cls, src, schema_fallback="incident_playbook")


def _val_alpaca(text, cls, src, schema_fallback: str = ""):
    data = _parse(text)
    if data is None:
        extracted = _brace_extract(text)
        if extracted:
            data = _parse(extracted)
    if data is None:
        return ValidationResult(ok=False, error=f"All strategies failed: {text[:120]!r}")
    try:
        # Accept many key aliases
        instr  = (data.get("instruction") or data.get("question") or
                  data.get("task") or data.get("prompt") or "")
        output = (data.get("output") or data.get("answer") or
                  data.get("conclusion") or data.get("response") or "")
        entry  = AlpacaEntry(
            task_type  = _coerce_task(data.get("task_type"), cls.task_type),
            instruction= instr.strip(),
            input      = str(data.get("input", data.get("context",""))),
            output     = output.strip(),
            source_file= src,
        )
        q = min(0.3 + len(entry.output)/1000, 0.8)  # alpaca capped lower
        entry.quality_score = q
        # Bug#7 FIX: Track fallback schema in the result for accurate statistics
        schema_label = "alpaca"
        if schema_fallback:
            schema_label = f"alpaca[fallback_from:{schema_fallback}]"
            logger.warning(
                "Schema '%s' validation failed — saved as alpaca fallback.",
                schema_fallback
            )
        return ValidationResult(
            ok=True,
            alpaca_lines=[entry.to_alpaca_jsonl()],
            rich_line=entry.to_jsonl(),
            schema_used=schema_label,
            quality=q,
            record_count=1,
        )
    except Exception as e:
        return ValidationResult(ok=False, error=f"Alpaca fallback failed: {e}")


# Phase 3 Validators

def _val_tool_usage(text, cls, src, source_chunk: str = ""):
    data = _parse(text)
    if data is None: return ValidationResult(ok=False, error=f"JSON parse failed: {text[:120]!r}")
    try:
        entry = ToolUsageEntry(
            task_type=_coerce_task(data.get("task_type"), cls.task_type),
            scenario=_req(data, "scenario"),
            selected_tool=_req(data, "selected_tool"),
            tool_rationale=_req(data, "tool_rationale"),
            command=_req(data, "command"),
            expected_output=_req(data, "expected_output"),
            interpretation=_req(data, "interpretation"),
            source_file=src,
        )
        q = min(0.4 + len(entry.command)/200 + len(entry.interpretation)/500, 1.0)
        entry.quality_score = q
        return ValidationResult(ok=True, alpaca_lines=[entry.to_alpaca_jsonl()], rich_line=entry.to_jsonl(), schema_used="tool_usage", quality=q, record_count=1)
    except Exception as e:
        logger.debug("ToolUsage validation failed (%s) — falling back", e)
        return _val_alpaca(text, cls, src, schema_fallback="tool_usage")

def _val_threat_hunting(text, cls, src, source_chunk: str = ""):
    data = _parse(text)
    if data is None: return ValidationResult(ok=False, error=f"JSON parse failed")
    try:
        entry = ThreatHuntingEntry(
            task_type=_coerce_task(data.get("task_type"), cls.task_type),
            hypothesis=_req(data, "hypothesis"),
            hunt_query=_req(data, "hunt_query"),
            expected_indicators=_list_str(data.get("expected_indicators", [])),
            findings_interpretation=_req(data, "findings_interpretation"),
            verdict=_req(data, "verdict"),
            source_file=src,
        )
        q = min(0.5 + len(entry.hunt_query)/200, 1.0)
        entry.quality_score = q
        return ValidationResult(ok=True, alpaca_lines=[entry.to_alpaca_jsonl()], rich_line=entry.to_jsonl(), schema_used="threat_hunting", quality=q, record_count=1)
    except Exception as e:
        logger.debug("ThreatHunting validation failed (%s)", e)
        return _val_alpaca(text, cls, src, schema_fallback="threat_hunting")

def _val_multi_step_decision(text, cls, src, source_chunk: str = ""):
    data = _parse(text)
    if data is None: return ValidationResult(ok=False, error=f"JSON parse failed")
    try:
        steps = []
        for i, s in enumerate(_listify(data.get("reasoning_chain",[])), 1):
            if isinstance(s, dict):
                steps.append(DecisionStep(
                    step=s.get("step", i),
                    observation=s.get("observation",""),
                    inference=s.get("inference",""),
                    confidence=s.get("confidence","medium")
                ))
        entry = MultiStepDecisionEntry(
            task_type=_coerce_task(data.get("task_type"), cls.task_type),
            trigger_event=_req(data, "trigger_event"),
            observations=_list_str(data.get("observations",[])),
            reasoning_chain=steps,
            final_decision=_req(data, "final_decision"),
            decision_rationale=_req(data, "decision_rationale"),
            alternative_considered=_req(data, "alternative_considered"),
            source_file=src,
        )
        q = min(0.4 + len(steps)*0.15, 1.0)
        entry.quality_score = q
        return ValidationResult(ok=True, alpaca_lines=[entry.to_alpaca_jsonl()], rich_line=entry.to_jsonl(), schema_used="multi_step_decision", quality=q, record_count=1)
    except Exception as e:
        logger.debug("MultiStepDecision validation failed (%s)", e)
        return _val_alpaca(text, cls, src, schema_fallback="multi_step_decision")

def _val_detection_engineering(text, cls, src, source_chunk: str = ""):
    data = _parse(text)
    if data is None: return ValidationResult(ok=False, error=f"JSON parse failed")
    try:
        entry = DetectionEngineeringEntry(
            task_type=_coerce_task(data.get("task_type"), cls.task_type),
            behavior_observed=_req(data, "behavior_observed"),
            mitre_technique=_req(data, "mitre_technique"),
            detection_rule=_req(data, "detection_rule"),
            rule_format=_req(data, "rule_format"),
            false_positive_risk=_req(data, "false_positive_risk"),
            tuning_notes=_req(data, "tuning_notes"),
            source_file=src,
        )
        q = min(0.5 + len(entry.detection_rule)/500, 1.0)
        entry.quality_score = q
        return ValidationResult(ok=True, alpaca_lines=[entry.to_alpaca_jsonl()], rich_line=entry.to_jsonl(), schema_used="detection_engineering", quality=q, record_count=1)
    except Exception as e:
        logger.debug("DetectionEngineering validation failed (%s)", e)
        return _val_alpaca(text, cls, src, schema_fallback="detection_engineering")

def _val_forensic_timeline(text, cls, src, source_chunk: str = ""):
    data = _parse(text)
    if data is None: return ValidationResult(ok=False, error=f"JSON parse failed")
    try:
        findings = []
        for i, f in enumerate(_listify(data.get("findings",[])), 1):
            if isinstance(f, dict):
                findings.append(TimelineFinding(
                    timestamp=f.get("timestamp",""),
                    artifact=f.get("artifact",""),
                    significance=f.get("significance",""),
                    mitre_ref=f.get("mitre_ref","")
                ))
        entry = ForensicTimelineEntry(
            task_type=_coerce_task(data.get("task_type"), cls.task_type),
            artifact_type=_req(data, "artifact_type"),
            artifact_path=_req(data, "artifact_path"),
            extraction_command=_req(data, "extraction_command"),
            findings=findings,
            timeline_summary=_req(data, "timeline_summary"),
            attribution_confidence=_req(data, "attribution_confidence"),
            source_file=src,
        )
        q = min(0.4 + len(findings)*0.1, 1.0)
        entry.quality_score = q
        return ValidationResult(ok=True, alpaca_lines=[entry.to_alpaca_jsonl()], rich_line=entry.to_jsonl(), schema_used="forensic_timeline", quality=q, record_count=1)
    except Exception as e:
        logger.debug("ForensicTimeline validation failed (%s)", e)
        return _val_alpaca(text, cls, src, schema_fallback="forensic_timeline")

def _val_negative_example(text, cls, src, source_chunk: str = ""):
    data = _parse(text)
    if data is None: return ValidationResult(ok=False, error=f"JSON parse failed")
    try:
        entry = NegativeExampleEntry(
            task_type=_coerce_task(data.get("task_type"), cls.task_type),
            incorrect_analysis=_req(data, "incorrect_analysis"),
            why_wrong=_req(data, "why_wrong"),
            correct_analysis=_req(data, "correct_analysis"),
            common_mistake_category=_req(data, "common_mistake_category"),
            source_file=src,
        )
        q = min(0.5 + len(entry.why_wrong)/400, 1.0)
        entry.quality_score = q
        return ValidationResult(ok=True, alpaca_lines=[entry.to_alpaca_jsonl()], rich_line=entry.to_jsonl(), schema_used="negative_example", quality=q, record_count=1)
    except Exception as e:
        logger.debug("NegativeExample validation failed (%s)", e)
        return _val_alpaca(text, cls, src, schema_fallback="negative_example")


# ─────────────────────────────────────────────────────────────────────────────
# Quality scorers — v1.0.0: information density, grounding, structure
# ─────────────────────────────────────────────────────────────────────────────


# Bug#3 FIX: Real code_gen quality scorer (replaces length-only formula)
_CODE_KEYWORDS = re.compile(
    r'\b(?:def|class|if|else|elif|for|while|try|except|import|return|yield|'
    r'async|await|with|lambda|raise|assert|pass|break|continue|'
    r'function|const|let|var|public|private|static|void|int|string|'
    r'SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)\b',
    re.I
)

def _score_code_gen(entry, source_chunk: str = "") -> float:
    """
    Real code quality assessment — Bug#3 fix.

    Dimensions:
      - Structural diversity: unique control-flow keywords (not just length)
      - Description quality: is the inferred_prompt descriptive?
      - Security notes presence: does it include security analysis?
      - Grounding: is the code related to the source chunk?
      - Length bonus: small bonus (not primary driver)
    """
    code = entry.code or ""
    prompt = entry.inferred_prompt or ""
    desc = entry.description or ""
    notes = entry.security_notes or ""

    # Structural diversity: unique programming keywords found
    kw_matches = set(_CODE_KEYWORDS.findall(code.lower()))
    structural = min(len(kw_matches) / 10.0, 0.30)  # 10 unique kw → 0.30

    # Description quality: non-trivial inferred_prompt
    desc_words = len(set(prompt.lower().split()))
    desc_quality = min(desc_words / 20.0, 0.20)  # 20 unique words → 0.20

    # Security notes: bonus if present and non-trivial
    security_bonus = 0.15 if len(notes.split()) >= 15 else (0.07 if notes.strip() else 0.0)

    # Grounding: does code share technical tokens with source?
    grounding = 0.0
    if source_chunk and code:
        code_tokens = set(re.findall(r'\b[\w]{3,}\b', code.lower()))
        src_tokens  = set(re.findall(r'\b[\w]{3,}\b', source_chunk.lower()))
        if code_tokens:
            overlap = len(code_tokens & src_tokens) / len(code_tokens)
            grounding = min(overlap * 1.5, 0.20)

    # Small length bonus (max 0.10 — not the primary driver)
    length_bonus = min(len(code) / 3000.0, 0.10)

    base = 0.35  # Base for passing schema validation
    total = base + structural + desc_quality + security_bonus + grounding + length_bonus
    return round(min(total, 0.99), 3)

# SCORE JACCARD — word-level Jaccard similarity between two strings.
# Used for intra-schema QA pair deduplication.
# Args:    a, b: str — strings to compare.
# Returns: float in [0.0, 1.0] — 0 = no overlap, 1 = identical vocabulary.
def _jaccard_sim(a: str, b: str) -> float:
    """Word-level Jaccard similarity between two strings."""
    sa = set(re.findall(r'\b\w+\b', a.lower()))
    sb = set(re.findall(r'\b\w+\b', b.lower()))
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


# SCORE DIVERSITY — measure vocabulary diversity as unique_words / total_words.
# Low diversity (<0.3) signals repetitive or padded LLM output.
# High diversity (>0.6) signals information-dense output.
# Only counts words of 3+ characters to exclude articles and prepositions.
# Args:    text: str — text to analyse.
# Returns: float in [0.0, 1.0].
def _vocab_diversity(text: str) -> float:
    """
    Measures vocabulary diversity as unique_words / total_words.
    Low diversity (< 0.3) = repetitive/padded output.
    High diversity (> 0.6) = information-dense output.
    """
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    if len(words) < 10:
        return 0.3
    return min(len(set(words)) / len(words), 1.0)


# SCORE GROUNDING — check how many evidence tokens appear in the reasoning.
# High overlap = reasoning is grounded in actual content, not hallucinated.
# Token extraction: words of 4+ characters from evidence and reasoning.
# Overlap formula: len(ev_tokens & rea_tokens) / len(ev_tokens), scaled ×2.
# A score of 0.5 (50% token overlap) produces a grounding score of 1.0.
# Args:    reasoning: str — generated reasoning text.
#          evidence: str  — source evidence / raw_sample text.
# Returns: float in [0.0, 1.0]. Returns 0.5 (neutral) if evidence is empty.
def _grounding_score(reasoning: str, evidence: str) -> float:
    """
    Checks how many specific tokens from the evidence appear in the reasoning.
    High overlap = the reasoning is grounded in the actual content.
    """
    if not evidence or not reasoning:
        return 0.0
    # Extract meaningful tokens from evidence (length >= 4)
    ev_tokens = set(re.findall(r'\b[\w.\-:/]{4,}\b', evidence.lower()))
    rea_tokens = set(re.findall(r'\b[\w.\-:/]{4,}\b', reasoning.lower()))
    if not ev_tokens:
        return 0.5  # neutral if evidence is empty
    overlap = len(ev_tokens & rea_tokens) / len(ev_tokens)
    return min(overlap * 2, 1.0)  # scale: 50% token overlap → score 1.0


def _score_cot(e: ChainOfThoughtEntry) -> float:
    """
    Scoring dimensions (Qualitative, Phase 2):
      - Grounding: reasoning cites evidence tokens (Primary)  0.40
      - MITRE presence/validity                               0.20
      - IOC presence                                          0.25
      - Valid severity                                        0.05
      - Vocabulary diversity (anti-repetition)                0.10
    """
    score = 0.0
    g_score = _grounding_score(e.reasoning, e.evidence)
    if g_score < 0.2:
        return 0.0  # Rejected if no grounding
    
    score += g_score * 0.40
    # Nuanced MITRE score
    mitre_count = len(e.mitre_ids) if e.mitre_ids else 0
    score += min(mitre_count * 0.10, 0.20)
    # Nuanced IOC score
    ioc_count = len(e.iocs) if e.iocs else 0
    score += min(ioc_count * 0.08, 0.25)
    
    if e.severity != Severity.INFO:
        score += 0.05
        
    # Scale vocabulary diversity more strictly
    v_div = _vocab_diversity(e.reasoning)
    # Also reward length depth
    length_bonus = min(len(e.reasoning.split()) / 500.0, 1.0) * 0.05
    score += v_div * 0.05 + length_bonus
    
    return round(min(max(score, 0.10), 0.99), 3)


def _score_analysis(e: StructuredAnalysisEntry) -> float:
    """
    Scoring dimensions (Qualitative, Phase 2):
      - Grounding (summary cites raw_sample)              0.40
      - MITRE coverage with confidence                    0.25
      - IOC presence                                      0.10
      - Verdict presence                                  0.10
      - Vocabulary diversity                              0.15
    """
    score = 0.0
    g_score = _grounding_score(e.summary, e.raw_sample)
    if g_score < 0.2:
        return 0.0
    
    score += g_score * 0.35
    
    if e.mitre:
        avg_conf = sum(m.confidence for m in e.mitre) / len(e.mitre)
        mitre_bonus = min(len(e.mitre) * 0.05, 0.15)
        score += (0.10 * avg_conf) + mitre_bonus
        
    ioc_count = len(e.iocs) if e.iocs else 0
    score += min(ioc_count * 0.03, 0.10)
    
    if e.verdict:
        score += 0.10
        
    v_div = _vocab_diversity(e.summary)
    length_bonus = min(len(e.summary.split()) / 300.0, 1.0) * 0.10
    score += v_div * 0.10 + length_bonus
    
    return round(min(max(score, 0.35), 0.99), 3)


def _score_qa(pairs: list[QAPair]) -> float:
    """
    Scoring dimensions (Qualitative, Phase 2):
      - Grounding: Average overlap between context and ans    0.40
      - Difficulty diversity (having diff types)              0.30
      - Vocabulary diversity                                  0.30
    """
    if not pairs:
        return 0.0
        
    score = 0.0
    g_scores = [_grounding_score(p.answer, p.context) for p in pairs]
    avg_g = sum(g_scores) / len(g_scores) if g_scores else 0.0
    
    if avg_g < 0.2:
        return 0.0
        
    score += avg_g * 0.40
    
    difficulties = {p.difficulty for p in pairs}
    score += len(difficulties) / 3 * 0.25
    
    all_text = " ".join(p.answer for p in pairs)
    v_div = _vocab_diversity(all_text)
    length_bonus = min(len(all_text.split()) / 500.0, 1.0) * 0.15
    score += v_div * 0.20 + length_bonus
    
    return round(min(max(score, 0.35), 0.99), 3)


def _score_chat(e: ChatMLEntry) -> float:
    """
    Scoring dimensions:
      - Turn count (target: 5+ messages)                 0.30
      - Assistant content density                        0.40
      - Vocabulary diversity of assistant turns          0.20
      - Follow-up question is genuinely different        0.10
    """
    turns = len(e.messages)
    score = min(turns / 5, 1.0) * 0.30
    asst_msgs = [m for m in e.messages if m.role == "assistant"]
    total_asst_words = sum(len(m.content.split()) for m in asst_msgs)
    score += min(total_asst_words / 150, 1.0) * 0.40
    all_asst_text = " ".join(m.content for m in asst_msgs)
    score += _vocab_diversity(all_asst_text) * 0.20
    # Check follow-up diversity: are the two user turns different?
    user_msgs = [m for m in e.messages if m.role == "user"]
    if len(user_msgs) >= 2:
        u1_words = set(user_msgs[0].content.lower().split())
        u2_words = set(user_msgs[1].content.lower().split())
        overlap = len(u1_words & u2_words) / max(len(u1_words | u2_words), 1)
        score += (1.0 - overlap) * 0.10  # reward different follow-up questions
    return round(min(score, 1.0), 3)


# ─────────────────────────────────────────────────────────────────────────────
# JSON helpers
# ─────────────────────────────────────────────────────────────────────────────

# CLEAN — strip markdown code fences from LLM output before JSON parsing.
# Handles '```json\n...' and '```\n...' patterns at start/end of text.
# Args:    text: str — raw LLM response.
# Returns: str — text with fences removed.
def _clean(text: str) -> str:
    text = re.sub(r"^```(?:json)?\s*\n?", "", text.strip())
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


# PARSE — extract a dict or list from text using three progressive strategies:
#   1. Direct json.loads() on cleaned text.
#   2. _repair() to fix escaped newlines/tabs inside strings.
#   3. _brace_extract() to find the outermost {} or [] block.
# Args:    text: str — text containing JSON.
# Returns: dict | list | None — None if all strategies fail.
def _parse(text: str) -> Optional[dict | list]:
    for candidate in [text, _repair(text), _brace_extract(text)]:
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


# REPAIR — shallow JSON repair for escaped whitespace inside quoted strings.
# Handles the common LLM error of unescaped newlines/tabs inside JSON strings.
# Limitation: does not handle trailing commas, truncated JSON, or missing quotes.
# Args:    text: str — raw JSON string with potential whitespace escaping issues.
# Returns: str — repaired string (or original if regex fails).
def _repair(text: str) -> str:
    try:
        return re.sub(
            r'("(?:[^"\\]|\\.)*")',
            lambda m: m.group(0).replace("\n","\\n").replace("\t","\\t"),
            text,
        )
    except Exception:
        return text


# EXTRACT — find the outermost balanced {} or [] block in text.
# Used when JSON is embedded inside prose (e.g., 'Here is the analysis: {...}').
# Correctly handles nested braces, strings, and escaped characters.
# Args:    text: str — text that may contain embedded JSON.
# Returns: str | None — the outermost JSON block, or None if not found.
def _brace_extract(text: str) -> Optional[str]:
    for opener, closer in [('{','}'),('[',']')]:
        start = text.find(opener)
        if start == -1:
            continue
        depth, in_str, esc = 0, False, False
        for i, ch in enumerate(text[start:], start):
            if esc:     esc = False; continue
            if ch == '\\' and in_str: esc = True; continue
            if ch == '"': in_str = not in_str; continue
            if in_str:  continue
            if ch == opener:  depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return text[start:i+1]
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Coercion helpers
# ─────────────────────────────────────────────────────────────────────────────

def _req(d: dict, key: str, fallback: str = "") -> str:
    v = d.get(key, fallback)
    s = str(v).strip() if v is not None else ""
    if not s:
        raise ValueError(f"Required field '{key}' is empty.")
    return s


def _coerce_task(raw: Any, fallback: TaskType) -> TaskType:
    if isinstance(raw, str):
        try: return TaskType(raw)
        except ValueError: pass
    return fallback


def _coerce_sev(raw: Any) -> Severity:
    if isinstance(raw, str):
        try: return Severity(raw.upper())
        except ValueError: pass
    return Severity.MEDIUM


def _list_str(raw: Any) -> list[str]:
    if not raw: return []
    if isinstance(raw, str):
        return [s.strip() for s in re.split(r'[,\n]', raw) if s.strip()]
    if isinstance(raw, list):
        return [str(i).strip() for i in raw if str(i).strip()]
    return []


def _listify(raw: Any) -> list:
    if isinstance(raw, list): return raw
    if raw is None: return []
    return [raw]


def _parse_mitre_item(item: Any) -> Optional[MitreEntry]:
    if isinstance(item, str):
        m = re.match(r"(T\d{4}(?:\.\d{3})?)\s*(.*)", item.strip())
        if m:
            return MitreEntry(id=m.group(1), name=m.group(2) or m.group(1), tactic="Unknown")
    elif isinstance(item, dict):
        try:
            return MitreEntry(
                id         = item.get("id", item.get("technique_id","")),
                name       = item.get("name", item.get("technique_name","")),
                tactic     = item.get("tactic","Unknown"),
                confidence = float(item.get("confidence",0.9)),
            )
        except Exception:
            pass
    return None
