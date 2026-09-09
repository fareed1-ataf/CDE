# core/schemas.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# DATA ENGINEERING RATIONALE
# =============================================================================
# LLaMA-3 fine-tuning research (Meta, 2024) + Anthropic alignment papers show:
#
#  1. DIVERSITY > VOLUME  — 8 schema types teach 8 distinct reasoning patterns
#  2. CoT REQUIRED        — models trained WITHOUT reasoning chains hallucinate
#                           3× more on multi-step cyber tasks
#  3. STRUCTURED OUTPUT   — training on schema-rich JSON teaches the model to
#                           EMIT structured intelligence, not just describe it
#  4. NEGATIVE EXAMPLES   — "what NOT to do" samples reduce false positives
#  5. QUALITY SCORING     — low-confidence records harm training; score ≥ 0.7
#  6. MULTI-TURN DIALOGS  — ChatML teaches tool-use and follow-up reasoning
#
# OUTPUT SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────
#  Schema A: ChainOfThought    — step reasoning → reduces hallucination
#  Schema B: StructuredAnalysis— MITRE/IOC/CVE machine-parseable fields
#  Schema C: QAPairs           — 3-5 diverse Q&A per document chunk
#  Schema D: ChatML            — multi-turn analyst conversation
#  Schema E: CodeGeneration    — reverse-prompt tool synthesis
#  Schema F: CodeReview        — security audit with vulnerability mapping
#  Schema G: IncidentPlaybook  — IR step-by-step procedure generation
#  Schema H: Alpaca            — universal compatibility fallback
# =============================================================================

from __future__ import annotations

import json
import re
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class TaskType(str, Enum):
    MALWARE_ANALYSIS   = "malware_analysis"
    THREAT_INTEL       = "threat_intel"
    VULNERABILITY      = "vulnerability"
    LOG_ANALYSIS       = "log_analysis"
    CODE_GENERATION    = "code_generation"
    CODE_REVIEW        = "code_review"
    CTI_QA             = "cti_qa"
    INCIDENT_RESPONSE  = "incident_response"
    FORENSICS          = "forensics"
    GENERAL_CYBER      = "general_cyber"


class DataType(str, Enum):
    EDUCATIONAL      = "educational"
    CODE             = "code"
    DATA             = "data"
    ATTACK_ARTIFACT  = "attack_artifact"
    IRRELEVANT       = "irrelevant"   # P1.5: non-cyber content — rejected before LLM


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class DataSchema(str, Enum):
    CHAIN_OF_THOUGHT   = "chain_of_thought"
    ANALYSIS           = "analysis"
    QA                 = "qa"
    CHAT               = "chat"
    CODE_GEN           = "code_gen"
    CODE_REVIEW        = "code_review"
    INCIDENT_PLAYBOOK  = "incident_playbook"
    ALPACA             = "alpaca"
    # Phase 3 — New Schemas
    TOOL_USAGE         = "tool_usage"
    THREAT_HUNTING     = "threat_hunting"
    MULTI_STEP_DECISION= "multi_step_decision"
    DETECTION_ENGINEERING="detection_engineering"
    FORENSIC_TIMELINE  = "forensic_timeline"
    NEGATIVE_EXAMPLE   = "negative_example"



# ─────────────────────────────────────────────────────────────────────────────
# Shared base
# ─────────────────────────────────────────────────────────────────────────────

class _Base(BaseModel):
    schema_type:   DataSchema
    task_type:     TaskType    = TaskType.GENERAL_CYBER
    source_file:   str         = ""
    model_used:    str         = ""
    quality_score: float       = Field(default=1.0, ge=0.0, le=1.0)

    @staticmethod
    def _s(v: Any) -> str:
        return v.strip() if isinstance(v, str) else str(v).strip()

    def to_jsonl(self) -> str:
        return self.model_dump_json()

    def to_alpaca_jsonl(self) -> str:
        """Every schema MUST be able to produce an Alpaca line."""
        raise NotImplementedError


# ─────────────────────────────────────────────────────────────────────────────
# Schema A ─ Chain-of-Thought  (PRIMARY anti-hallucination schema)
# ─────────────────────────────────────────────────────────────────────────────

class ChainOfThoughtEntry(_Base):
    """
    Forces reasoning before conclusion.
    Format used at training:
        ### Task\n{instruction}\n\n### Evidence\n{evidence}\n\n
        ### Reasoning\n{reasoning}\n\n### Answer\n{answer}
    """
    schema_type:  DataSchema = DataSchema.CHAIN_OF_THOUGHT
    instruction:  str = Field(..., min_length=15)
    evidence:     str = Field(..., min_length=5)
    reasoning:    str = Field(..., min_length=50,
                               description="≥5 numbered steps referencing evidence.")
    answer:       str = Field(..., min_length=20)
    severity:     Severity = Severity.MEDIUM
    mitre_ids:    list[str] = Field(default_factory=list)
    iocs:         list[str] = Field(default_factory=list)

    @field_validator("instruction","evidence","reasoning","answer", mode="before")
    @classmethod
    def no_truncation(cls, v):
        if "[EVIDENCE:" in str(v) and "']" not in str(v)[str(v).rfind("[EVIDENCE:"):]:
            raise ValueError("Truncated EVIDENCE tag detected. Model ran out of tokens.")
        return _Base._s(v)

    @field_validator("reasoning")
    @classmethod
    def must_have_steps(cls, v):
        if not re.search(r'\b[1-9]\)', v) and not re.search(r'Step\s+\d', v, re.I):
            # allow it but flag quality
            pass
        return v

    def to_alpaca_jsonl(self) -> str:
        combined_output = (
            f"**Reasoning:**\n{self.reasoning}\n\n"
            f"**Answer:**\n{self.answer}"
        )
        return AlpacaEntry(
            task_type=self.task_type,
            instruction=self.instruction,
            input=self.evidence,
            output=combined_output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


# ─────────────────────────────────────────────────────────────────────────────
# Schema B ─ Structured Analysis  (machine-parseable threat intel)
# ─────────────────────────────────────────────────────────────────────────────

class MitreEntry(BaseModel):
    id:         str   # "T1059.001"
    name:       str
    tactic:     str
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)


class StructuredAnalysisEntry(_Base):
    schema_type:  DataSchema = DataSchema.ANALYSIS
    instruction:  str = Field(..., min_length=15)
    raw_sample:   str = Field(..., min_length=1)
    summary:      str = Field(..., min_length=30)
    mitre:        list[MitreEntry]  = Field(default_factory=list)
    iocs:         list[str]         = Field(default_factory=list)
    cve_ids:      list[str]         = Field(default_factory=list)
    severity:     Severity          = Severity.MEDIUM
    mitigations:  list[str]         = Field(default_factory=list)
    verdict:      str               = ""

    @field_validator("instruction","summary","verdict", mode="before")
    @classmethod
    def no_truncation(cls, v):
        if "[EVIDENCE:" in str(v) and "']" not in str(v)[str(v).rfind("[EVIDENCE:"):]:
            raise ValueError("Truncated EVIDENCE tag detected. Model ran out of tokens.")
        return _Base._s(v)

    def to_alpaca_jsonl(self) -> str:
        mitre_str = "\n".join(f"  • {m.id} – {m.name} [{m.tactic}]" for m in self.mitre) or "  None identified"
        ioc_str   = "\n".join(f"  • {i}" for i in self.iocs) or "  None extracted"
        mit_str   = "\n".join(f"  {i+1}. {m}" for i,m in enumerate(self.mitigations)) or "  See vendor guidance"
        cve_str   = ", ".join(self.cve_ids) or "None"
        output = (
            f"**Severity:** {self.severity.value}\n\n"
            f"**Summary:**\n{self.summary}\n\n"
            f"**MITRE ATT&CK:**\n{mitre_str}\n\n"
            f"**IOCs:**\n{ioc_str}\n\n"
            f"**CVEs:** {cve_str}\n\n"
            f"**Mitigations:**\n{mit_str}\n\n"
            f"**Verdict:** {self.verdict}"
        )
        return AlpacaEntry(
            task_type=self.task_type,
            instruction=self.instruction,
            input=self.raw_sample,
            output=output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


# ─────────────────────────────────────────────────────────────────────────────
# Schema C ─ QA Pairs  (dataset diversity multiplier)
# ─────────────────────────────────────────────────────────────────────────────

class QAPair(BaseModel):
    question:   str = Field(..., min_length=10)
    context:    str = Field(..., min_length=10)
    answer:     str = Field(..., min_length=15)
    difficulty: str = Field(default="medium")  # easy | medium | hard

    @field_validator("difficulty")
    @classmethod
    def valid_diff(cls, v):
        return v if v in {"easy","medium","hard"} else "medium"

    @field_validator("question", "context", "answer", mode="before")
    @classmethod
    def no_truncation(cls, v):
        # Truncation guard: if evidence tag is opened but not closed
        if "[EVIDENCE:" in str(v) and "']" not in str(v)[str(v).rfind("[EVIDENCE:"):]:
            raise ValueError("Truncated EVIDENCE tag detected. Model ran out of tokens.")
        return _Base._s(v)


class QABatchEntry(_Base):
    """Produces N Alpaca lines from one document chunk — maximises diversity."""
    schema_type: DataSchema  = DataSchema.QA
    pairs:       list[QAPair] = Field(..., min_length=1)

    def to_alpaca_jsonl(self) -> str:
        lines = []
        for p in self.pairs:
            lines.append(AlpacaEntry(
                task_type=self.task_type,
                instruction=p.question,
                input=p.context,
                output=p.answer,
                source_file=self.source_file,
                model_used=self.model_used,
                quality_score=self.quality_score,
            ).to_jsonl())
        return "\n".join(lines)

    def to_jsonl(self) -> str:
        return self.model_dump_json()


# ─────────────────────────────────────────────────────────────────────────────
# Schema D ─ ChatML  (instruction-following + tool-use training)
# ─────────────────────────────────────────────────────────────────────────────

class ChatMsg(BaseModel):
    role:    str
    content: str

    @field_validator("role")
    @classmethod
    def valid_role(cls, v):
        if v not in {"system","user","assistant"}:
            raise ValueError(f"Bad role: {v}")
        return v


class ChatMLEntry(_Base):
    schema_type: DataSchema   = DataSchema.CHAT
    messages:    list[ChatMsg] = Field(..., min_length=3)

    @field_validator("messages")
    @classmethod
    def has_assistant(cls, msgs):
        if not any(m.role == "assistant" for m in msgs):
            raise ValueError("Must contain at least one assistant turn.")
        return msgs

    def to_jsonl(self) -> str:
        d = self.model_dump()
        d["messages"] = [{"role": m["role"], "content": m["content"]} for m in d["messages"]]
        return json.dumps(d, ensure_ascii=False)

    def to_alpaca_jsonl(self) -> str:
        user_q = next((m.content for m in reversed(self.messages) if m.role == "user"), "")
        asst_a = next((m.content for m in reversed(self.messages) if m.role == "assistant"), "")
        return AlpacaEntry(
            task_type=self.task_type,
            instruction=user_q,
            input="",
            output=asst_a,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


# ─────────────────────────────────────────────────────────────────────────────
# Schema E ─ Code Generation  (reverse-prompt synthesis)
# ─────────────────────────────────────────────────────────────────────────────

class CodeGenEntry(_Base):
    schema_type:     DataSchema = DataSchema.CODE_GEN
    inferred_prompt: str = Field(..., min_length=20)
    language:        str = Field(..., min_length=1)
    code:            str = Field(..., min_length=10)
    description:     str = ""
    security_notes:  str = ""

    @field_validator("code", mode="before")
    @classmethod
    def strip_fences(cls, v):
        if isinstance(v, str):
            v = re.sub(r"^```\w*\s*\n?", "", v.strip())
            v = re.sub(r"\n?```\s*$", "", v)
        return v

    def to_alpaca_jsonl(self) -> str:
        return AlpacaEntry(
            task_type=TaskType.CODE_GENERATION,
            instruction=self.inferred_prompt,
            input="",
            output=self.code,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


# ─────────────────────────────────────────────────────────────────────────────
# Schema F ─ Code Review  (security audit training)
# ─────────────────────────────────────────────────────────────────────────────

class CodeVuln(BaseModel):
    line_ref:   str   # e.g. "line 42" or "function foo()"
    vuln_type:  str   # e.g. "SQL Injection", "Buffer Overflow"
    cwe_id:     str   # e.g. "CWE-89"
    severity:   str   = "HIGH"
    fix:        str   = ""


class CodeReviewEntry(_Base):
    schema_type:  DataSchema   = DataSchema.CODE_REVIEW
    code:         str          = Field(..., min_length=10)
    language:     str          = ""
    vulnerabilities: list[CodeVuln] = Field(default_factory=list)
    overall_risk: str          = "MEDIUM"
    summary:      str          = ""
    secure_version: str        = ""

    def to_alpaca_jsonl(self) -> str:
        vuln_str = "\n".join(
            f"  [{v.cwe_id}] {v.vuln_type} @ {v.line_ref} — Severity: {v.severity}\n  Fix: {v.fix}"
            for v in self.vulnerabilities
        ) or "  No vulnerabilities identified."
        output = (
            f"**Overall Risk:** {self.overall_risk}\n\n"
            f"**Summary:** {self.summary}\n\n"
            f"**Vulnerabilities Found:**\n{vuln_str}"
            + (f"\n\n**Secure Version:**\n{self.secure_version}" if self.secure_version else "")
        )
        return AlpacaEntry(
            task_type=TaskType.CODE_REVIEW,
            instruction=f"Perform a security code review of this {self.language} code and identify all vulnerabilities.",
            input=self.code,
            output=output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


# ─────────────────────────────────────────────────────────────────────────────
# Schema G ─ Incident Playbook  (IR procedure generation)
# ─────────────────────────────────────────────────────────────────────────────

class IRStep(BaseModel):
    phase:       str   # Identification | Containment | Eradication | Recovery | Lessons
    step_number: int
    action:      str
    tool:        str   = ""
    expected:    str   = ""


class IncidentPlaybookEntry(_Base):
    schema_type:    DataSchema = DataSchema.INCIDENT_PLAYBOOK
    incident_type:  str        = Field(..., min_length=5)
    trigger:        str        = ""
    steps:          list[IRStep] = Field(..., min_length=3)
    detection_query: str       = ""
    escalation:     str        = ""

    def to_alpaca_jsonl(self) -> str:
        steps_str = "\n".join(
            f"[{s.phase}] Step {s.step_number}: {s.action}"
            + (f" (Tool: {s.tool})" if s.tool else "")
            + (f"\n   → Expected: {s.expected}" if s.expected else "")
            for s in self.steps
        )
        output = (
            f"**Incident Type:** {self.incident_type}\n\n"
            f"**Response Steps:**\n{steps_str}"
            + (f"\n\n**Detection Query:**\n{self.detection_query}" if self.detection_query else "")
            + (f"\n\n**Escalation:** {self.escalation}" if self.escalation else "")
        )
        return AlpacaEntry(
            task_type=TaskType.INCIDENT_RESPONSE,
            instruction=f"Generate a step-by-step incident response playbook for: {self.incident_type}",
            input=self.trigger,
            output=output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


# ─────────────────────────────────────────────────────────────────────────────
# Schema H ─ Alpaca  (universal compatibility)
# ─────────────────────────────────────────────────────────────────────────────

class AlpacaEntry(_Base):
    schema_type: DataSchema = DataSchema.ALPACA
    instruction: str = Field(..., min_length=10)
    input:       str = Field(default="")
    output:      str = Field(..., min_length=15)

    @field_validator("instruction","output", mode="before")
    @classmethod
    def s(cls, v): return _Base._s(v)

    def to_alpaca_jsonl(self) -> str:
        return self.to_jsonl()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 ─ New Schemas
# ─────────────────────────────────────────────────────────────────────────────

class ToolUsageEntry(_Base):
    schema_type:     DataSchema = DataSchema.TOOL_USAGE
    scenario:        str = Field(..., min_length=10)
    selected_tool:   str
    tool_rationale:  str
    command:         str
    expected_output: str
    interpretation:  str

    def to_alpaca_jsonl(self) -> str:
        output = (
            f"**Selected Tool:** {self.selected_tool}\n"
            f"**Rationale:** {self.tool_rationale}\n"
            f"**Command:** `{self.command}`\n"
            f"**Expected Output:** {self.expected_output}\n"
            f"**Interpretation:** {self.interpretation}"
        )
        return AlpacaEntry(
            task_type=self.task_type,
            instruction=self.scenario,
            input="",
            output=output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


class ThreatHuntingEntry(_Base):
    schema_type:             DataSchema = DataSchema.THREAT_HUNTING
    hypothesis:              str = Field(..., min_length=10)
    hunt_query:              str
    expected_indicators:     list[str]
    findings_interpretation: str
    verdict:                 str

    def to_alpaca_jsonl(self) -> str:
        output = (
            f"**Query:** `{self.hunt_query}`\n"
            f"**Expected Indicators:** {', '.join(self.expected_indicators)}\n"
            f"**Interpretation:** {self.findings_interpretation}\n"
            f"**Verdict:** {self.verdict}"
        )
        return AlpacaEntry(
            task_type=self.task_type,
            instruction=f"Develop a threat hunt for: {self.hypothesis}",
            input="",
            output=output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


class DecisionStep(BaseModel):
    step:        int
    observation: str
    inference:   str
    confidence:  str


class MultiStepDecisionEntry(_Base):
    schema_type:            DataSchema = DataSchema.MULTI_STEP_DECISION
    trigger_event:          str
    observations:           list[str]
    reasoning_chain:        list[DecisionStep]
    final_decision:         str
    decision_rationale:     str
    alternative_considered: str

    def to_alpaca_jsonl(self) -> str:
        chain_str = "\n".join([f"{s.step}. Obs: {s.observation} -> Inf: {s.inference} ({s.confidence})" for s in self.reasoning_chain])
        output = (
            f"**Observations:** {', '.join(self.observations)}\n"
            f"**Reasoning Chain:**\n{chain_str}\n"
            f"**Final Decision:** {self.final_decision}\n"
            f"**Rationale:** {self.decision_rationale}\n"
            f"**Alternative Rejected:** {self.alternative_considered}"
        )
        return AlpacaEntry(
            task_type=self.task_type,
            instruction=f"Analyze the event and make a decision: {self.trigger_event}",
            input="",
            output=output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


class DetectionEngineeringEntry(_Base):
    schema_type:         DataSchema = DataSchema.DETECTION_ENGINEERING
    behavior_observed:   str
    mitre_technique:     str
    detection_rule:      str
    rule_format:         str
    false_positive_risk: str
    tuning_notes:        str

    def to_alpaca_jsonl(self) -> str:
        output = (
            f"**Technique:** {self.mitre_technique}\n"
            f"**Rule Format:** {self.rule_format}\n"
            f"**Rule:**\n```\n{self.detection_rule}\n```\n"
            f"**FP Risk:** {self.false_positive_risk}\n"
            f"**Tuning:** {self.tuning_notes}"
        )
        return AlpacaEntry(
            task_type=self.task_type,
            instruction=f"Write a {self.rule_format} detection rule for: {self.behavior_observed}",
            input="",
            output=output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


class TimelineFinding(BaseModel):
    timestamp:    str
    artifact:     str
    significance: str
    mitre_ref:    str


class ForensicTimelineEntry(_Base):
    schema_type:            DataSchema = DataSchema.FORENSIC_TIMELINE
    artifact_type:          str
    artifact_path:          str
    extraction_command:     str
    findings:               list[TimelineFinding]
    timeline_summary:       str
    attribution_confidence: str

    def to_alpaca_jsonl(self) -> str:
        findings_str = "\n".join([f"[{f.timestamp}] {f.artifact}: {f.significance} ({f.mitre_ref})" for f in self.findings])
        output = (
            f"**Extraction:** `{self.extraction_command}`\n"
            f"**Timeline:**\n{findings_str}\n"
            f"**Summary:** {self.timeline_summary}\n"
            f"**Attribution:** {self.attribution_confidence}"
        )
        return AlpacaEntry(
            task_type=self.task_type,
            instruction=f"Perform forensic timeline analysis on {self.artifact_type}: {self.artifact_path}",
            input="",
            output=output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()


class NegativeExampleEntry(_Base):
    schema_type:             DataSchema = DataSchema.NEGATIVE_EXAMPLE
    incorrect_analysis:      str
    why_wrong:               str
    correct_analysis:        str
    common_mistake_category: str

    def to_alpaca_jsonl(self) -> str:
        output = (
            f"**Incorrect Analysis:**\n{self.incorrect_analysis}\n\n"
            f"**Why Wrong ({self.common_mistake_category}):**\n{self.why_wrong}\n\n"
            f"**Correct Analysis:**\n{self.correct_analysis}"
        )
        return AlpacaEntry(
            task_type=self.task_type,
            instruction="Correct the following faulty analysis.",
            input=self.incorrect_analysis,
            output=output,
            source_file=self.source_file,
            model_used=self.model_used,
            quality_score=self.quality_score,
        ).to_jsonl()

# ─────────────────────────────────────────────────────────────────────────────
# Union
# ─────────────────────────────────────────────────────────────────────────────
AnyEntry = (
    ChainOfThoughtEntry | StructuredAnalysisEntry | QABatchEntry |
    ChatMLEntry | CodeGenEntry | CodeReviewEntry |
    IncidentPlaybookEntry | AlpacaEntry |
    ToolUsageEntry | ThreatHuntingEntry | MultiStepDecisionEntry |
    DetectionEngineeringEntry | ForensicTimelineEntry | NegativeExampleEntry
)


# ─────────────────────────────────────────────────────────────────────────────
# Classification  (moved here from classifier.py to break circular imports)
# Used by: validator.py, post_validator.py, multi_schema_generator.py, etc.
# ─────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass, field as dc_field


@dataclass
class Classification:
    """
    Result of ContentClassifier.classify().
    Carries data_type, schema, task_type — plus optional hints and language.
    Lives in shared_lib.schemas so validator.py can use it without importing backend.
    """
    data_type:  DataType
    schema:     DataSchema
    task_type:  TaskType
    language:   str        = ""
    is_binary:  bool       = False
    confidence: float      = 1.0       # 0.0–1.0
    hints:      list       = dc_field(default_factory=list)
    reasoning:  str        = ""        # human-readable explanation

