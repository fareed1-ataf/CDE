# core/prompts.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# PROMPT ENGINEERING LIBRARY — INTELLIGENCE GRADE
#
# v1.0.0 Enhancements:
#  1. Dynamic Constraint Block — explicitly tells LLM what is/isn't allowed
#     (MITRE, IOC, CVE) based on classification signals
#  2. Evidence Anchoring — forces model to cite specific tokens from input
#  3. Content Preview (KEY FACTS) — first 400 chars shown as anchor
#  4. All original schema-specific prompts and few-shot examples preserved
# =============================================================================

import os
from pathlib import Path
from typing import Dict, Tuple

from shared_lib.schemas import DataSchema, TaskType
from .classifier import Classification

# ─────────────────────────────────────────────────────────────────────────────
# Dynamic Prompt Loader
# ─────────────────────────────────────────────────────────────────────────────

PROMPTS_DIR = Path(__file__).parent.parent.parent / "prompts"

_RULES = ""
_SYSTEM_MAP: Dict[DataSchema, str] = {}
_FEW_SHOT_MAP: Dict[DataSchema, str] = {}

def _load_prompt(schema: DataSchema, filename: str) -> None:
    """Loads a prompt from the markdown file and populates the maps."""
    filepath = PROMPTS_DIR / filename
    if not filepath.exists():
        _SYSTEM_MAP[schema] = _RULES
        _FEW_SHOT_MAP[schema] = ""
        return

    content = filepath.read_text(encoding="utf-8")

    sys_part = ""
    fs_part = ""

    if "[SYSTEM]" in content:
        parts = content.split("[FEW_SHOT]")
        sys_part = parts[0].replace("[SYSTEM]", "").strip()
        if len(parts) > 1:
            fs_part = parts[1].strip()
    else:
        sys_part = content.strip()

    full_system = f"{_RULES}\n{sys_part}"

    _SYSTEM_MAP[schema] = full_system
    _FEW_SHOT_MAP[schema] = fs_part

def init_prompts() -> None:
    """Initialize all prompts from disk."""
    global _RULES
    rules_path = PROMPTS_DIR / "_rules.md"
    if rules_path.exists():
        _RULES = rules_path.read_text(encoding="utf-8").strip()

    _load_prompt(DataSchema.CHAIN_OF_THOUGHT, "chain_of_thought.md")
    _load_prompt(DataSchema.ANALYSIS, "structured_analysis.md")
    _load_prompt(DataSchema.QA, "qa_pairs.md")
    _load_prompt(DataSchema.CHAT, "chatml.md")
    _load_prompt(DataSchema.CODE_GEN, "code_generation.md")
    _load_prompt(DataSchema.CODE_REVIEW, "code_review.md")
    _load_prompt(DataSchema.INCIDENT_PLAYBOOK, "incident_playbook.md")
    _load_prompt(DataSchema.ALPACA, "alpaca.md")

    # Phase 3
    _load_prompt(DataSchema.TOOL_USAGE, "tool_usage.md")
    _load_prompt(DataSchema.THREAT_HUNTING, "threat_hunting.md")
    _load_prompt(DataSchema.MULTI_STEP_DECISION, "multi_step_decision.md")
    _load_prompt(DataSchema.DETECTION_ENGINEERING, "detection_engineering.md")
    _load_prompt(DataSchema.FORENSIC_TIMELINE, "forensic_timeline.md")
    _load_prompt(DataSchema.NEGATIVE_EXAMPLE, "negative_example.md")

# Initialize prompts immediately upon module import
init_prompts()

# ─────────────────────────────────────────────────────────────────────────────
# Public builder
# ─────────────────────────────────────────────────────────────────────────────

def build_prompt(
    content:        str,
    classification: Classification,
    filename:       str = "",
) -> Tuple[str, str]:
    """
    Return (system_prompt, user_prompt).

    v1.0.0 Enhancements:
      - Dynamic Constraint Block: explicitly tells LLM what is/isn't allowed
        (MITRE, IOC, CVE) based on classification signals — prevents hallucination
      - Evidence Anchoring: forces LLM to cite at least 3 tokens from input
      - Content Preview: first 400 chars shown as KEY FACTS anchor
    """
    schema   = classification.schema
    system   = _SYSTEM_MAP.get(schema, _RULES)
    few_shot = _FEW_SHOT_MAP.get(schema, "")

    # ── Context block ─────────────────────────────────────────────────────────
    ctx_lines = []
    if filename:
        ctx_lines.append(f"SOURCE FILE  : {filename}")
    if classification.language:
        ctx_lines.append(f"LANGUAGE     : {classification.language}")
    ctx_lines.append(f"SCHEMA       : {schema.value}")
    ctx_lines.append(f"VALID TASK TYPES   : {', '.join(t.value for t in TaskType)}")
    ctx_lines.append(f"CONFIDENCE   : {classification.confidence:.0%}")
    ctx_lines.append(f"CLASSIFIER   : {classification.reasoning}")
    if classification.is_binary:
        ctx_lines.append("NOTE         : Binary file — analyze extracted strings only")
    if classification.confidence < 0.65:
        ctx_lines.append(
            "WARNING: LOW CONFIDENCE — apply analysis schema if content type is ambiguous"
        )
    ctx_block = "\n".join(ctx_lines)

    # ── Dynamic Constraint Block (v1.0.0) ──────────────────────────────────────
    # Determines whether MITRE/IOC are appropriate based on classification signals.
    # This is the primary anti-hallucination mechanism at the prompt level.
    has_threat_signals = any(
        kw in classification.reasoning.lower()
        for kw in ["malicious", "attack", "exploit", "suspicious", "malware"]
    )

    if has_threat_signals:
        mitre_rule = (
            "MITRE: ALLOWED — include T-IDs ONLY for explicit attack actions "
            "(API calls, commands, network ops). Max 3 IDs. "
            "Each must cite a specific observable in the content."
        )
        ioc_rule = (
            "IOCs: ALLOWED — extract only IPs/domains/hashes that appear VERBATIM "
            "in the content below. Do NOT invent or extrapolate IOCs."
        )
    else:
        mitre_rule = (
            "MITRE: NOT ALLOWED — do not include any T-IDs. "
            "Content is educational/benign — no attack actions present."
        )
        ioc_rule = (
            "IOCs: NOT ALLOWED — do not include IPs, domains, or hashes. "
            "Content does not contain confirmed attack artifacts."
        )

    constraint_block = (
        "CONSTRAINTS FOR THIS RECORD:\n"
        f"  {mitre_rule}\n"
        f"  {ioc_rule}\n"
        "  CVEs: Only reference CVEs that appear verbatim in the content.\n"
        "  GROUNDING: Cite at least 3 specific tokens/values from the content.\n"
        '  If content is insufficient, output: {"error": "insufficient_input"}'
    )

    # ── Content preview anchor (v1.0.0) ─────────────────────────────────────────
    # Shows the first 400 chars to anchor the LLM before it reads the full chunk.
    key_facts = ""
    if content and len(content) > 200:
        preview = content[:400].strip().replace("\n", " ")
        key_facts = f"KEY FACTS (first 400 chars): {preview} [...]\n"

    # ── Assemble user prompt ─────────────────────────────────────────────────
    sep = chr(9472) * 64  # ─────── separator

    user = (
        f"FORMAT EXAMPLE (study this — produce output of equal depth and specificity):\n"
        f"{few_shot}\n"
        f"{sep}\n"
        f"{ctx_block}\n"
        f"{sep}\n"
        f"{constraint_block}\n"
        f"{sep}\n"
        f"{key_facts}"
        f"CONTENT TO ANALYZE:\n\n{content}\n\n"
        f"{sep}\n"
        "Produce the JSON output now. Match the depth and specificity of the FORMAT EXAMPLE. "
        "IMPORTANT: Select the most appropriate task_type from VALID TASK TYPES. "
        "CRITICAL: Cite specific values from the content — do not generalize."
    )
    return system, user
