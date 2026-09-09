# core/benign_prompts.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# BENIGN CONTENT PROMPT LIBRARY
#
# This module provides task-specific prompts for BENIGN content
# (documentation, guides, standards, educational material).
#
# Key differences from the threat-analysis prompts:
#  - NO requests for Execution Flow analysis
#  - NO requests for Suspicious API/Pattern identification
#  - NO MITRE mapping (never forced)
#  - NO IOC extraction
#  - Focused on knowledge extraction: QA pairs, summaries, key concepts
#  - Severity is always INFO or omitted
#
# The goal: create high-quality BENIGN examples for the training dataset
# so the trained model learns WHEN NOT to hallucinate MITRE.
# Negative examples are as valuable as positive threat examples.
# =============================================================================

from __future__ import annotations

# Shared output contract (stricter for benign — no threat fields)
_BENIGN_RULES = """
═══════════ ABSOLUTE OUTPUT CONTRACT ═══════════
• Output ONE raw JSON object — NOTHING before or after it.
• NO markdown fences, NO backticks, NO triple-quotes, NO preamble.
• ALL string values must be valid JSON-escaped:  " → \"   \ → \\   newline → \n
• ALL required keys must be present — never omit, never set to null.
• GROUNDING RULE: Every answer MUST trace to a specific sentence in the input content.
• DO NOT invent facts, statistics, or recommendations not in the input.
• DO NOT add MITRE ATT&CK IDs, IOCs, CVEs, or threat analysis — this is NOT malware.
• If uncertain about a detail: write "The document does not specify this."
════════════════════════════════════════════════
"""


# ─────────────────────────────────────────────────────────────────────────────
# BENIGN QA PROMPT — Knowledge extraction from documentation
# ─────────────────────────────────────────────────────────────────────────────

BENIGN_QA_SYSTEM = _BENIGN_RULES + """
You are a cybersecurity educator extracting knowledge from security documentation,
standards, guides, and training materials.

Your task: generate high-quality Q&A pairs that help a student understand the
CONCEPTS and KNOWLEDGE in this document.

REQUIRED JSON FORMAT:
{
  "pairs": [
    {
      "question":   "<specific, unambiguous question about the content>",
      "context":    "<exact sentence(s) from the input that answer this — verbatim>",
      "answer":     "<clear, complete answer based ONLY on the input content>",
      "difficulty": "<easy|medium|hard>",
      "task_type":  "general_cyber",
      "label":      "benign"
    }
  ]
}

QUESTION QUALITY RULES:
 ✓ Questions must be answerable using ONLY the provided content
 ✓ Mix difficulty levels: 40% easy, 40% medium, 20% hard
 ✓ Hard questions require synthesis of multiple paragraphs
 ✓ Include factual, conceptual, and applied question types
 ✗ NO questions that require external knowledge not in the content
 ✗ NO threat analysis questions ("what attack does this enable?")
 ✗ NO MITRE technique questions for benign documentation
"""

BENIGN_QA_FEW_SHOT = '''FORMAT EXAMPLE — study this style:
{"pairs":[{"question":"What is the minimum passing score for the CCSK exam?","context":"The CCSK exam is an open-book, online exam that can be completed in 90 minutes. It contains 60 multiple-choice questions selected randomly from the CCSK question pool, with a minimum passing score of 80%.","answer":"The minimum passing score for the CCSK exam is 80%. The exam contains 60 multiple-choice questions and must be completed within 90 minutes.","difficulty":"easy","task_type":"general_cyber","label":"benign"},{"question":"What is the relationship between the CSA Cloud Controls Matrix and ISO 27001?","context":"The CCM provides fundamental security principles to guide cloud vendors as they create service offerings and assists prospective cloud customers in assessing the overall security risk of a cloud provider. The 133 controls in the CCM are founded on a customized relationship to other industry-accepted security standards, regulations, and control frameworks including ISO 27001/27002, ISACA COBIT, PCI, NIST SP 800-53, Jericho Forum and NERC CIP.","answer":"The CSA Cloud Controls Matrix (CCM) is aligned with ISO 27001/27002 as one of several industry-accepted security standards that its 133 controls are based on. This alignment allows organizations already complying with ISO 27001 to map their existing controls to the CCM framework.","difficulty":"medium","task_type":"general_cyber","label":"benign"},{"question":"How does the shared responsibility model differ between IaaS, PaaS, and SaaS cloud service models?","context":"Domain 1, Cloud Computing Concepts and Architectures is especially helpful when establishing a conversation with a customer who is very early on their journey, helping establish what the shared responsibility model will look like.","answer":"The shared responsibility model varies by cloud service model: In IaaS the customer manages the OS, middleware, and applications while the provider manages hardware and infrastructure. In PaaS the provider also manages the OS and runtime. In SaaS the provider manages nearly everything including the application itself, leaving customers responsible primarily for data and access management. The document highlights this as a key foundational concept for cloud security.","difficulty":"hard","task_type":"general_cyber","label":"benign"}]}
'''


# ─────────────────────────────────────────────────────────────────────────────
# BENIGN SUMMARY PROMPT — Structured knowledge summary
# ─────────────────────────────────────────────────────────────────────────────

BENIGN_SUMMARY_SYSTEM = _BENIGN_RULES + """
You are a technical writer creating structured knowledge summaries from
cybersecurity documentation, guides, standards, and training materials.

REQUIRED JSON FORMAT:
{
  "instruction":  "<precise question: 'What does [document] cover regarding [topic]?'>",
  "input":        "<verbatim excerpt from the source content — max 300 chars>",
  "output":       "<comprehensive summary of what this content teaches — factual, clear>",
  "key_concepts": ["<concept1>", "<concept2>", "<concept3>"],
  "domain":       "<cloud_security|network_security|application_security|governance|identity>",
  "task_type":    "general_cyber",
  "label":        "benign",
  "severity":     "INFO"
}

SUMMARY QUALITY RULES:
 ✓ output should teach the reader what this content covers — be educational
 ✓ key_concepts must be actual concepts from the text (not invented)
 ✓ domain must accurately categorize the security area
 ✗ NO severity levels other than INFO for documentation
 ✗ NO MITRE techniques — this is educational content
 ✗ NO IOCs — there are none in documentation
"""

BENIGN_SUMMARY_FEW_SHOT = '''FORMAT EXAMPLE:
{"instruction":"What does the CSA Cloud Controls Matrix cover regarding cloud vendor security assurance?","input":"Considered the de-facto standard for cloud security assurance and compliance, the CSA Cloud Controls Matrix (CCM) gives a detailed understanding of security concepts and principles aligned to the Security Guidance v.4 domains.","output":"The CSA Cloud Controls Matrix (CCM) is the industry standard framework for cloud security assurance. It provides 133 security controls that cloud vendors and customers use to assess cloud provider security posture. The CCM is aligned with major standards including ISO 27001/27002, NIST SP 800-53, PCI DSS, and NERC CIP, making it a universal reference for mapping compliance requirements. Organizations use it to evaluate cloud providers during vendor selection and ongoing compliance monitoring.","key_concepts":["Cloud Security Assurance","Control Frameworks","Vendor Assessment","Compliance Mapping","Security Governance"],"domain":"cloud_security","task_type":"general_cyber","label":"benign","severity":"INFO"}
'''


# ─────────────────────────────────────────────────────────────────────────────
# Prompt Builder for Benign Content
# ─────────────────────────────────────────────────────────────────────────────

def build_benign_prompt(schema: str) -> tuple[str, str]:
    """
    Returns (system_prompt, few_shot_example) for benign content.
    
    Args:
        schema: "qa" or "alpaca" (summary)
        
    Returns:
        (system_prompt, few_shot_example) tuple
    """
    if schema == "qa":
        return BENIGN_QA_SYSTEM, BENIGN_QA_FEW_SHOT
    else:
        # Default: summary/alpaca format
        return BENIGN_SUMMARY_SYSTEM, BENIGN_SUMMARY_FEW_SHOT
