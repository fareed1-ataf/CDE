from enum import Enum

class TrainingGoal(str, Enum):
    """
    Defines the ultimate training target for the dataset.
    This replaces the schema-first thinking. Instead of "What schema should we use?",
    the engine asks "What are we training the model to become?".
    """
    MALWARE_ANALYST          = "malware_analyst"
    SECURITY_TOOL_BUILDER    = "security_tool_builder"
    INCIDENT_RESPONDER       = "incident_responder"
    THREAT_INTEL_ANALYST     = "threat_intel_analyst"
    SECURE_CODER             = "secure_coder"
    VULNERABILITY_RESEARCHER = "vulnerability_researcher"
    GENERAL_CYBER_ASSISTANT  = "general_cyber_assistant"
    # Phase 3 — New Goals
    THREAT_HUNTER            = "threat_hunter"            # Hypothesis-based hunting via SIEM/EDR
    SOC_ANALYST              = "soc_analyst"              # Log analysis + alert triage
    DETECTION_ENGINEER       = "detection_engineer"       # YARA + Sigma + KQL + SPL rules
    DIGITAL_FORENSICS        = "digital_forensics"        # Artifact → Timeline → Attribution
    MALWARE_REVERSE_ENGINEER = "malware_reverse_engineer" # Static + Dynamic deep analysis
