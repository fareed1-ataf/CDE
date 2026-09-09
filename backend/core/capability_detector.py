from dataclasses import dataclass
from backend.core.content_analyzer import ContentDimensions
from shared_lib.threat_scorer import ThreatScore, ThreatLevel

@dataclass
class ContentCapabilities:
    """What kind of training tasks can this file actually support?"""
    supports_code_review:     bool = False  # Is there enough code to review?
    supports_tool_generation: bool = False  # Can we extract tool specs?
    supports_malware_analysis:bool = False  # Is there offensive behavior?
    supports_incident_playbook:bool= False  # Is there response/mitigation info?
    supports_cti_qa:          bool = False  # Is there enough technical knowledge?
    supports_cot_reasoning:   bool = False  # Phase 3: Default False to prevent CoT on simple docs
    supports_log_analysis:    bool = False  # Phase 3: Log files, SIEM exports
    supports_code_analysis:   bool = False  # Phase 3: General code (malicious or benign)
    supports_forensics:       bool = False  # Phase 3: Memory dumps, registry, PCAP

class CapabilityDetector:
    """
    Determines capabilities of the content before mapping to training goals.
    This prevents generating a CodeReview schema for a plain text doc.
    """
    def detect(self, content: str, dims: ContentDimensions, threat: ThreatScore) -> ContentCapabilities:
        caps = ContentCapabilities()
        content_lower = content.lower()
        
        # 1. Malware Analysis
        if threat.level in {ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS}:
            caps.supports_malware_analysis = True
            caps.supports_code_analysis = True
            
        # 2. Code Review & Tool Generation
        if dims.code_volume >= 0.3:
            caps.supports_code_review = True
            caps.supports_code_analysis = True
            if threat.is_benign:
                caps.supports_tool_generation = True
                
        # 3. Incident Playbook & Forensics
        ir_keywords = {"mitigation", "remediation", "playbook", "incident", "response", "detect"}
        forensic_keywords = {"memory", "dump", "pcap", "registry", "hive", "artifact", "timeline"}
        log_keywords = {"event", "log", "sysmon", "splunk", "siem", "alert", "query"}
        
        words = set(content_lower.split())
        if len(words & ir_keywords) >= 2 or (threat.is_benign and dims.structural_complexity > 0.4):
            caps.supports_incident_playbook = True
            
        if len(words & forensic_keywords) >= 2:
            caps.supports_forensics = True
            
        if len(words & log_keywords) >= 2:
            caps.supports_log_analysis = True
            
        # 4. Threat Intel / QA
        if dims.semantic_density >= 0.2:
            caps.supports_cti_qa = True
            
        # 5. Chain of Thought Support (Phase 3 fix)
        # Only support CoT if it's not a very simple document
        if dims.structural_complexity > 0.2 or dims.semantic_density > 0.3 or caps.supports_malware_analysis or caps.supports_incident_playbook:
            caps.supports_cot_reasoning = True
            
        return caps
