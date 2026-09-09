from dataclasses import dataclass
from backend.core.capability_detector import ContentCapabilities
from backend.core.training_goal import TrainingGoal
from shared_lib.schemas import DataSchema

@dataclass(frozen=True)
class Skill:
    name: str
    weight: float
    schema: DataSchema

class SkillExtractionLayer:
    """
    Translates Content Capabilities + Training Goal into specific Skills
    to be extracted.
    """
    
    SKILL_MAP = {
        ("supports_malware_analysis", TrainingGoal.MALWARE_ANALYST): [
            Skill("behavioral_analysis", 0.4, DataSchema.CHAIN_OF_THOUGHT),
            Skill("ioc_extraction", 0.25, DataSchema.ANALYSIS),
            Skill("threat_classification", 0.2, DataSchema.QA),
            Skill("detection_engineering", 0.15, DataSchema.CODE_GEN),
        ],
        
        ("supports_code_review", TrainingGoal.SECURITY_TOOL_BUILDER): [
            Skill("vulnerability_detection", 0.4, DataSchema.CODE_REVIEW),
            Skill("secure_coding", 0.3, DataSchema.CODE_GEN),
            Skill("tool_design_patterns", 0.3, DataSchema.CODE_GEN),
        ],
        
        ("supports_tool_generation", TrainingGoal.SECURITY_TOOL_BUILDER): [
            Skill("requirements_to_code", 0.5, DataSchema.CODE_GEN),
            Skill("api_usage_patterns", 0.3, DataSchema.CODE_REVIEW),
            Skill("tool_documentation", 0.2, DataSchema.QA),
        ],
        
        ("supports_cti_qa", TrainingGoal.THREAT_INTEL_ANALYST): [
            Skill("intelligence_synthesis", 0.5, DataSchema.QA),
            Skill("report_summarization", 0.3, DataSchema.ANALYSIS),
            Skill("threat_actor_profiling", 0.2, DataSchema.CHAIN_OF_THOUGHT),
        ],
        
        ("supports_incident_playbook", TrainingGoal.INCIDENT_RESPONDER): [
            Skill("playbook_creation", 0.6, DataSchema.INCIDENT_PLAYBOOK),
            Skill("response_reasoning", 0.4, DataSchema.CHAIN_OF_THOUGHT),
        ],
        
        ("supports_code_review", TrainingGoal.SECURE_CODER): [
            Skill("secure_code_review", 0.6, DataSchema.CODE_REVIEW),
            Skill("secure_implementation", 0.4, DataSchema.CODE_GEN),
        ],
        
        # Phase 3: Fix VULNERABILITY_RESEARCHER
        ("supports_code_analysis", TrainingGoal.VULNERABILITY_RESEARCHER): [
            Skill("vulnerability_analysis", 0.5, DataSchema.ANALYSIS),
            Skill("exploit_reasoning", 0.3, DataSchema.CHAIN_OF_THOUGHT),
            Skill("cve_qa", 0.2, DataSchema.QA),
        ],
        
        # Phase 3: New Goals
        ("supports_log_analysis", TrainingGoal.SOC_ANALYST): [
            Skill("alert_triage", 0.5, DataSchema.MULTI_STEP_DECISION),
            Skill("siem_queries", 0.3, DataSchema.THREAT_HUNTING),
            Skill("log_explanation", 0.2, DataSchema.QA),
        ],
        
        ("supports_log_analysis", TrainingGoal.THREAT_HUNTER): [
            Skill("hypothesis_generation", 0.5, DataSchema.THREAT_HUNTING),
            Skill("hunting_reasoning", 0.3, DataSchema.CHAIN_OF_THOUGHT),
            Skill("tool_usage", 0.2, DataSchema.TOOL_USAGE),
        ],
        
        ("supports_code_analysis", TrainingGoal.DETECTION_ENGINEER): [
            Skill("detection_rule_writing", 0.6, DataSchema.DETECTION_ENGINEERING),
            Skill("behavior_documentation", 0.4, DataSchema.ANALYSIS),
        ],
        
        ("supports_forensics", TrainingGoal.DIGITAL_FORENSICS): [
            Skill("timeline_analysis", 0.5, DataSchema.FORENSIC_TIMELINE),
            Skill("artifact_reasoning", 0.3, DataSchema.CHAIN_OF_THOUGHT),
            Skill("tool_usage", 0.2, DataSchema.TOOL_USAGE),
        ],
        
        ("supports_malware_analysis", TrainingGoal.MALWARE_REVERSE_ENGINEER): [
            Skill("deep_reverse_engineering", 0.5, DataSchema.CHAIN_OF_THOUGHT),
            Skill("tool_usage", 0.3, DataSchema.TOOL_USAGE),
            Skill("anti_analysis_detection", 0.2, DataSchema.ANALYSIS),
        ],
    }
    
    def extract_skills(
        self,
        capabilities: ContentCapabilities,
        goal: TrainingGoal,
        richness: float
    ) -> list[Skill]:
        """
        Returns a prioritized list of skills to extract based on capabilities and goal.
        """
        all_skills = []
        
        for (cap_name, req_goal), skills in self.SKILL_MAP.items():
            # Support fallback to GENERAL_CYBER_ASSISTANT by acting as a catch-all if cap matches
            if getattr(capabilities, cap_name) and (goal == req_goal or goal == TrainingGoal.GENERAL_CYBER_ASSISTANT):
                max_skills = 4 if richness >= 0.65 else 2
                all_skills.extend(skills[:max_skills])
        
        # Default fallback
        if not all_skills:
            all_skills = [
                Skill("general_understanding", 0.5, DataSchema.QA),
                Skill("logical_reasoning", 0.5, DataSchema.CHAIN_OF_THOUGHT)
            ]
            
        # Deduplicate by schema to avoid duplicate schemas in the strategy planner
        # We prefer the skill with the highest weight for a given schema
        unique_skills = {}
        for skill in all_skills:
            if skill.schema not in unique_skills or unique_skills[skill.schema].weight < skill.weight:
                unique_skills[skill.schema] = skill
                
        # Sort by weight
        return sorted(unique_skills.values(), key=lambda s: s.weight, reverse=True)
