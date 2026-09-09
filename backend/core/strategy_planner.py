from backend.core.skill_extractor import Skill
from shared_lib.schemas import DataSchema

class StrategyPlanner:
    """
    Translates extracted skills into a concrete execution strategy (which schemas to run).
    This replaces the static TaskRouter with a dynamic skill-based router.
    
    v1.0.0 Upgrade: Diversity-Aware Planning
    Penalizes schemas from the same cognitive group (e.g., picking QA and Chat together)
    to maximize the pedagogical diversity of the generated records.
    """
    
    SCHEMA_GROUPS = {
        DataSchema.CHAIN_OF_THOUGHT: "reasoning",
        DataSchema.ANALYSIS: "reasoning",
        DataSchema.MULTI_STEP_DECISION: "reasoning",
        DataSchema.THREAT_HUNTING: "reasoning",
        DataSchema.FORENSIC_TIMELINE: "reasoning",
        DataSchema.QA: "interactive",
        DataSchema.CHAT: "interactive",
        DataSchema.CODE_GEN: "technical",
        DataSchema.CODE_REVIEW: "technical",
        DataSchema.TOOL_USAGE: "technical",
        DataSchema.DETECTION_ENGINEERING: "technical",
        DataSchema.INCIDENT_PLAYBOOK: "procedural",
        DataSchema.NEGATIVE_EXAMPLE: "other",
        DataSchema.ALPACA: "other",
    }

    def plan(self, skills: list[Skill], richness: float, threat_level_str: str = "BENIGN", max_schemas: int = 3) -> list[DataSchema]:
        # M7: Threat Level -> Schema Priority
        threat_priority_boosts = {
            "MALICIOUS": {DataSchema.THREAT_HUNTING: 0.3, DataSchema.ANALYSIS: 0.2, DataSchema.INCIDENT_PLAYBOOK: 0.2},
            "SUSPICIOUS": {DataSchema.MULTI_STEP_DECISION: 0.2, DataSchema.CHAIN_OF_THOUGHT: 0.2},
            "BENIGN": {DataSchema.CODE_GEN: 0.2, DataSchema.CODE_REVIEW: 0.2, DataSchema.TOOL_USAGE: 0.1}
        }
        boosts = threat_priority_boosts.get(threat_level_str.upper(), {})
        
        scored_schemas = {}
        for skill in skills:
            if skill.schema not in scored_schemas:
                scored_schemas[skill.schema] = skill.weight + boosts.get(skill.schema, 0.0)
                
        # Diversity-aware selection
        schemas_needed = []
        selected_groups = set()
        
        # Iteratively pick the best schema, then penalize its group
        remaining = dict(scored_schemas)
        allowed_by_richness = 5 if richness >= 0.65 else 2
        final_limit = min(max_schemas, allowed_by_richness)
        
        while remaining and len(schemas_needed) < final_limit:
            # Pick schema with the highest current score
            best_schema = max(remaining.keys(), key=lambda s: remaining[s])
            schemas_needed.append(best_schema)
            
            group = self.SCHEMA_GROUPS.get(best_schema, "unknown")
            selected_groups.add(group)
            
            # Remove from remaining pool
            del remaining[best_schema]
            
            # Penalize remaining schemas in the same group to encourage cognitive diversity
            for s in list(remaining.keys()):
                if self.SCHEMA_GROUPS.get(s, "unknown") == group:
                    remaining[s] -= 0.35  # Diversity penalty
        
        return schemas_needed
