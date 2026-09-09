import pytest
from shared_lib.quality_scorer import score_quality, QualityEngine

def test_grounding_score():
    source = "The adversary used mimikatz to dump lsass memory and retrieve NTLM hashes over SMB."
    output = {"reasoning": "mimikatz was executed to access lsass and extract NTLM hashes via SMB."}
    
    score = score_quality("chain_of_thought", output, source)
    assert score.grounding_ratio > 0.5
    
    # Test hallucinated grounding
    bad_output = {"reasoning": "The attacker deployed cobalt strike beacon."}
    score2 = score_quality("chain_of_thought", bad_output, source)
    assert score2.grounding_ratio < 0.2

def test_technical_depth():
    engine = QualityEngine()
    # Weak
    res1 = engine._score_technical_depth("This is a bad thing that happened to the computer.")
    assert res1 < 0.2
    
    # Strong (uses cyber terms)
    res2 = engine._score_technical_depth("The ransomware payload obfuscation used AES encryption to evade the firewall.")
    assert res2 > 0.3

def test_mitre_validity():
    engine = QualityEngine()
    source = "Technique T1059.001 was observed."
    
    # Valid and in source
    res1 = engine._score_mitre_validity({"mitre_ids": ["T1059.001"]}, source)
    assert res1 == 1.0
    
    # Valid format but NOT in source (half credit)
    res2 = engine._score_mitre_validity({"mitre_ids": ["T1110.003"]}, source)
    assert res2 == 0.5
    
    # Invalid format
    res3 = engine._score_mitre_validity({"mitre_ids": ["BRUTEFORCE"]}, source)
    assert res3 == 0.0

def test_structural_completeness():
    engine = QualityEngine()
    
    # Missing fields for analysis
    res1 = engine._score_structure("analysis", {"instruction": "Analyze this."})
    assert res1 < 0.5
    
    # Complete
    res2 = engine._score_structure("analysis", {
        "instruction": "Analyze this.",
        "summary": "It is bad.",
        "verdict": "Malicious"
    })
    assert res2 >= 0.8
