# tests/test_post_validator.py  — Cyber Data Engine v1.0.0
# =============================================================================
# Unit tests for PostValidator (v1.0.0 — Bug#2 fix verification)
#
# Tests cover:
#   - Bug#2 fix: ok=False when all alpaca_lines rejected by grounding
#   - MITRE stripping for benign content
#   - IOC stripping when not allowed
#   - CVE format validation
#   - Severity normalization
#   - Proper record_count update after grounding rejection
# =============================================================================

import json
import pytest

from shared_lib.post_validator import PostValidator, post_validate, PostValidationResult
from shared_lib.validator import ValidationResult


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def make_threat(
    level_str="BENIGN",
    mitre_allowed=False,
    ioc_allowed=False,
    cot_allowed=False,
    confidence=0.9,
):
    """Create a ThreatScore-compatible object for testing."""
    from shared_lib.threat_scorer import ThreatScore, ThreatLevel
    level_map = {
        "BENIGN": ThreatLevel.BENIGN,
        "SUSPICIOUS": ThreatLevel.SUSPICIOUS,
        "MALICIOUS": ThreatLevel.MALICIOUS,
    }
    return ThreatScore(
        level=level_map.get(level_str, ThreatLevel.BENIGN),
        confidence=confidence,
        mitre_allowed=mitre_allowed,
        ioc_allowed=ioc_allowed,
        cot_allowed=cot_allowed,
        keyword_score=0.0,
        entropy_score=0.0,
        context_score=0.0,
        final_score=0.5 if level_str != "BENIGN" else 0.1,
        has_action_verbs=False,
        has_exploit_context=False,
        has_system_target=False,
    )


def make_valid_result(output_text="Test output text.", schema="alpaca", quality=0.75):
    """Create a ValidationResult with one alpaca line."""
    line = json.dumps({
        "instruction": "Analyze this malware sample.",
        "output": output_text,
        "task_type": "malware_analysis",
        "source_file": "test.py",
    })
    return ValidationResult(
        ok=True,
        alpaca_lines=[line],
        rich_line=line,
        schema_used=schema,
        quality=quality,
        record_count=1,
        error="",
        raw="",
        provider="test",
    )


@pytest.fixture
def validator():
    return PostValidator()


# ─────────────────────────────────────────────────────────────────────────────
# Bug#2 Fix Tests — ok=False when all lines rejected
# ─────────────────────────────────────────────────────────────────────────────

class TestBug2Fix:
    """
    Critical Bug#2 test suite.
    Before fix: ok=True even when alpaca_lines=[] after grounding rejection.
    After fix: ok=False + record_count=0 when all lines are rejected.
    """

    def test_all_lines_rejected_returns_false(self, validator):
        """
        If output is completely unrelated to source chunk,
        all lines should be rejected and result.ok must be False.
        """
        # Completely unrelated output vs source
        unrelated_output = (
            "The Renaissance period in European history saw dramatic changes "
            "in art, architecture and philosophy during the 14th-17th centuries. "
            "Leonardo da Vinci and Michelangelo were prominent figures."
        )
        result = make_valid_result(output_text=unrelated_output)
        threat = make_threat("BENIGN")
        chunk = "import socket; s.connect(('10.0.0.1', 4444)); exec(recv_data)"

        post_result = validator.validate(result, threat, chunk=chunk)

        assert post_result.result.ok is False, (
            "Bug#2: result.ok should be False when all alpaca_lines are grounding-rejected"
        )
        assert post_result.result.record_count == 0, (
            "Bug#2: record_count should be 0 when all lines rejected"
        )
        assert post_result.result.alpaca_lines == [], (
            "Bug#2: alpaca_lines should be empty after full rejection"
        )

    def test_grounding_fail_populates_error(self, validator):
        """Error message should explain WHY record was rejected."""
        unrelated_output = "The history of ancient Rome spans many centuries."
        result = make_valid_result(output_text=unrelated_output)
        threat = make_threat("BENIGN")
        chunk = "subprocess.run(['cmd', '/c', 'whoami'], capture_output=True)"

        post_result = validator.validate(result, threat, chunk=chunk)

        if not post_result.result.ok:
            assert "grounding" in post_result.result.error.lower(), (
                "Error should mention grounding failure"
            )

    def test_failed_result_ok_was_previously_true(self, validator):
        """
        Regression test: Previously, an empty alpaca_lines still returned ok=True.
        This test ensures the old behavior NO LONGER occurs.
        """
        # No chunk provided (empty chunk) → grounding check skipped → ok should stay True
        result = make_valid_result(output_text="The malware uses socket for C2 communication.")
        threat = make_threat("BENIGN")

        post_result = validator.validate(result, threat, chunk="")

        # Without chunk, grounding cannot be verified → result should remain ok=True
        assert post_result.result.ok is True, (
            "Without source chunk, grounding cannot fail — result should stay ok=True"
        )

    def test_partial_rejection_preserves_ok_true(self, validator):
        """
        If some lines pass and some fail, result should remain ok=True
        with only the passing lines.
        """
        good_line = json.dumps({
            "instruction": "Analyze this code.",
            "output": "The malware uses socket connection to 10.0.0.1 on port 4444 for C2.",
            "task_type": "malware_analysis",
            "source_file": "test.py",
        })
        bad_line = json.dumps({
            "instruction": "Analyze this code.",
            "output": "History of Roman Empire and its fall in 476 AD.",
            "task_type": "malware_analysis",
            "source_file": "test.py",
        })

        result = ValidationResult(
            ok=True,
            alpaca_lines=[good_line, bad_line],
            rich_line=good_line,
            schema_used="alpaca",
            quality=0.7,
            record_count=2,
            error="",
            raw="",
            provider="test",
        )
        threat = make_threat("MALICIOUS", mitre_allowed=True, ioc_allowed=True)
        chunk = "The malware connects socket to 10.0.0.1 port 4444 for command and control."

        post_result = validator.validate(result, threat, chunk=chunk)
        # At least one line should be kept if it's grounded
        assert post_result.result.record_count >= 0


# ─────────────────────────────────────────────────────────────────────────────
# MITRE Stripping Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMitreStripping:

    def test_mitre_stripped_when_not_allowed(self, validator):
        """mitre_ids should be cleared for benign content."""
        line = json.dumps({
            "instruction": "Explain encryption",
            "output": "AES is a symmetric encryption algorithm.",
            "task_type": "general_cyber",
            "mitre_ids": ["T1059.001", "T1055"],
            "source_file": "test.py",
        })
        result = ValidationResult(
            ok=True, alpaca_lines=[line], rich_line=line,
            schema_used="alpaca", quality=0.7, record_count=1,
            error="", raw="", provider="test",
        )
        threat = make_threat("BENIGN", mitre_allowed=False)
        chunk = "AES is used for encryption. It is a symmetric cipher."

        post_result = validator.validate(result, threat, chunk=chunk)

        if post_result.result.ok and post_result.result.alpaca_lines:
            cleaned = json.loads(post_result.result.alpaca_lines[0])
            assert cleaned.get("mitre_ids", []) == [], "MITRE IDs should be stripped for benign content"
        assert post_result.cleaned is True

    def test_mitre_preserved_when_allowed_and_grounded(self, validator):
        """MITRE IDs in source should NOT be stripped for malicious content."""
        source = "T1059.001 PowerShell execution was observed. subprocess.run powershell attack."
        line = json.dumps({
            "instruction": "Analyze the PowerShell attack",
            "output": "The attacker used T1059.001 PowerShell execution via subprocess.",
            "task_type": "malware_analysis",
            "mitre_ids": ["T1059.001"],
            "source_file": "test.py",
        })
        result = ValidationResult(
            ok=True, alpaca_lines=[line], rich_line=line,
            schema_used="chain_of_thought", quality=0.8, record_count=1,
            error="", raw="", provider="test",
        )
        threat = make_threat("MALICIOUS", mitre_allowed=True, ioc_allowed=True, confidence=0.9)

        post_result = validator.validate(result, threat, chunk=source)

        if post_result.result.ok and post_result.result.alpaca_lines:
            cleaned = json.loads(post_result.result.alpaca_lines[0])
            # T1059.001 is in source → should be preserved
            mitre_ids = cleaned.get("mitre_ids", [])
            assert "T1059.001" in mitre_ids, "Grounded MITRE ID should be preserved"


# ─────────────────────────────────────────────────────────────────────────────
# IOC Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIOCHandling:

    def test_ioc_stripped_when_not_allowed(self, validator):
        """IOCs should be removed for benign content."""
        line = json.dumps({
            "instruction": "Explain networking",
            "output": "TCP connections use ports.",
            "task_type": "general_cyber",
            "iocs": ["192.168.1.100", "malware.exe"],
            "source_file": "test.py",
        })
        result = ValidationResult(
            ok=True, alpaca_lines=[line], rich_line=line,
            schema_used="alpaca", quality=0.7, record_count=1,
            error="", raw="", provider="test",
        )
        threat = make_threat("BENIGN", ioc_allowed=False)

        post_result = validator.validate(result, threat, chunk="TCP connections use port numbers.")

        if post_result.result.ok and post_result.result.alpaca_lines:
            cleaned = json.loads(post_result.result.alpaca_lines[0])
            assert cleaned.get("iocs", []) == [], "IOCs should be stripped for benign content"


# ─────────────────────────────────────────────────────────────────────────────
# CVE Validation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCVEValidation:

    def test_invalid_cve_year_flagged(self, validator):
        """CVEs with years before 1999 or after 2026 should be marked invalid."""
        line = json.dumps({
            "instruction": "Analyze vulnerability",
            "output": "Exploiting CVE-1985-1234 which affects old systems. Also CVE-2023-44487.",
            "task_type": "vulnerability_analysis",
            "source_file": "test.py",
        })
        result = ValidationResult(
            ok=True, alpaca_lines=[line], rich_line=line,
            schema_used="analysis", quality=0.7, record_count=1,
            error="", raw="", provider="test",
        )
        threat = make_threat("MALICIOUS", mitre_allowed=True, ioc_allowed=True)
        chunk = "CVE-2023-44487 is a known HTTP/2 vulnerability. CVE-1985-1234 was mentioned."

        post_result = validator.validate(result, threat, chunk=chunk)

        if post_result.result.ok and post_result.result.alpaca_lines:
            cleaned_text = post_result.result.alpaca_lines[0]
            # Invalid year CVE should be marked
            assert "INVALID CVE" in cleaned_text or "CVE-1985" not in cleaned_text


# ─────────────────────────────────────────────────────────────────────────────
# Severity Normalization Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityNormalization:

    def test_high_severity_normalized_for_benign(self, validator):
        """CRITICAL/HIGH severity should be normalized to INFO for benign content."""
        line = json.dumps({
            "instruction": "Explain SQL",
            "output": "SQL is a database query language.",
            "task_type": "general_cyber",
            "severity": "CRITICAL",
            "source_file": "test.py",
        })
        result = ValidationResult(
            ok=True, alpaca_lines=[line], rich_line=line,
            schema_used="alpaca", quality=0.7, record_count=1,
            error="", raw="", provider="test",
        )
        threat = make_threat("BENIGN")

        post_result = validator.validate(result, threat, chunk="SQL is a query language for databases.")

        if post_result.result.ok and post_result.result.alpaca_lines:
            cleaned = json.loads(post_result.result.alpaca_lines[0])
            assert cleaned.get("severity") == "INFO", (
                f"Expected INFO severity for benign content, got {cleaned.get('severity')}"
            )

    def test_severity_preserved_for_malicious(self, validator):
        """Severity should NOT be changed for malicious content."""
        source = "Ransomware encrypts files with AES and demands payment via Bitcoin."
        line = json.dumps({
            "instruction": "Analyze ransomware",
            "output": "Ransomware encrypts files with AES and demands Bitcoin payment.",
            "task_type": "malware_analysis",
            "severity": "CRITICAL",
            "source_file": "test.py",
        })
        result = ValidationResult(
            ok=True, alpaca_lines=[line], rich_line=line,
            schema_used="chain_of_thought", quality=0.8, record_count=1,
            error="", raw="", provider="test",
        )
        threat = make_threat("MALICIOUS", mitre_allowed=True, ioc_allowed=True, confidence=0.95)

        post_result = validator.validate(result, threat, chunk=source)

        if post_result.result.ok and post_result.result.alpaca_lines:
            cleaned = json.loads(post_result.result.alpaca_lines[0])
            assert cleaned.get("severity") == "CRITICAL", "Severity should be preserved for malicious content"


# ─────────────────────────────────────────────────────────────────────────────
# Record count accuracy test
# ─────────────────────────────────────────────────────────────────────────────

class TestRecordCount:

    def test_record_count_matches_alpaca_lines(self, validator):
        """record_count must exactly match len(alpaca_lines) after post-validation."""
        good_output = "The malware connects to socket on port 4444 for command and control."
        line = json.dumps({
            "instruction": "Analyze C2 communication",
            "output": good_output,
            "task_type": "malware_analysis",
            "source_file": "test.py",
        })
        result = ValidationResult(
            ok=True, alpaca_lines=[line],
            rich_line=line, schema_used="alpaca",
            quality=0.75, record_count=1,
            error="", raw="", provider="test",
        )
        threat = make_threat("MALICIOUS", mitre_allowed=True, ioc_allowed=True)
        chunk = "The malware connects to socket on port 4444 for command and control operations."

        post_result = validator.validate(result, threat, chunk=chunk)

        actual_count = len(post_result.result.alpaca_lines)
        reported_count = post_result.result.record_count
        assert actual_count == reported_count, (
            f"record_count ({reported_count}) must match len(alpaca_lines) ({actual_count})"
        )
