# core/classifier.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# SMART CONTENT CLASSIFIER
# Determines schema + task type BEFORE sending to LLM.
# Uses 4-layer inspection: extension → filename keywords → content patterns → entropy
# Returns confidence score so low-confidence results can be logged/reviewed.
# =============================================================================
"""
classifier.py  —  Four-Layer Content Classifier

Classifies any file into one of four DataTypes using purely deterministic
rule-based logic. No LLM is invoked at any point.

Layer Architecture:
  Layer 0 — Binary/PCAP fast-path: immediately returns for known binary
             formats regardless of content.
  Layer 1 — Extension map: maps code extensions (→ CODE), data extensions
             (→ DATA), and document extensions (→ EDUCATIONAL).
  Layer 2 — Source code: escalates to ATTACK_ARTIFACT if content has
             overwhelming malware signals (score >= 0.85) or malware filename.
  Layer 3 — Documents: escalates to ATTACK_ARTIFACT on high malware score.
  Layer 4 (fallback) — Unknown extension: EDUCATIONAL with low confidence.

Hard Type Lock:
  Once a DataType is assigned by extension, the schema and task_type are
  locked and cannot be overridden by content signals (except the escalation
  paths noted above). This prevents cross-domain schema pollution.

Dead Code Flag:
  _compute_cyber_relevance() is defined but never called. Retained for
  Phase 5 review.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from shared_lib.schemas import DataSchema, TaskType, DataType, Classification

# ─────────────────────────────────────────────────────────────────────────────
# Signature libraries
# ─────────────────────────────────────────────────────────────────────────────

_CODE_EXT_MAP: dict[str, str] = {
    ".py":"Python",".pyw":"Python",".ps1":"PowerShell",".psm1":"PowerShell",
    ".sh":"Bash",".bash":"Bash",".zsh":"Zsh",".bat":"Batch/CMD",".cmd":"Batch/CMD",
    ".vbs":"VBScript",".vba":"VBA",".js":"JavaScript",".mjs":"JavaScript",
    ".ts":"TypeScript",".jsx":"React/JSX",".tsx":"React/TSX",".php":"PHP",
    ".rb":"Ruby",".go":"Go",".rs":"Rust",".cs":"C#",".java":"Java",
    ".c":"C",".cpp":"C++",".cc":"C++",".h":"C/C++ Header",".hpp":"C++ Header",
    ".lua":"Lua",".pl":"Perl",".r":"R",".m":"MATLAB",".swift":"Swift",
    ".kt":"Kotlin",".kts":"Kotlin Script",".scala":"Scala",".groovy":"Groovy",
    ".asm":"Assembly",".s":"Assembly",".nim":"Nim",".zig":"Zig",
}

_DOC_EXTS  = {".pdf",".docx",".doc",".txt",".md",".rst",".tex",".html",".htm",".rtf"}
_DATA_EXTS = {".json",".jsonl",".yaml",".yml",".xml",".csv",".tsv",".log",".toml",".ini",".conf"}
_PCAP_EXTS = {".pcap",".pcapng",".cap"}
_BIN_EXTS  = {".exe",".dll",".so",".elf",".bin",".sys",".drv",".com",".ocx",".lib",".a"}
_IMG_EXTS  = {".png",".jpg",".jpeg",".gif",".bmp",".tiff",".webp",".ico"}
_ARCHIVE_EXTS={".zip",".tar",".gz",".7z",".rar",".bz2",".xz"}
_SHEET_EXTS={".xlsx",".xls",".ods",".numbers"}


# Content pattern signatures — (regex, weight, tag)
_MALWARE_SIGS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'(?:cmd|powershell|wscript|cscript)\.exe', re.I),       0.4, "cmd_exec"),
    (re.compile(r'invoke-expression|iex\s*\(',           re.I),           0.5, "iex"),
    (re.compile(r'FromBase64String|encodedCommand',      re.I),           0.5, "base64"),
    (re.compile(r'shellcode|msfvenom|meterpreter',       re.I),           0.7, "exploit_tool"),
    (re.compile(r'mimikatz|sekurlsa|lsadump',            re.I),           0.8, "credential_dump"),
    (re.compile(r'CreateRemoteThread|VirtualAlloc',      re.I),           0.6, "process_inject"),
    (re.compile(r'WriteProcessMemory|NtCreateThread',    re.I),           0.6, "process_inject"),
    (re.compile(r'(?:wget|curl)\s+(?:https?|ftp)://',    re.I),           0.3, "download"),
    (re.compile(r'DownloadString|DownloadFile',          re.I),           0.5, "download"),
    (re.compile(r'(?:\\x[0-9a-fA-F]{2}){8,}'),                   0.5, "hex_shellcode"),
    (re.compile(r'ransomware|\.locked|CryptoLocker',     re.I),           0.8, "ransomware"),
    (re.compile(r'cobalt[\s_]?strike|beacon',            re.I),           0.7, "c2_framework"),
    (re.compile(r'privilege[\s_]?escal|UAC[\s_]?bypass', re.I),          0.5, "privesc"),
    (re.compile(r'persistence|run[\s_]?key|autorun',     re.I),           0.4, "persistence"),
    (re.compile(r'obfuscat|encode.*decode|rot13',        re.I),           0.4, "obfuscation"),
    (re.compile(r'xor\s*\(|xor\s+byte',                 re.I),           0.3, "xor_obf"),
    (re.compile(r'keylog|GetAsyncKeyState',              re.I),           0.7, "keylogger"),
    (re.compile(r'botnet|C2|command[\s_]?and[\s_]?control', re.I),       0.6, "c2"),
    (re.compile(r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER)', re.I),            0.2, "registry"),
    (re.compile(r'net\s+(?:user|localgroup|share)',      re.I),           0.3, "net_recon"),
]

_LOG_SIGS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'),             0.4, "iso_ts"),
    (re.compile(r'\[(?:ERROR|WARN|INFO|DEBUG|CRITICAL|FATAL)\]', re.I),  0.5, "log_level"),
    (re.compile(r'EventID|event_id\s*[:=]\s*\d+',       re.I),           0.5, "event_id"),
    (re.compile(r'src(?:ip)?[\s:=]+\d{1,3}\.\d{1,3}',  re.I),           0.4, "src_ip"),
    (re.compile(r'(?:failed|invalid|denied)\s+(?:login|auth|password)', re.I), 0.5, "auth_fail"),
    (re.compile(r'HTTP/[12]\.\d"\s+[45]\d{2}',          re.I),           0.3, "http_error"),
    (re.compile(r'syslog|/var/log/',                     re.I),           0.3, "syslog"),
]

_REPORT_SIGS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'executive\s+summary|threat\s+actor',  re.I),           0.5, "report_structure"),
    (re.compile(r'indicators?\s+of\s+compromise|IOC',   re.I),           0.6, "ioc_section"),
    (re.compile(r'T\d{4}(?:\.\d{3})?'),                          0.4, "mitre_id"),
    (re.compile(r'CVE-\d{4}-\d{4,}',                    re.I),           0.4, "cve_ref"),
    (re.compile(r'attribution|nation[\s-]?state|APT\s*\d+', re.I),      0.5, "attribution"),
    (re.compile(r'campaign|malware\s+family|dropper',   re.I),           0.4, "threat_intel"),
    (re.compile(r'CVSS\s+(?:score|v\d)',                re.I),           0.4, "cvss"),
]

_FINANCIAL_SIGS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'delinquenc(?:y|ies)|non-accrual|loan\s+portfolio', re.I), 0.7, "loans"),
    (re.compile(r'balance\s+sheet|income\s+statement|cash\s+flow', re.I), 0.6, "financial_statements"),
    (re.compile(r'ebitda|revenue|fiscal\s+year|quarterly\s+results', re.I), 0.5, "earnings"),
    (re.compile(r'dividends?|shareholders?|stockholders?', re.I), 0.4, "equity"),
    (re.compile(r'credit\s+risk|interest\s+rate|amortization', re.I), 0.5, "banking"),
]

_TOOL_SIGS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'def\s+\w+\([^)]*\)\s*:'),                      0.3, "py_func"),
    (re.compile(r'if\s+__name__\s*==\s*["\']__main__["\']'),    0.5, "py_main"),
    (re.compile(r'argparse\.|optparse\.|click\.',        re.I),           0.4, "cli_tool"),
    (re.compile(r'socket\.(?:connect|bind|listen)',      re.I),           0.4, "network_tool"),
    (re.compile(r'function\s+\w+\s*\{',                 re.I),           0.3, "func_def"),
    (re.compile(r'#!\s*/(?:usr/bin|bin)/(?:python|bash|env)', re.I),    0.3, "shebang"),
]

_FNAME_MALWARE = {
    "malware","ransomware","trojan","backdoor","rootkit","exploit","payload",
    "shellcode","dropper","loader","stealer","rat","keylogger","botnet",
    "worm","virus","obfusc","implant","beacon","stager","crypter",
}
_FNAME_REPORT = {
    "report","analysis","threat","intel","cti","advisory","bulletin",
    "writeup","ioc","apt","campaign","incident","forensic","audit",
}
_FNAME_LOG = {
    "log","event","syslog","audit","access","error","debug","trace","pcap",
}


# ─────────────────────────────────────────────────────────────────────────────
# Classifier
# ─────────────────────────────────────────────────────────────────────────────

class ContentClassifier:

    # CLASSIFY — assign DataType, DataSchema, and TaskType to a file.
    # Args:    filename: str — full filename including extension.
    #          preview: str  — first ~4000 chars of extracted text content.
    # Returns: Classification with data_type, schema, task_type, confidence,
    #          hints (list of signal tags), and reasoning (human-readable).
    # Side effects: None. Pure computation.
    def classify(self, filename: str, preview: str = "") -> Classification:
        """
        Classify a file based on Hard Type Lock (Architecture v1.0.0).
        Preview = first 4000 chars.
        Returns a Classification with data_type, schema, and task_type.
        """
        ext     = Path(filename).suffix.lower()
        fstem   = Path(filename).stem.lower()
        p       = preview[:4000]

        # ── Layer 0: Quick bypass for code/binary types ───────────────────────────
        # Document files (.txt, .md, .pdf …) are checked.
        _always_relevant = (
            ext in _CODE_EXT_MAP
            or ext in _BIN_EXTS
            or ext in _PCAP_EXTS
            or ext in _ARCHIVE_EXTS
            or ext in _SHEET_EXTS
        )
        
        # Cache for mal_score to prevent redundant regex execution
        # Layer 0: lazy mal_score computation via closure.
        # The regex scan is expensive; cache the result so Layer 2 and Layer 4
        # share a single computation rather than running it twice.
        _cached_mal_score = None
        def get_mal_score() -> float:
            nonlocal _cached_mal_score
            if _cached_mal_score is None:
                _cached_mal_score = self._score(p, _MALWARE_SIGS)
            return _cached_mal_score

        # ── Layer 1: Binary executables & PCAP (ATTACK_ARTIFACT / FORENSICS) ──
        if ext in _BIN_EXTS:
            return Classification(
                data_type=DataType.ATTACK_ARTIFACT,
                schema=DataSchema.CHAIN_OF_THOUGHT,
                task_type=TaskType.MALWARE_ANALYSIS,
                is_binary=True,
                confidence=0.95,
                hints=["binary_executable", f"ext:{ext}"],
                reasoning=f"Binary executable ({ext}) — assuming attack artifact/malware candidate.",
            )

        if ext in _PCAP_EXTS:
            return Classification(
                data_type=DataType.ATTACK_ARTIFACT,
                schema=DataSchema.CHAIN_OF_THOUGHT,
                task_type=TaskType.LOG_ANALYSIS,
                confidence=0.95,
                hints=["pcap_capture"],
                reasoning="Network capture file — mapped to attack artifact.",
            )

        # ── Layer 2: Source Code (CODE) ───────────────────────────────────────
        if ext in _CODE_EXT_MAP:
            lang = _CODE_EXT_MAP[ext]
            mal_score  = get_mal_score()
            fname_mal  = any(k in fstem for k in _FNAME_MALWARE)

            # Only flag as ATTACK if explicit overwhelming malware signals are present
            if mal_score >= 0.85 or fname_mal:
                return Classification(
                    data_type=DataType.ATTACK_ARTIFACT,
                    schema=DataSchema.CHAIN_OF_THOUGHT,
                    task_type=TaskType.MALWARE_ANALYSIS,
                    language=lang,
                    confidence=0.90,
                    hints=[f"malware_score:{mal_score:.2f}", f"lang:{lang}"],
                    reasoning=f"Code file ({lang}) with EXPLICIT attack payload signals.",
                )
            
            return Classification(
                data_type=DataType.CODE,
                schema=DataSchema.CODE_GEN,
                task_type=TaskType.CODE_GENERATION,
                language=lang,
                confidence=0.95,
                hints=[f"lang:{lang}"],
                reasoning=f"Code file ({lang}) — strictly locked to CODE type.",
            )

        # ── Layer 3: Structured Data / Logs (DATA) ───────────────────────────
        if ext in _DATA_EXTS:
            # P1.5: Block raw .json files from generating useless syntax QA
            if ext == ".json":
                # Detect high-value structured threat intelligence formats before blocking.
                stix_signals     = ["spec_version", "objects", "attack-pattern", "malware", "indicator"]
                sigma_signals    = ["title", "logsource", "detection", "condition"]
                suricata_signals = ["alert", "flow", "payload", "app_proto"]
                openIOC_signals  = ["indicators", "IndicatorItem", "malware-samples"]
                all_signal_sets  = [stix_signals, sigma_signals, suricata_signals, openIOC_signals]

                is_threat_intel_json = any(
                    sum(1 for sig in signals if sig in p) >= 3
                    for signals in all_signal_sets
                )

                if not is_threat_intel_json:
                    return Classification(
                        data_type=DataType.IRRELEVANT,
                        schema=DataSchema.QA,
                        task_type=TaskType.GENERAL_CYBER,
                        confidence=0.90,
                        hints=["raw_json_blocked"],
                        reasoning="Generic JSON with no threat intel signals — dropping.",
                    )
                # Threat intel JSON (STIX/SIGMA/IOC) → falls through to document processing
                return Classification(
                    data_type=DataType.ATTACK_ARTIFACT,
                    schema=DataSchema.CHAIN_OF_THOUGHT,
                    task_type=TaskType.MALWARE_ANALYSIS,
                    confidence=0.80,
                    hints=["structured_threat_intel_json"],
                    reasoning="JSON contains structured threat intelligence signals (STIX/SIGMA/Suricata/OpenIOC).",
                )
            return Classification(
                data_type=DataType.DATA,
                schema=DataSchema.QA,
                task_type=TaskType.GENERAL_CYBER,
                confidence=0.85,
                hints=["structured_data_locked"],
                reasoning="Structured data (DB/CSV/Log) — strictly locked to DATA type.",
            )

        # ── Layer 4: Documents (EDUCATIONAL / DOC) ────────────────────────────
        if ext in _DOC_EXTS or ext == "":
            mal_score  = get_mal_score()
            fin_score  = self._score(p, _FINANCIAL_SIGS)
            has_cve    = bool(re.search(r'CVE-\d{4}-\d{4,}', p))
            fname_mal  = any(k in fstem for k in _FNAME_MALWARE)

            # P1.5: Drop strictly financial documents (Domain Dilution Fix)
            if fin_score >= 0.6 and fin_score > mal_score:
                return Classification(
                    data_type=DataType.IRRELEVANT,
                    schema=DataSchema.QA,
                    task_type=TaskType.GENERAL_CYBER,
                    confidence=0.90,
                    hints=[f"fin_score:{fin_score:.2f}"],
                    reasoning="Document is heavily focused on financial/banking metrics (non-cyber) — dropping to prevent domain dilution.",
                )

            # High score or explicit exploit doc
            if mal_score >= 0.8 or fname_mal:
                return Classification(
                    data_type=DataType.ATTACK_ARTIFACT,
                    schema=DataSchema.CHAIN_OF_THOUGHT,
                    task_type=TaskType.MALWARE_ANALYSIS,
                    confidence=0.85,
                    hints=[f"mal:{mal_score:.2f}"],
                    reasoning=f"Document with extremely strong attack signals.",
                )

            # Default for text/pdf/markdown docs -> Educational
            return Classification(
                data_type=DataType.EDUCATIONAL,
                schema=DataSchema.QA,
                task_type=TaskType.GENERAL_CYBER,
                confidence=0.80,
                hints=["doc_educational_locked"],
                reasoning="General document — strictly locked to EDUCATIONAL type.",
            )

        # ── Fallback ──────────────────────────────────────────────────────────
        return Classification(
            data_type=DataType.EDUCATIONAL,
            schema=DataSchema.ALPACA,
            task_type=TaskType.GENERAL_CYBER,
            confidence=0.4,
            hints=[f"unknown_ext:{ext}","fallback"],
            reasoning=f"Unknown extension ({ext}) — falling back to EDUCATIONAL.",
        )

    # ── Scoring helpers ───────────────────────────────────────────────────────

    # SCORE — compute weighted sum of pattern matches, capped at 1.0.
    # Args:    text: str         — content to scan.
    #          sigs: list[tuple] — list of (compiled_regex, weight, tag) tuples.
    # Returns: float in [0.0, 1.0] — total weighted score.
    # Side effects: None.
    @staticmethod
    def _score(text: str, sigs: list[tuple]) -> float:
        """Weighted sum of pattern matches, capped at 1.0."""
        total = 0.0
        for pattern, weight, _ in sigs:
            if pattern.search(text):
                total += weight
        return min(total, 1.0)

    # SCORE (DEAD CODE) — hybrid relevance scorer combining keyword density
    # and code-pattern detection.
    # NOTE: This method is NEVER CALLED in the current codebase.
    #       Flagged for removal in Phase 5 (item m1).
    # Args:    text: str — content to analyse.
    #          ext: str  — file extension (currently unused inside the method).
    # Returns: float in [0.0, 1.0] — relevance score.
    @staticmethod
    def _compute_cyber_relevance(text: str, ext: str) -> float:
        """P1.5: Hybrid relevance score for document-type files.

        Combines keyword density with code-pattern detection.
        Returns a score in [0.0, 1.0]. Threshold is _RELEVANCE_THRESHOLD.

        Why hybrid (not keywords alone): a Rust malware file might have zero
        'exploit' or 'malware' words, but it will have socket/connect patterns.
        """
        if not text:
            return 0.0

        # Component 1: Cyber keyword density (60% weight)
        CYBER_KEYWORDS = {
            "exploit","vulnerability","malware","payload","shellcode",
            "injection","socket","subprocess","process","registry",
            "network","packet","firewall","authentication","encryption",
            "hash","certificate","token","privilege","cve","mitre",
            "attack","ioc","c2","backdoor","rootkit","trojan","ransomware",
            "python","powershell","bash","assembly","buffer","memory",
            "port","protocol","http","https","dns","tcp","udp","ssh",
            "ftp","reverse","shell","obfuscat","encode","decode",
            "overflow","heap","stack","thread","kernel","syscall",
        }
        words = set(re.findall(r'\b\w+\b', text.lower()))
        distinct_keywords_found = len(words & CYBER_KEYWORDS)
        # If we find 15 distinct cyber keywords in the text, it's highly relevant.
        kw_score = min(distinct_keywords_found / 15.0, 1.0)

        # Component 2: Code / technical pattern density (40% weight)
        CODE_PATTERNS = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',   # IP address
            r'(?:connect|bind|listen)\s*\(',            # socket ops
            r'(?:subprocess|exec|eval|system)\s*\(',   # execution
            r'(?:open|read|write)\s*\(',                # file ops
            r'0x[0-9a-fA-F]{2,}',                       # hex values
            r'CVE-\d{4}-\d+',                           # CVE IDs
            r'T\d{4}(?:\.\d{3})?',                      # MITRE IDs
            r'(?:sha|md5|sha256|sha512)\s*[:=]',        # hashes
            r'(?:https?|ftp)://\S+',                    # URLs
            r'(?:import|include|require)\s+\w+',        # imports
        ]
        pattern_hits = sum(
            1 for p in CODE_PATTERNS if re.search(p, text, re.I)
        )
        pattern_score = pattern_hits / len(CODE_PATTERNS)

        return kw_score * 0.60 + pattern_score * 0.40
