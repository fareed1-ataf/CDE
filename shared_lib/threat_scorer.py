# core/threat_scorer.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# HYBRID THREAT SCORING ENGINE  (replaces binary rule engine)
#
# Architecture Decision (initial design):
#   BEFORE (v1.0.0): Binary rule decisions → fragile on mixed content
#   AFTER  (v1.0.0): Weighted scoring pipeline → robust on real-world data
#
# Expert Feedback Addressed:
#   ✓ Problem 1: Adversarial/mixed content handling
#   ✓ Problem 2: Rule engine → scoring engine (not hard decisions)
#   ✓ Problem 3: Triple-condition MITRE gate (action + context + target)
#   ✗ Rejected:  LLM Mini for classification (circular dependency risk +
#                 2x latency. Replaced with Context Window Scoring instead.)
#
# Scoring Formula:
#   ThreatScore = (keyword_score × 0.40)
#               + (entropy_score × 0.30)
#               + (context_score × 0.30)
#
#   context_score = smarter pattern matching with ±50 char window analysis
#   NOT an LLM — uses sliding window regex for contextual awareness
#
# MITRE Gate (Triple Condition):
#   allow_mitre = action_verbs AND exploit_context AND system_target
#   All THREE must be present simultaneously — not just one or two.
# =============================================================================
"""
threat_scorer.py  —  Hybrid Threat Scoring Engine

Assigns a continuous threat score in [0.0, 1.0] to any file content.

Scoring Formula:
    ThreatScore = (keyword_score  × 0.40)
                + (entropy_score  × 0.30)
                + (context_score  × 0.30)

Sub-scorer roles:
  keyword_score  — regex matches against curated malware / benign pattern lists.
  entropy_score  — Shannon entropy of character distribution.
                   High entropy → obfuscated or encoded content.
  context_score  — sliding-window proximity: detects suspicious keywords
                   appearing within ±200 chars of an attack-context pattern.
                   Provides contextual awareness with zero LLM cost.

MITRE ATT&CK Gate (Triple Condition):
    mitre_allowed = action_verbs AND exploit_context AND system_target
    All three must be simultaneously true. This prevents MITRE hallucination
    on documents that merely discuss attack concepts in an educational context.

Location Note:
    Lives in shared_lib/ (moved from backend/core/) so that both backend.core
    and shared_lib modules can import it without circular imports.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Threat Level Enum
# ─────────────────────────────────────────────────────────────────────────────

class ThreatLevel(str, Enum):
    BENIGN     = "benign"      # Score < 0.25  → educational/doc content
    SUSPICIOUS = "suspicious"  # Score 0.25-0.5 → ambiguous, partial signals
    MALICIOUS  = "malicious"   # Score > 0.5   → confirmed attack artifacts


@dataclass
class ThreatScore:
    """Detailed threat scoring breakdown — transparent and debuggable."""
    keyword_score:  float      # 0.0-1.0  (weight: 40%)
    entropy_score:  float      # 0.0-1.0  (weight: 30%)
    context_score:  float      # 0.0-1.0  (weight: 30%)
    final_score:    float      # weighted combination

    # MITRE triple-gate results
    has_action_verbs:   bool
    has_exploit_context: bool
    has_system_target:  bool

    level:          ThreatLevel
    confidence:     float
    mitre_allowed:  bool
    ioc_allowed:    bool
    cot_allowed:    bool
    signals:        list[str] = field(default_factory=list)
    reasoning:      str = ""

    @property
    def is_benign(self) -> bool:
        return self.level == ThreatLevel.BENIGN

    @property
    def is_malicious(self) -> bool:
        return self.level == ThreatLevel.MALICIOUS


# ─────────────────────────────────────────────────────────────────────────────
# Keyword Pattern Libraries
# ─────────────────────────────────────────────────────────────────────────────

# HIGH-CONFIDENCE malicious execution artifacts
_MALWARE_KEYWORDS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'invoke-expression|iex\s*\(',               re.I), 0.80, "ps_iex"),
    (re.compile(r'FromBase64String|encodedcommand',          re.I), 0.75, "base64_decode"),
    (re.compile(r'shellcode|msfvenom|meterpreter',           re.I), 0.90, "exploit_tool"),
    (re.compile(r'mimikatz|sekurlsa|lsadump',                re.I), 0.95, "cred_dump"),
    (re.compile(r'CreateRemoteThread|VirtualAlloc',          re.I), 0.80, "process_inject"),
    (re.compile(r'WriteProcessMemory|NtCreateThread',        re.I), 0.80, "process_inject"),
    (re.compile(r'DownloadString\s*\(|DownloadFile\s*\(',    re.I), 0.70, "download_exec"),
    (re.compile(r'cobalt[\s_]?strike|cobaltstrike',          re.I), 0.90, "c2_framework"),
    (re.compile(r'ysoserial|TypeConfuseDelegate',            re.I), 0.85, "deserialization"),
    (re.compile(r'msf(?:venom|console)|metasploit',          re.I), 0.85, "exploit_fw"),
    (re.compile(r'schtasks\s+/create',                       re.I), 0.65, "scheduled_task"),
    (re.compile(r'(?:\\x[0-9a-fA-F]{2}){8,}'),                     0.70, "hex_shellcode"),
    (re.compile(r'ransomware|CryptoLocker|\.locked',         re.I), 0.90, "ransomware"),
    (re.compile(r'GetAsyncKeyState|keylog',                  re.I), 0.85, "keylogger"),
    (re.compile(r'reverse[\s_]?shell|bind[\s_]?shell',       re.I), 0.85, "shell"),
    (re.compile(r'nc\s+-[lep]|-e\s+/bin/(?:sh|bash)',        re.I), 0.90, "netcat_shell"),
    (re.compile(r'beacon(?:\.dll|\.exe|\s+call)',             re.I), 0.85, "cs_beacon"),
]

# MODERATE signals — could be educational or operational
_SUSPICIOUS_KEYWORDS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'CVE-\d{4}-\d{4,}',                        re.I), 0.45, "cve_ref"),
    (re.compile(r'T\d{4}(?:\.\d{3})?'),                            0.25, "mitre_ref"),
    (re.compile(r'\bexploit\b',                              re.I), 0.35, "exploit_word"),
    (re.compile(r'vuln(?:erable|erability|s)?\b',            re.I), 0.30, "vuln_word"),
    (re.compile(r'machine\s*key|validationKey|decryptionKey', re.I), 0.50, "machine_key"),
    (re.compile(r'web\.config|machineKey\s+validation',      re.I), 0.45, "webconfig"),
    (re.compile(r'sql\s+injection|xss|sqli\b',               re.I), 0.45, "web_vuln"),
    (re.compile(r'BOLA|IDOR|broken\s+(?:access|auth)',       re.I), 0.40, "api_vuln"),
    (re.compile(r'nmap\s+-|masscan\s+',                      re.I), 0.40, "scan_tool"),
    (re.compile(r'hashcat|john\s+the\s+ripper',              re.I), 0.45, "cracking"),
    (re.compile(r'pentest|red\s+team\s+(?:ops|operation)',   re.I), 0.35, "pentest_ops"),
    (re.compile(r'privilege\s+escalat|privesc',              re.I), 0.40, "privesc"),
    (re.compile(r'lateral\s+movement|pivot\s+to',            re.I), 0.40, "lateral_move"),
]

# STRONG benign documentation signals
_BENIGN_KEYWORDS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'no\s+prerequisites?\s+required',           re.I), 0.60, "cert_guide"),
    (re.compile(r'certif(?:ication|icate)\s+(?:of|for|exam)', re.I), 0.55, "certification"),
    (re.compile(r'learning\s+objectives?|after\s+completing', re.I), 0.55, "learning_obj"),
    (re.compile(r'CCSK|CISSP|CISM|Security\+\s',            re.I), 0.50, "cert_program"),
    (re.compile(r'Cloud\s+Security\s+Alliance|CSA\s+Guidance', re.I), 0.55, "csa_doc"),
    (re.compile(r'OWASP\s+(?:Top\s+10|Cheat\s+Sheet)',       re.I), 0.45, "owasp_guide"),
    (re.compile(r'ENISA\s+(?:report|guideline)',             re.I), 0.50, "enisa_doc"),
    (re.compile(r'NIST\s+SP\s+\d{3}',                       re.I), 0.45, "nist_pub"),
    (re.compile(r'ISO\s+270\d{2}',                          re.I), 0.45, "iso_standard"),
    (re.compile(r'shared\s+responsibility\s+model',          re.I), 0.55, "cloud_concepts"),
    (re.compile(r'exam\s+(?:prep|tips?|questions?|guide)',   re.I), 0.60, "exam_guide"),
    (re.compile(r'who\s+should\s+(?:earn|take|attend)\s',   re.I), 0.60, "audience"),
    (re.compile(r'chapter\s+\d+|section\s+\d+\.',           re.I), 0.35, "textbook"),
    (re.compile(r'governance|compliance\s+framework',        re.I), 0.30, "grc"),
]

# ─────────────────────────────────────────────────────────────────────────────
# MITRE Triple-Gate Patterns
# ─────────────────────────────────────────────────────────────────────────────

# Gate 1: Attack action verbs (must describe an active operation)
_ACTION_VERBS = re.compile(
    r'\b(?:'
    r'exploit(?:ing|s|ed|er)?'
    r'|inject(?:ing|s|ed)?'
    r'|bypass(?:ing|es|ed)?'
    r'|execut(?:ing|es|ed|e)?'
    r'|escalat(?:ing|es|ed)?'
    r'|dump(?:ing|s|ed)?'
    r'|steal(?:ing|s)?|stole'
    r'|exfiltrat(?:ing|es|ed)?'
    r'|persist(?:ing|s|ed)?'
    r'|pivot(?:ing|s|ed)?'
    r'|spawn(?:ing|s|ed)?\s+(?:shell|process)'
    r'|creat(?:ing|es|ed)?\s+(?:remote\s+thread|process\s+inject)'
    r'|dropp(?:ing|s|ed)?\s+(?:payload|malware|binary)'
    r'|lateral(?:ly)?\s+mov'
    r')\b',
    re.I
)

# Gate 2: Exploit/attack context (not just discussing the concept)
_EXPLOIT_CONTEXT = re.compile(
    r'\b(?:'
    r'target(?:ing|ed)?\s+(?:the\s+)?(?:system|host|machine|server|application|endpoint)'
    r'|victim\s+(?:machine|host|system|network)'
    r'|compromis(?:e|ed|ing)\s+(?:the\s+)?(?:system|host|machine)'
    r'|attacker\s+(?:can|could|will|did)'
    r'|malicious\s+(?:payload|code|script|actor)'
    r'|adversar(?:y|ial)\s+(?:action|technique|tactic)'
    r'|C2\s+(?:server|beacon|callback|communication)'
    r'|command[\s_]and[\s_]control'
    r'|dropper\s+(?:stage|payload)'
    r'|reverse\s+shell\s+(?:to|back|connect)'
    r'|infected\s+(?:host|system|machine)'
    r')\b',
    re.I
)

# Gate 3: System/application target (MITRE always maps to a target)
_SYSTEM_TARGET = re.compile(
    r'\b(?:'
    r'Windows|Linux|macOS|Android|iOS'
    r'|(?:Active\s+Directory|AD\s+domain)'
    r'|(?:IIS|Apache|nginx|Tomcat)'
    r'|(?:ASP\.NET|\.NET\s+Framework)'
    r'|(?:SQL\s+Server|MySQL|PostgreSQL|Oracle)'
    r'|(?:PowerShell|cmd\.exe|bash|sh\b)'
    r'|(?:LSASS|lsass\.exe|ntds\.dit)'
    r'|(?:registry\s+key|HKEY_|RunOnce)'
    r'|(?:kernel|ring0|privilege\s+level)'
    r'|(?:web\s+application|API\s+endpoint)'
    r'|(?:cloud\s+(?:tenant|subscription|function))'
    r')\b',
    re.I
)

# ─────────────────────────────────────────────────────────────────────────────
# Context Window Scorer (replaces LLM Mini — same contextual awareness)
# ─────────────────────────────────────────────────────────────────────────────

# Pattern pairs: (anchor_pattern, context_boost_pattern, boost_value)
# Detects when a suspicious word appears NEAR an attack context
_CONTEXT_WINDOW_RULES: list[tuple[re.Pattern, re.Pattern, float, str]] = [
    # "exploit" near a target system
    (re.compile(r'exploit', re.I), re.compile(r'ASP\.NET|ViewState|machineKey|validationKey', re.I), 0.70, "exploit+webapp"),
    # Download + execute proximity
    (re.compile(r'DownloadString|wget|curl', re.I), re.compile(r'IEX|invoke|exec|run', re.I), 0.75, "download+exec"),
    # Vulnerability mention near code
    (re.compile(r'vuln|CVE-', re.I), re.compile(r'proof.of.concept|PoC|exploit\s+code', re.I), 0.60, "vuln+poc"),
    # Machine key near attack
    (re.compile(r'machineKey|validationKey', re.I), re.compile(r'ysoserial|viewstate|forged|bypass', re.I), 0.80, "machinekey+exploit"),
    # "bypass" near auth controls
    (re.compile(r'bypass', re.I), re.compile(r'authentication|authorization|WAF|firewall|AMSI|AV', re.I), 0.65, "bypass+control"),
    # "injection" near code
    (re.compile(r'injection|inject', re.I), re.compile(r'payload|shellcode|command|sql|xpath', re.I), 0.65, "inject+payload"),
    # Encoded command near execution
    (re.compile(r'base64|encoded|obfuscat', re.I), re.compile(r'execute|run|IEX|invoke|powershell', re.I), 0.70, "encode+exec"),
    # Semantic Risk Signals (Layer 1 enhancement)
    (re.compile(r'credential|password|hash|ticket', re.I), re.compile(r'dump|steal|extract|brute\s*force|pass\s*the', re.I), 0.85, "credential_abuse"),
    (re.compile(r'access|login|session', re.I), re.compile(r'unauthorized|bypass|without\s+permission|hijack', re.I), 0.80, "unauth_access"),
    (re.compile(r'escalat|elevat', re.I), re.compile(r'privilege|admin|root|system', re.I), 0.85, "privesc_intent"),
    (re.compile(r'bypass|evade|disable', re.I), re.compile(r'authentication|mfa|2fa|firewall|antivirus|edr|amsi', re.I), 0.80, "defense_evasion"),
    # benign guide near learning context → REDUCES score
    (re.compile(r'OWASP|CCSK|CISSP|guide', re.I), re.compile(r'learn|understand|chapter|course|exam', re.I), -0.40, "guide+learning"),
    # Discussion context (reduces score)
    (re.compile(r'exploit|attack|vulnerability', re.I), re.compile(r'is\s+a|refers\s+to|defined\s+as|describes|overview\s+of', re.I), -0.25, "concept_only"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Benign file extension & filename signals
# ─────────────────────────────────────────────────────────────────────────────

_EXT_SCORES: dict[str, tuple[float, str]] = {
    # Malicious-leaning extensions
    '.exe': (0.80, 'binary_exe'),  '.dll': (0.80, 'binary_dll'),
    '.so':  (0.75, 'binary_so'),   '.elf': (0.75, 'binary_elf'),
    '.bin': (0.60, 'binary_bin'),  '.sys': (0.70, 'binary_sys'),
    '.ps1': (0.35, 'script_ps1'),  '.psm1': (0.35, 'script_ps1'),
    '.bat': (0.30, 'script_bat'),  '.vbs': (0.35, 'script_vbs'),
    '.sh':  (0.20, 'script_sh'),   '.cmd': (0.30, 'script_cmd'),
    # Benign-leaning extensions (negative score)
    '.pdf': (-0.20, 'doc_pdf'),    '.md':  (-0.15, 'doc_md'),
    '.txt': (-0.15, 'doc_txt'),    '.rst': (-0.15, 'doc_rst'),
    '.html': (-0.10, 'doc_html'),  '.docx': (-0.20, 'doc_docx'),
}

_BENIGN_FNAME_PATTERNS = re.compile(
    r'guide|tutorial|training|certification|course|handbook'
    r'|overview|introduction|readme|changelog|policy|standard|framework'
    r'|checklist|whitepaper|report|conference|workshop',
    re.I
)


# ─────────────────────────────────────────────────────────────────────────────
# Entropy Scorer
# ─────────────────────────────────────────────────────────────────────────────

# ENTROPY — compute Shannon entropy of the character frequency distribution.
# Shannon entropy H = -SUM(p_i * log2(p_i)) where p_i = freq(char_i) / len(text).
# Interpretation: <3.5 = natural text, 3.5-4.5 = code, 4.5-5.5 = compressed/encoded,
# >5.5 = likely obfuscated/shellcode.
# Args:    text: str — input text to analyse.
# Returns: float — Shannon entropy (typically 0.0-6.5 for text content).
def _shannon_entropy(text: str) -> float:
    """Shannon entropy of character distribution. High entropy = obfuscated."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


# SCORE ENTROPY — convert raw Shannon entropy to a normalised threat score [0,1].
# Only analyses text[:2000] to bound computation time.
# Piecewise linear mapping:
#   entropy < 3.5  → 0.0       (natural language — no threat signal)
#   3.5 – 4.5     → 0.0–0.2  (normal code — low signal)
#   4.5 – 5.5     → 0.2–0.5  (compressed/encoded — moderate signal)
#   > 5.5          → 0.5–0.9  (obfuscated/encrypted — strong signal)
# Args:    text: str — input text.
# Returns: float in [0.0, 1.0].
def _compute_entropy_score(text: str) -> float:
    """
    Converts Shannon entropy to a threat score.
    
    Entropy scale:
      < 3.5 → very low entropy (natural text like docs)         → score ~0.0
      3.5-4.5 → normal code/config                             → score ~0.2
      4.5-5.5 → compressed/encoded content                      → score ~0.5
      > 5.5 → likely obfuscated/encrypted/shellcode             → score ~0.8+
    """
    entropy = _shannon_entropy(text[:2000])
    if entropy < 3.5:
        return 0.0
    elif entropy < 4.5:
        return (entropy - 3.5) * 0.2
    elif entropy < 5.5:
        return 0.2 + (entropy - 4.5) * 0.3
    else:
        return min(0.5 + (entropy - 5.5) * 0.15, 0.90)


# ─────────────────────────────────────────────────────────────────────────────
# Context Window Scorer (the intelligent part — no LLM needed)
# ─────────────────────────────────────────────────────────────────────────────

# SCORE CONTEXT — sliding-window proximity analysis.
# For each rule in _CONTEXT_WINDOW_RULES, finds all anchor pattern matches and
# checks if the context pattern appears within ±200 chars of the anchor.
# ±200 chars ≈ one paragraph — the typical scope of a single attack step.
# Negative boost rules (benign educational signals) REDUCE the score.
# Args:    text: str        — input text.
#          signals: list    — mutable list; matched rule tags are appended.
# Returns: float clamped to [0.0, 1.0]. Raw score can go negative (benign rules).
# Side effects: appends tag strings to the signals list.
def _compute_context_score(text: str, signals: list[str]) -> float:
    """
    Sliding window pattern analysis.
    
    For each rule, checks if an anchor pattern appears within ±200 chars of 
    a context pattern. This is far more accurate than simple keyword presence.
    """
    score = 0.0
    for anchor_pat, context_pat, boost, tag in _CONTEXT_WINDOW_RULES:
        for m in anchor_pat.finditer(text):
            start = max(0, m.start() - 200)
            end   = min(len(text), m.end() + 200)
            window = text[start:end]
            if context_pat.search(window):
                score += boost
                signals.append(f"ctx:{tag}")
                break  # Don't double-count same rule

    return max(min(score, 1.0), 0.0)   # Clamp [-∞,+∞] → [0,1]


# ─────────────────────────────────────────────────────────────────────────────
# Main Scoring Engine
# ─────────────────────────────────────────────────────────────────────────────

class ThreatScoringEngine:
    """
    Hybrid threat scoring engine.
    
    Outputs a continuous score [0.0, 1.0] instead of binary decisions.
    This makes the system robust on mixed/ambiguous content.
    
    Formula: ThreatScore = kw(0.40) + entropy(0.30) + context(0.30)
    """

    WEIGHTS = {
        "keyword": 0.40,
        "entropy": 0.30,
        "context": 0.30,
    }

    # Score thresholds
    BENIGN_THRESHOLD    = 0.25
    MALICIOUS_THRESHOLD = 0.50

    # SCORE — compute the hybrid threat score for a file.
    # Pipeline stages:
    #   1. Extension + filename baseline — starting delta by file type.
    #   2. Keyword score (40%) — malware / suspicious / benign pattern matching.
    #   3. Layer 0 intent bypass — forces keyword_score=0 for clear educational docs.
    #   4. Entropy score (30%) — Shannon entropy of content[:2000].
    #   5. Context score (30%) — sliding-window proximity analysis.
    #   6. Weighted final score — clamped to [0.0, 1.0].
    #   7. Threat level — BENIGN (<0.25), SUSPICIOUS (0.25-0.50), MALICIOUS (>0.50).
    #   8. MITRE triple-gate — action_verbs AND exploit_context AND system_target.
    #   9. IOC/CoT gates — score-threshold based.
    #  10. Confidence — blends score distance from midpoint with cls_confidence.
    # Args:    filename: str        — source file path (extension + stem analysed).
    #          content: str         — raw text. Only content[:4000] is scored.
    #          cls_confidence: float — ContentClassifier confidence [0.0, 1.0].
    # Returns: ThreatScore with full component breakdown.
    # Side effects: None.
    def score(self, filename: str, content: str, cls_confidence: float = 0.6) -> ThreatScore:
        """
        Compute hybrid threat score for content.
        
        Args:
            filename: Source file path
            content:  Text content (uses first 4000 chars)
            cls_confidence: Classifier confidence (used to scale final confidence)
        """
        ext  = Path(filename).suffix.lower()
        stem = Path(filename).stem.lower()
        text = content[:4000]

        signals: list[str] = []

        # ── Extension + filename baseline ─────────────────────────────────────
        ext_delta = 0.0
        if ext in _EXT_SCORES:
            ext_delta, sig = _EXT_SCORES[ext]
            signals.append(sig)
        if _BENIGN_FNAME_PATTERNS.search(stem):
            ext_delta -= 0.15
            signals.append("benign_filename")

        # ── Keyword Score (40%) ───────────────────────────────────────────────
        malware_kw  = self._score_keywords(text, _MALWARE_KEYWORDS,    signals)
        suspicious_kw = self._score_keywords(text, _SUSPICIOUS_KEYWORDS, signals)
        benign_kw   = self._score_keywords(text, _BENIGN_KEYWORDS,     signals)

        # ── Layer 0: Intent Null Check ────────────────────────────────────────
        # If the document intent is explicitly educational/documentation, bypass security pipeline
        # WHY separate is_educational flag: if the filename or benign keyword
        # signals are dominant, we force keyword_score to 0.0 BEFORE the
        # weighted formula runs. This prevents a certification guide that
        # mentions 'exploit' once from receiving a non-zero keyword contribution.
        is_educational = bool(_BENIGN_FNAME_PATTERNS.search(stem)) or (benign_kw > 0.5 and malware_kw < 0.3)
        if is_educational:
            signals.append("layer0_intent_bypass")
            keyword_score = 0.0  # Force benign

        # Raw keyword score: malware boosts, benign reduces
        if not is_educational:
            keyword_score = min(
                max(malware_kw * 1.0 + suspicious_kw * 0.4 - benign_kw * 0.6 + ext_delta, 0.0),
                1.0
            )

        # ── Entropy Score (30%) ───────────────────────────────────────────────
        entropy_score = _compute_entropy_score(text)
        if entropy_score > 0.4:
            signals.append(f"high_entropy:{entropy_score:.2f}")

        # ── Context Window Score (30%) ────────────────────────────────────────
        context_score = _compute_context_score(text, signals)

        # ── Weighted Final Score ──────────────────────────────────────────────
        final_score = (
            keyword_score * self.WEIGHTS["keyword"]
            + entropy_score * self.WEIGHTS["entropy"]
            + context_score * self.WEIGHTS["context"]
        )
        final_score = round(min(max(final_score, 0.0), 1.0), 4)

        # ── Threat Level Determination ────────────────────────────────────────
        if final_score < self.BENIGN_THRESHOLD:
            level = ThreatLevel.BENIGN
        elif final_score < self.MALICIOUS_THRESHOLD:
            level = ThreatLevel.SUSPICIOUS
        else:
            level = ThreatLevel.MALICIOUS

        # ── MITRE Triple-Gate (must pass ALL 3) ───────────────────────────────
        has_action_verbs    = bool(_ACTION_VERBS.search(text))
        has_exploit_context = bool(_EXPLOIT_CONTEXT.search(text))
        has_system_target   = bool(_SYSTEM_TARGET.search(text))
        
        if has_action_verbs:    signals.append("gate1:action_verbs")
        if has_exploit_context: signals.append("gate2:exploit_context")
        if has_system_target:   signals.append("gate3:system_target")

        # MITRE requires: score threshold + ALL 3 gates pass
        mitre_allowed = (
            final_score >= self.BENIGN_THRESHOLD
            and has_action_verbs
            and has_exploit_context
            and has_system_target
        )

        # IOC extraction: only for suspicious/malicious with meaningful score
        ioc_allowed = final_score >= self.BENIGN_THRESHOLD and malware_kw > 0.2

        # Deep CoT analysis: only for confirmed threat signals
        cot_allowed = final_score >= self.MALICIOUS_THRESHOLD or (
            final_score >= self.BENIGN_THRESHOLD and context_score > 0.3
        )

        # Final confidence = combination of score certainty + classifier confidence
        raw_confidence = min(abs(final_score - 0.375) * 2.5 + 0.5, 0.99)
        confidence = round((raw_confidence * 0.7) + (cls_confidence * 0.3), 3)

        reasoning = (
            f"final={final_score:.3f} [kw={keyword_score:.2f}×{self.WEIGHTS['keyword']} "
            f"ent={entropy_score:.2f}×{self.WEIGHTS['entropy']} "
            f"ctx={context_score:.2f}×{self.WEIGHTS['context']}] "
            f"level={level.value.upper()} "
            f"MITRE_gates=[{int(has_action_verbs)}{int(has_exploit_context)}{int(has_system_target)}]"
        )

        return ThreatScore(
            keyword_score    = round(keyword_score, 3),
            entropy_score    = round(entropy_score, 3),
            context_score    = round(context_score, 3),
            final_score      = final_score,
            has_action_verbs  = has_action_verbs,
            has_exploit_context = has_exploit_context,
            has_system_target = has_system_target,
            level            = level,
            confidence       = confidence,
            mitre_allowed    = mitre_allowed,
            ioc_allowed      = ioc_allowed,
            cot_allowed      = cot_allowed,
            signals          = signals,
            reasoning        = reasoning,
        )

    # SCORE KEYWORDS — accumulate weighted keyword match scores, capped at 1.0.
    # Args:    text: str           — content to scan.
    #          rules: list[tuple]  — list of (compiled_regex, weight, tag) tuples.
    #          signals: list       — mutable list; matched tags are appended.
    # Returns: float in [0.0, 1.0] — accumulated weighted score.
    # Side effects: appends matched tag strings to the signals list.
    @staticmethod
    def _score_keywords(
        text: str,
        rules: list[tuple[re.Pattern, float, str]],
        signals: list[str],
    ) -> float:
        total = 0.0
        for pattern, weight, tag in rules:
            if pattern.search(text):
                total += weight
                signals.append(tag)
        return min(total, 1.0)


# ── Module-level singleton ────────────────────────────────────────────────────
_scorer = ThreatScoringEngine()


# SCORE — public module-level API. Delegates to the module singleton.
# Args:    filename: str   — source file path.
#          content: str    — raw text content.
#          confidence: float — classifier confidence to blend into output.
# Returns: ThreatScore with full component breakdown.
def score_threat(filename: str, content: str, confidence: float = 0.6) -> ThreatScore:
    """
    Public API — compute hybrid threat score.
    Returns ThreatScore with full breakdown for transparency/debugging.
    """
    return _scorer.score(filename, content, confidence)


# Backward compatibility alias (for modules that import assess_threat)
# ASSESS — backward-compatibility alias for score_threat().
# Retained so that modules importing 'assess_threat' continue to work
# without modification after the rename from the legacy threat_level module.
def assess_threat(filename: str, content: str, confidence: float = 0.6) -> ThreatScore:
    return score_threat(filename, content, confidence)
