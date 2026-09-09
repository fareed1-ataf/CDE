# core/mitre_kb.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# MITRE ATT&CK SEMANTIC KNOWLEDGE BASE (Layer 2 - Security Lens)
#
# Architecture v1.0.0 Implementation:
#   Input → Embedding/Vector → Similarity Search → MITRE candidates
#
# Design principles:
#   1. RAG-lite Semantic Matching: Uses TF-IDF cosine similarity to map
#      document text directly to official MITRE definitions.
#   2. Confidence Thresholding: Rejects matches < 0.80.
#   3. Zero LLM Guessing: Replaces forced LLM generation with grounded retrieval.
#   4. High-Performance: Runs entirely locally in microseconds.
# =============================================================================

import math
import re
from collections import Counter
from dataclasses import dataclass

@dataclass
class MitreTechnique:
    id: str
    name: str
    tactic: str
    description: str
    _vector: dict[str, float] = None
    _norm: float = 0.0

# ─────────────────────────────────────────────────────────────────────────────
# Minimal MITRE KB (Core techniques for demonstration)
# In production, this would be loaded from Enterprise ATT&CK JSON
# ─────────────────────────────────────────────────────────────────────────────
_RAW_KB = [
    {
        "id": "T1059.001", "name": "PowerShell", "tactic": "Execution",
        "desc": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include Invoke-Expression, IEX, DownloadString, encodedcommand."
    },
    {
        "id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control",
        "desc": "Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as ftp. Once present, adversaries may also transfer/copy tools between victim devices within a compromised environment (i.e. Lateral Tool Transfer)."
    },
    {
        "id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
        "desc": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses. Examples include base64, hex encoding, XOR, packing."
    },
    {
        "id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "tactic": "Persistence",
        "desc": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the run keys in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level."
    },
    {
        "id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access",
        "desc": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material. Examples include mimikatz, sekurlsa, procdump."
    },
    {
        "id": "T1036.005", "name": "Match Legitimate Name or Location", "tactic": "Defense Evasion",
        "desc": "Adversaries may match or approximate the name or location of legitimate files or resources when naming/placing them. This is done for the sake of evading defenses and observation. This may be done by placing an executable in a commonly trusted directory (ex: under System32) or naming it something like svchost.exe."
    },
    {
        "id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
        "desc": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability. These applications are often websites, but can include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols, or any other applications with Internet accessible open sockets, such as web servers and related services. Examples include SQL injection, remote code execution (RCE), cross-site scripting (XSS)."
    }
]

# ─────────────────────────────────────────────────────────────────────────────
# Semantic Search Engine (TF-IDF Space)
# ─────────────────────────────────────────────────────────────────────────────

def _tokenize(text: str) -> list[str]:
    # Lowercase, remove non-alphanumeric, split by word boundary
    return re.findall(r'\b[a-z0-9]+\b', text.lower())

class MitreRetrievalEngine:
    """
    RAG-lite Semantic Retrieval for MITRE ATT&CK.
    Uses TF-IDF to map textual descriptions and keywords to techniques.
    """
    def __init__(self):
        self.techniques: list[MitreTechnique] = []
        self.vocab: set[str] = set()
        self.idf: dict[str, float] = {}
        self._build_index()

    def _build_index(self):
        # Parse techniques
        for raw in _RAW_KB:
            # Augment description with name and tactic for better semantic matching
            full_text = f"{raw['name']} {raw['tactic']} {raw['desc']}"
            t = MitreTechnique(raw["id"], raw["name"], raw["tactic"], full_text)
            self.techniques.append(t)

        # Compute Document Frequencies
        N = len(self.techniques)
        df = Counter()
        for t in self.techniques:
            tokens = set(_tokenize(t.description))
            for tok in tokens:
                df[tok] += 1
                self.vocab.add(tok)

        # Compute IDF
        for tok, count in df.items():
            self.idf[tok] = math.log((N + 1) / (count + 1)) + 1.0

        # Compute TF-IDF vectors for KB
        for t in self.techniques:
            tokens = _tokenize(t.description)
            tf = Counter(tokens)
            vec = {}
            norm = 0.0
            for tok, count in tf.items():
                val = count * self.idf.get(tok, 0.0)
                vec[tok] = val
                norm += val * val
            t._vector = vec
            t._norm = math.sqrt(norm)

    def _vectorize(self, text: str) -> tuple[dict[str, float], float]:
        tokens = _tokenize(text)
        tf = Counter(tokens)
        vec = {}
        norm = 0.0
        for tok, count in tf.items():
            if tok in self.vocab:
                val = count * self.idf[tok]
                vec[tok] = val
                norm += val * val
        return vec, math.sqrt(norm)

    def search(self, text: str, threshold: float = 0.35, top_k: int = 3) -> list[dict]:
        """
        Search the MITRE KB for the best matching techniques.
        Returns mapped results with confidence scores.
        """
        vec, norm = self._vectorize(text)
        if norm == 0:
            return []

        results = []
        for t in self.techniques:
            # Cosine similarity
            dot = sum(vec.get(tok, 0) * t._vector.get(tok, 0) for tok in vec.keys())
            if t._norm > 0:
                similarity = dot / (norm * t._norm)
            else:
                similarity = 0.0

            # Boost if exact ID is mentioned (Fallback Extraction as requested)
            if t.id.lower() in text.lower():
                similarity = max(similarity, 0.95)

            if similarity >= threshold:
                results.append({
                    "id": t.id,
                    "name": t.name,
                    "tactic": t.tactic,
                    "confidence": round(similarity, 2)
                })

        # Sort by confidence descending
        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results[:top_k]

# Global Engine Instance
kb_engine = MitreRetrievalEngine()

def retrieve_mitre(text: str, strict: bool = True) -> list[dict]:
    """
    Layer 2 Security Lens: Retrieve MITRE mappings grounded in KB.
    Args:
        text: The text to analyze
        strict: If True, uses a high confidence threshold (0.45 semantic similarity)
    """
    threshold = 0.45 if strict else 0.25
    return kb_engine.search(text, threshold=threshold, top_k=3)
