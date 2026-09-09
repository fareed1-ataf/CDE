[SYSTEM]
CURRENT TASK: Q&A Pair Extraction (QA Schema)

REQUIRED JSON KEYS:
{
  "pairs": [
    {
      "question":   "<precise technical question — prefer HOW/WHY/WHAT MECHANISM over WHAT IS>",
      "context":    "<the relevant excerpt from the input that makes this question answerable>",
      "answer":     "<expert-level, self-contained answer — explain mechanism, not just label>",
      "difficulty": "<easy|medium|hard>"
    }
  ]
}

SCHEMA SPECIFIC RULES:
- Quantity: Generate 4-5 pairs per input.
- Expert Answers: Answers must explain the technical mechanism. Use your cybersecurity expertise to provide depth (e.g., explain WHY a technique evades detection, HOW a buffer overflow is triggered, WHAT the attacker achieves).
- Difficulty Contract:
  - EASY → Single fact, answered from one line of the input.
  - MEDIUM → Requires connecting 2 observable facts or explaining a mechanism.
  - HARD → Requires synthesizing 3+ facts, explaining WHY it works, or comparing techniques. Must be verifiable against the input.
- No Duplication: Each question MUST target a distinct concept. No paraphrasing the same question.
- Answer Independence: Answers must be readable and complete without needing to see the context.
- Evidence Anchoring: You MUST quote exact tokens from the context in your answer when making technical claims using [EVIDENCE: 'exact quote'].
- Strict Answerability: ONLY generate questions where the full, definitive answer is present in the context. NEVER generate a question that requires you to say "without further context it is unclear" or "it is not explicitly stated". If a text excerpt is useless, do not generate a question for it.
- Constraint Adherence: You MUST strictly follow the rules in the [CONSTRAINTS] block. Do NOT hallucinate content.

[FEW_SHOT]
FORMAT EXAMPLE:
{"pairs":[{"question":"Why does UMBRELLA STAND use fake TLS headers instead of real TLS for its C2 channel?","context":"UMBRELLA STAND beacons to its C2 server using communications prefixed with a fake TLS header before the encrypted message. The actual payload is encrypted using AES in CBC mode with a hardcoded key.","answer":"UMBRELLA STAND uses a fake TLS header (T1001.003 — Data Obfuscation: Protocol Impersonation) to make its C2 traffic superficially resemble legitimate HTTPS traffic and evade network-layer inspection tools that match on protocol signatures. However, it does not implement the actual TLS handshake, because doing so would require a valid certificate chain and add complexity. The actual confidentiality is provided by AES-CBC encryption with a hardcoded key. This means a network monitor that performs TLS fingerprinting (e.g., JA3) or deep packet inspection would detect the absence of a real TLS handshake and identify it as anomalous.","difficulty":"hard"},{"question":"What encryption algorithm and mode does UMBRELLA STAND use for its beaconing traffic?","context":"The actual payload is encrypted using AES in CBC mode with a hardcoded key and IV.","answer":"UMBRELLA STAND encrypts its C2 beacon payload using AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode. Both the key and the initialization vector (IV) are hardcoded in the binary, which means an analyst who extracts these values from a sample can decrypt all captured C2 traffic retroactively.","difficulty":"medium"}]}
