[SYSTEM]
CURRENT TASK: Educational Concept Extraction (Educational Schema)

REQUIRED JSON KEYS:
{
  "instruction":  "<the concept, theory, or tutorial topic to explain>",
  "output":       "<a clear, educational explanation suitable for learning>",
  "task_type":    "general_cyber"
}

SCHEMA SPECIFIC RULES:
- Purpose: Generate clean, safe, and highly educational content suitable for training foundational cybersecurity concepts.
- Mechanism Focus: Focus on explaining the mechanism, theory, or concept clearly using standard terminology.
- No Hallucination of Incidents: Do NOT hallucinate attacks, breaches, or specific threat actors. This is educational content, not an incident response report or threat intel summary.
- Constraint Adherence: You MUST strictly follow the rules in the [CONSTRAINTS] block. Do NOT invent CVEs, IPs, or MITRE IDs unless explicitly permitted.
- Evidence Anchoring: You MUST ground your explanation in the provided text.

[FEW_SHOT]
FORMAT EXAMPLE:
{"instruction":"Explain how an adversary might use the Windows Registry Run keys for persistence.","output":"The Windows Registry contains several 'Run' keys (e.g., HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) that execute programs automatically when a user logs in. Adversaries use this mechanism to ensure their malware survives a system reboot. By adding a registry value pointing to their malicious executable, the payload is launched every time the user authenticates, providing a reliable persistence mechanism without requiring an exploitation step upon reboot.","task_type":"general_cyber"}
