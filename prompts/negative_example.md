[SYSTEM]
CURRENT TASK: Negative Example Generation (NegativeExample Schema)

REQUIRED JSON KEYS:
{
  "incorrect_analysis":      "<a plausible but incorrect or hallucinated analysis of the input>",
  "why_wrong":               "<expert explanation of why the incorrect analysis is technically wrong>",
  "correct_analysis":        "<the accurate analysis based strictly on the input>",
  "common_mistake_category": "<mitre_misattribution|hallucinated_ioc|wrong_severity|missed_technique>",
  "task_type":               "<malware_analysis|threat_intel|vulnerability|incident_response>"
}

SCHEMA SPECIFIC RULES:
- Plausible Inaccuracy: The `incorrect_analysis` should look like a mistake a junior analyst or a hallucinating LLM would make (e.g., claiming a script connects to an IP that isn't actually in the script).
- Pedagogical Correction: The `why_wrong` field must explicitly teach the model *how* to avoid this mistake.
- Ground Truth: The `correct_analysis` must be perfectly grounded in the input.
- If the input is too simple to generate a meaningful negative example, return {"error": "input_too_simple"}.

[FEW_SHOT]
FORMAT EXAMPLE:
{"incorrect_analysis":"This PowerShell script is ransomware. It encrypts files on the disk using AES and then deletes the volume shadow copies to prevent recovery. The MITRE technique is T1486 (Data Encrypted for Impact).","why_wrong":"The input script does contain the word 'encrypt', but a close reading shows it is encrypting its own payload in memory to evade detection, not encrypting user files. There is no code that deletes shadow copies. The incorrect analysis hallucinated ransomware behavior based on a single keyword.","correct_analysis":"The script uses AES to decrypt an embedded payload in memory before executing it. This is a defense evasion technique (T1027 - Obfuscated Files or Information), not ransomware. It does not interact with user files or shadow copies.","common_mistake_category":"hallucinated_ioc","task_type":"malware_analysis"}
