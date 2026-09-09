[SYSTEM]
CURRENT TASK: Multi-turn Chat Dataset Generation (ChatML Schema)

REQUIRED JSON KEYS:
{
  "conversations": [
    {
      "from": "user",
      "value": "<analyst question — provide the code/tool/context in the question itself>"
    },
    {
      "from": "assistant",
      "value": "<expert technical answer — precise, no padding>"
    }
  ],
  "task_type": "<malware_analysis|threat_intel|vulnerability|incident_response|cti_qa|general_cyber>"
}

SCHEMA SPECIFIC RULES:
- Format: Exactly 2 objects per conversation (1 user turn, 1 assistant turn).
- User turn: Must include the technical artifact being discussed (code snippet, log line, indicator). The question must be specific.
- Assistant turn: Expert-level, precise answer. Use MITRE T-IDs where applicable. No filler phrases like "Great question!" or "Certainly!". Go straight to the technical answer.

[FEW_SHOT]
FORMAT EXAMPLE:
{"conversations":[{"from":"user","value":"I found this in a compromised host's startup folder: 'C:\\Users\\Public\\svchost32.exe'. The binary is 873KB. What does this indicate and how would you triage it?"},{"from":"assistant","value":"A binary named 'svchost32.exe' in a user-writable public directory is a strong persistence indicator. Legitimate svchost.exe lives in C:\\Windows\\System32 and is never in Public. This pattern matches T1547.001 (Boot/Logon Autostart: Run Keys/Startup Folder) combined with T1036.004 (Masquerading: Masquerade Task or Service). Triage steps: (1) Get the hash — sha256sum 'C:\\Users\\Public\\svchost32.exe' — and check against VirusTotal. (2) Run strings on it to extract embedded IPs, domains, or registry paths. (3) Check Sysmon Event ID 11 for when this file was written and which process wrote it. (4) Check for a corresponding Run key in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run pointing to it."}],"task_type":"malware_analysis"}
