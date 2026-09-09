[SYSTEM]
CURRENT TASK: Instruction-Following Dataset Generation (Alpaca Schema)

REQUIRED JSON KEYS:
{
  "instruction": "<precise analyst question or task — specific to the behavior observed in this content>",
  "input":       "<the source content: paste the relevant code, command, or text excerpt>",
  "output":      "<expert-level, technically accurate response — explain the behavior, purpose, technique, and implications>",
  "task_type":   "<malware_analysis|threat_intel|vulnerability|incident_response|cti_qa|general_cyber>"
}

SCHEMA SPECIFIC RULES:
- Analytical Depth: The output MUST demonstrate expert reasoning — explain HOW and WHY, not just WHAT.
- MITRE Inference: If the code/behavior maps to a MITRE technique, state the T-ID and justify it with a specific observable from the input (API call, command, pattern).
- Input field: Must contain the exact source content being analyzed. Never leave empty for analysis tasks.
- Output precision: Every technical claim must be justified by something observable in the input or directly derivable from your expert analysis of it. No random additions.

[FEW_SHOT]
FORMAT EXAMPLE:
{"instruction":"Explain the persistence mechanism and its evasion technique in this PowerShell code.","input":"$RegPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'\nNew-ItemProperty -Path $RegPath -Name 'svchost32' -Value \"C:\\Users\\Public\\payload.exe\" -PropertyType String -Force\n[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.CSharp') | Out-Null","output":"This script establishes persistence using a Registry Run key (T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder). The malware writes a value named 'svchost32' — a name chosen to masquerade as a legitimate Windows process — pointing to a payload at C:\\Users\\Public\\payload.exe, a world-writable directory that doesn't require elevated privileges. The secondary line loads the Microsoft.CSharp assembly using reflection (T1620 — Reflective Code Loading), a technique used to execute code in-memory and evade static detection tools that scan the filesystem. Detection: Monitor Sysmon Event ID 13 (RegistryValueSet) on HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run for unexpected process names.","task_type":"malware_analysis"}
