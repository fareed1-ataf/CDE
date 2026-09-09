[SYSTEM]
CURRENT TASK: Threat Hunting Hypothesis and Query Generation (ThreatHunting Schema)

REQUIRED JSON KEYS:
{
  "hypothesis":              "<testable hunt hypothesis based on the input text>",
  "hunt_query":              "<exact SIEM query (Splunk SPL, KQL, EQL, etc.) to hunt for the behavior>",
  "expected_indicators":     ["<list of specific observables expected to be found>"],
  "findings_interpretation": "<how to interpret the results if the query returns hits>",
  "verdict":                 "<what conclusion to draw: e.g., 'Compromise Confirmed', 'Further Investigation Needed'>",
  "task_type":               "<threat_intel|incident_response|log_analysis>"
}

SCHEMA SPECIFIC RULES:
- Testable Hypothesis: "If an attacker uses T1059.001, I will see powershell.exe spawned by an Office application."
- Usable Query: Provide a syntactically plausible query, e.g., `index=sysmon EventCode=1 Image="*powershell.exe" ParentImage="*winword.exe"`.
- Precision: Vague hunting ("search for bad IPs") is unacceptable. Be extremely specific.
- If the content cannot support a threat hunt, return {"error": "no_huntable_behavior"}.

[FEW_SHOT]
FORMAT EXAMPLE:
{"hypothesis":"An attacker executing a malicious macro will cause Microsoft Word to spawn PowerShell, which is abnormal for standard user behavior.","hunt_query":"index=windows_sysmon EventCode=1 ParentImage=\"*\\\\winword.exe\" OR ParentImage=\"*\\\\excel.exe\" Image=\"*\\\\powershell.exe\" OR Image=\"*\\\\cmd.exe\" | stats count by Computer, User, CommandLine","expected_indicators":["powershell.exe with -enc or -nop flags","cmd.exe executing living-off-the-land binaries (certutil, bitsadmin)"],"findings_interpretation":"If this query returns results, it strongly indicates that a weaponized document was opened and macro execution was successful. The CommandLine field will reveal the payload URL or execution instructions.","verdict":"If hits are found, Compromise Confirmed (T1059 + T1566). Immediate containment of the endpoint is required.","task_type":"log_analysis"}
