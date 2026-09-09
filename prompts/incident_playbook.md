[SYSTEM]
CURRENT TASK: Incident Playbook Dataset Generation (Playbook Schema)

REQUIRED JSON KEYS:
{
  "trigger": "<specific alert, indicator, or event that initiates this playbook>",
  "investigation_steps": [
    "<actionable step: specific log query, command, or check to perform>"
  ],
  "remediation_steps": [
    "<actionable fix: specific command, configuration change, or containment action>"
  ],
  "task_type": "<incident_response>"
}

SCHEMA SPECIFIC RULES:
- Trigger Precision: Must be a specific, detectable event — not "suspicious activity". Example: "Sysmon Event ID 1 showing PowerShell.exe with -enc flag spawned by Word.exe".
- Investigation Steps: Use specific tools and queries (e.g., Windows Event Log queries, SIEM searches, memory forensics commands). Be concrete.
- Remediation Steps: Specific, executable actions. Name the exact command or configuration. Use your expert knowledge to provide the technically correct remediation.
- If the input lacks sufficient incident context to build a meaningful playbook, return: {"error": "insufficient_incident_context"}.

[FEW_SHOT]
FORMAT EXAMPLE:
{"trigger":"EDR alert: powershell.exe spawned with '-enc' flag by winword.exe on an endpoint — potential macro-based dropper execution.","investigation_steps":["Query Sysmon Event ID 1 for process creation: ParentImage=winword.exe AND Image=powershell.exe to confirm parent-child relationship and capture full command line","Decode the Base64 payload from the -enc argument: [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<encoded_string>'))","Check Sysmon Event ID 3 (NetworkConnect) from the powershell.exe PID for outbound connections to identify C2 IP","Inspect %TEMP% and %APPDATA% directories on the affected host for dropped payloads using: dir /a /s C:\\Users\\%USERNAME%\\AppData","Pull recent process memory dump of the PowerShell process for YARA scanning: procdump -ma <PID> powershell.dmp"],"remediation_steps":["Isolate the affected endpoint from the network immediately via EDR host isolation feature","Kill the suspicious PowerShell process: Stop-Process -Id <PID> -Force","Revoke and reset credentials of the logged-in user — assume credential theft if C2 contact was confirmed","Block the identified C2 IP/domain at the perimeter firewall and proxy","Disable macro execution in Office via Group Policy: User Configuration > Administrative Templates > Microsoft Word > Block macros from running in Office files from the internet"],"task_type":"incident_response"}
