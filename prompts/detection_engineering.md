[SYSTEM]
CURRENT TASK: Detection Engineering Rule Generation (DetectionEngineering Schema)

REQUIRED JSON KEYS:
{
  "behavior_observed":   "<the specific attack behavior observed in the input>",
  "mitre_technique":     "<MITRE ATT&CK technique ID (e.g., T1059.001)>",
  "detection_rule":      "<the actual syntactically valid detection rule code>",
  "rule_format":         "<YARA|Sigma|KQL|SPL|Sysmon_XML>",
  "false_positive_risk": "<high|medium|low>",
  "tuning_notes":        "<instructions on how an analyst should tune this rule in production>",
  "task_type":           "<detection_engineering>"
}

SCHEMA SPECIFIC RULES:
- Rule Validity: The `detection_rule` must be syntactically valid for the specified `rule_format`. Do not invent fake syntax.
- Behavior Match: The rule must accurately match the specific behavior observed in the input, not a generic catch-all.
- FP Risk: Be honest about false positive risk. If a rule relies on a common LOLBin without command-line arguments, the FP risk is HIGH.
- If the input does not contain a discernible attack behavior that can be written into a rule, return {"error": "no_detectable_behavior"}.

[FEW_SHOT]
FORMAT EXAMPLE:
{"behavior_observed":"A PowerShell script downloading a payload using Net.WebClient and executing it entirely in memory using IEX.","mitre_technique":"T1059.001","detection_rule":"title: Suspicious PowerShell Download and Execute\nid: 9a8b7c6d-1234-4567-890a-bcdef1234567\nstatus: experimental\ndescription: Detects PowerShell downloading and executing a script in memory using IEX.\nlogsource:\n    product: windows\n    service: sysmon\ndetection:\n    selection:\n        EventID: 1\n        Image|endswith: '\\powershell.exe'\n        CommandLine|contains|all:\n            - 'Net.WebClient'\n            - 'DownloadString'\n            - 'IEX'\n    condition: selection\nfields:\n    - CommandLine\n    - ParentImage\nfalsepositives:\n    - Legitimate administrative scripts updating modules.\nlevel: high","rule_format":"Sigma","false_positive_risk":"medium","tuning_notes":"If legitimate admin scripts use this pattern, exclude specific ParentImage values (e.g., specific management software agents) or require the presence of obfuscation flags (-enc, -nop) to trigger the alert.","task_type":"detection_engineering"}
