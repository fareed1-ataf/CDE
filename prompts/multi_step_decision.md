[SYSTEM]
CURRENT TASK: Multi-Step Decision Making (MultiStepDecision Schema)

REQUIRED JSON KEYS:
{
  "trigger_event":          "<the initial alert, observation, or finding that starts the process>",
  "observations":           ["<list of specific observable facts from the input>"],
  "reasoning_chain": [
    {
      "step": <integer>,
      "observation": "<specific fact>",
      "inference": "<what this fact means in context>",
      "confidence": "<high|medium|low>"
    }
  ],
  "final_decision":         "<the ultimate security decision (e.g., 'Isolate Host', 'Mark as False Positive')>",
  "decision_rationale":     "<summary of why the decision was made based on the chain>",
  "alternative_considered": "<an alternative decision that was rejected and why>",
  "task_type":              "<incident_response|malware_analysis|log_analysis>"
}

SCHEMA SPECIFIC RULES:
- Chain Logic: Each step in the reasoning_chain must logically build towards the final decision.
- Inference: Don't just restate the observation. State the *inference* (e.g., Obs: "Encoded PowerShell", Inf: "Attempt to bypass AMSI or static signatures").
- Decision: The final_decision must be a definitive action or classification, not a vague "continue monitoring".
- If the input does not contain enough information to form a logical decision chain, return {"error": "insufficient_data_for_decision"}.

[FEW_SHOT]
FORMAT EXAMPLE:
{"trigger_event":"CrowdStrike alert for unusual volume of SMB traffic originating from a developer workstation.","observations":["Workstation DEV-PC-01 connected to 45 unique internal endpoints via port 445 in 10 minutes.","No prior history of this workstation acting as an admin or scanner.","A process named 'svchost.exe' is running out of C:\\Users\\Public\\Downloads."],"reasoning_chain":[{"step":1,"observation":"High volume of SMB (port 445) traffic to multiple hosts","inference":"This matches network scanning or lateral movement propagation behavior (e.g., worm, ransomware).","confidence":"high"},{"step":2,"observation":"No prior scanning history from this host","inference":"The activity is anomalous and not part of a scheduled vulnerability scan.","confidence":"high"},{"step":3,"observation":"'svchost.exe' running from C:\\Users\\Public\\Downloads","inference":"svchost.exe should only execute from System32. Execution from a public writable folder is a classic masquerading technique (T1036.005).","confidence":"high"}],"final_decision":"Isolate DEV-PC-01 immediately and initiate incident response playbook for lateral movement.","decision_rationale":"The combination of anomalous SMB scanning and a masqueraded svchost.exe binary strongly indicates an active compromise attempting lateral movement.","alternative_considered":"Considered marking as an unauthorized user scan, but the masqueraded binary elevates this to an active malware incident rather than a policy violation.","task_type":"incident_response"}
