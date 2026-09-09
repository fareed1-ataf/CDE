[SYSTEM]
CURRENT TASK: Digital Forensics Timeline Generation (ForensicTimeline Schema)

REQUIRED JSON KEYS:
{
  "artifact_type":          "<memory_dump|disk_image|log_file|pcap|registry_hive>",
  "artifact_path":          "<the path or source of the artifact from the input>",
  "extraction_command":     "<exact command used to extract the findings (e.g., volatility command, logparser)>",
  "findings": [
    {
      "timestamp":    "<timestamp of the event>",
      "artifact":     "<the specific artifact found (e.g., a process name, a registry key, a file path)>",
      "significance": "<why this artifact matters>",
      "mitre_ref":    "<MITRE ATT&CK ID>"
    }
  ],
  "timeline_summary":       "<expert summary of the sequence of events>",
  "attribution_confidence": "<high|medium|low|none>",
  "task_type":              "<forensics>"
}

SCHEMA SPECIFIC RULES:
- Timestamps: Extract precise timestamps if available in the input. If not, use relative terms (e.g., "T+0", "Post-infection").
- Extraction Command: Be precise with the tool used to extract the data (e.g., `volatility -f mem.raw --profile=Win10x64_19041 pslist`).
- Significance: Explain *why* the finding is malicious or relevant to the investigation.
- If the input does not contain forensic artifacts or timeline data, return {"error": "no_forensic_data"}.

[FEW_SHOT]
FORMAT EXAMPLE:
{"artifact_type":"memory_dump","artifact_path":"WIN-SRV01-MemDump.raw","extraction_command":"volatility3 -f WIN-SRV01-MemDump.raw windows.malfind","findings":[{"timestamp":"2023-10-27 14:02:11 UTC","artifact":"svchost.exe (PID 4512)","significance":"Process contains an unbacked executable memory region with an MZ header, indicating injected code.","mitre_ref":"T1055.012"},{"timestamp":"2023-10-27 14:02:15 UTC","artifact":"Network connection to 198.51.100.44:443","significance":"The injected svchost.exe initiated an outbound HTTPS connection to a known C2 server.","mitre_ref":"T1071.001"}],"timeline_summary":"The timeline reveals that an attacker successfully injected a malicious payload into a legitimate svchost.exe process (PID 4512) at 14:02:11 UTC. Four seconds later, this process established a command and control channel to 198.51.100.44 over HTTPS, bypassing standard process-based network filtering.","attribution_confidence":"medium","task_type":"forensics"}
