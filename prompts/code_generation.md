[SYSTEM]
CURRENT TASK: Code Generation Dataset Generation (CodeGen Schema)

REQUIRED JSON KEYS:
{
  "instruction": "<precise task: what code to write and for what purpose>",
  "input":       "<the source context: existing code, report, behavior description, or tool specification>",
  "code":        "<syntactically valid, functionally correct code — no markdown fences>",
  "language":    "<python|powershell|c|bash|yara|go|javascript|...>",
  "task_type":   "<malware_analysis|threat_intel|vulnerability|incident_response|cti_qa|general_cyber>"
}

SCHEMA SPECIFIC RULES:
- Code Quality: Generated code MUST be syntactically valid and functionally correct. Test it mentally before outputting.
- Purpose Alignment: The code must directly serve the task stated in the instruction (e.g., a YARA rule, a detector script, a PoC for a vulnerability class).
- Offensive/Defensive Balance: You may generate red-team tools (shellcode loaders, persistence scripts) for training purposes, and blue-team detectors (YARA rules, log parsers, EDR queries). Be technically accurate in both cases.
- No placeholder logic: No TODO comments, no stub functions that do nothing.

[FEW_SHOT]
FORMAT EXAMPLE:
{"instruction":"Write a YARA rule to detect the Python shellcode loader pattern from this sample.","input":"import ctypes, base64\nshellcode = base64.b64decode('...')\nbuf = ctypes.create_string_buffer(shellcode)\nptr = ctypes.cast(buf, ctypes.c_void_p)\nctypes.windll.kernel32.VirtualAlloc(0, len(buf), 0x3000, 0x40)\nctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)","code":"rule Python_Shellcode_Loader {\n    meta:\n        description = \"Detects Python-based shellcode loaders using ctypes VirtualAlloc+CreateThread pattern\"\n        severity = \"CRITICAL\"\n        technique = \"T1059.006, T1055\"\n    strings:\n        $api1 = \"VirtualAlloc\" ascii\n        $api2 = \"CreateThread\" ascii\n        $lib1 = \"ctypes\" ascii\n        $enc1 = \"base64.b64decode\" ascii\n        $enc2 = \"b64decode\" ascii\n    condition:\n        $lib1 and $api1 and $api2 and (1 of ($enc*))\n}","language":"yara","task_type":"malware_analysis"}
