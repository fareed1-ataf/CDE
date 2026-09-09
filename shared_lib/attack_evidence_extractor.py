import re
from dataclasses import dataclass

@dataclass
class AttackEvidence:
    behavior: str
    techniques: list[str]
    code_snippet: str

class AttackEvidenceExtractor:
    """
    Validates MITRE techniques by finding actual code patterns (evidences)
    in the source text rather than relying directly on LLM extraction.

    v1.0.0: Expanded from 18 to 38+ patterns covering:
      - Windows/PowerShell malware
      - Linux/macOS attack patterns (NEW)
      - JavaScript web malware (NEW)
      - Python RAT patterns (NEW)
      - Advanced persistence and evasion
    """

    # Pattern -> Extracted Behavior -> Candidate MITRE Techniques
    BEHAVIOR_EXTRACTORS = [
        (r'(?i)subprocess\.run\([^)]*powershell', 
         "PowerShell execution via subprocess", 
         ["T1059.001", "T1059"]),
        
        (r'(?i)socket\.connect\([^)]+\)',
         "Outbound TCP connection established",
         ["T1071.001", "T1043", "T1071"]),
        
        (r'(?i)os\.chdir|os\.getcwd',
         "Directory traversal/discovery",
         ["T1083"]),
        
        (r'(?i)ctypes.*VirtualAlloc|VirtualAlloc.*ctypes',
         "Memory allocation with execute permissions",
         ["T1055"]),
        
        (r'(?i)base64\.b64decode.*exec|eval.*b64decode',
         "Base64 decode and execute pattern",
         ["T1027", "T1059"]),
         
        (r'(?i)requests\.(?:get|post|put|delete)\(',
         "HTTP/HTTPS request established",
         ["T1071.001", "T1105"]),
         
        (r'(?i)(?:net|ipconfig|whoami|systeminfo|tasklist|route)',
         "System information/network discovery commands",
         ["T1016", "T1033", "T1082", "T1049"]),
         
        (r'(?i)winreg|RegOpenKey|RegSetValue',
         "Registry modification",
         ["T1112", "T1547.001"]),
         
        (r'(?i)crontab|schtasks',
         "Scheduled task / cron job modification",
         ["T1053.003", "T1053.005", "T1053"]),
         
        # Phase 3 Expansion (15+ New Patterns)
        (r'(?i)CreateService|sc\.exe\s+create',
         "Service creation for persistence",
         ["T1543.003"]),
         
        (r'(?i)SetWindowsHookEx|GetAsyncKeyState',
         "Keylogging via Windows hooks",
         ["T1056.001"]),
         
        (r'(?i)ZwUnmapViewOfSection|NtUnmapViewOfSection',
         "Process hollowing preparation",
         ["T1055.012"]),
         
        (r'(?i)AES|Fernet|encrypt.*files',
         "File encryption (ransomware pattern)",
         ["T1486"]),
         
        (r'(?i)wevtutil.*cl|ClearEventLog',
         "Event log clearing (anti-forensics)",
         ["T1070.001"]),
         
        (r'(?i)NetUserAdd|net\s+user\s+.*\/add',
         "Local account creation",
         ["T1136.001"]),
         
        (r'(?i)WMI|Get-WmiObject|Invoke-WmiMethod',
         "Windows Management Instrumentation (WMI) execution",
         ["T1047"]),
         
        (r'(?i)vssadmin.*delete|bcdedit.*recoveryenabled\s+no',
         "Inhibit system recovery / delete shadow copies",
         ["T1490"]),
         
        (r'(?i)lsass\.exe|MiniDumpWriteDump|procdump',
         "LSASS memory dumping / credential access",
         ["T1003.001"]),
         
        (r'(?i)cmd\.exe\s+/c|%COMSPEC%',
         "Windows Command Shell execution",
         ["T1059.003"]),
         
        (r'(?i)Invoke-Mimikatz|sekurlsa::logonpasswords',
         "Mimikatz execution / credential dumping",
         ["T1003"]),
         
        (r'(?i)certutil\.exe\s+-urlcache\s+-split\s+-f',
         "Ingress tool transfer via certutil",
         ["T1105"]),
         
        (r'(?i)bitsadmin.*\/transfer',
         "BITS Jobs for ingress tool transfer",
         ["T1197", "T1105"]),
         
        (r'(?i)rundll32\.exe.*DllRegisterServer',
         "System binary proxy execution via rundll32",
         ["T1218.011"]),
         
        (r'(?i)regsvr32\.exe\s+/s\s+/u\s+/i:',
         "System binary proxy execution via regsvr32",
         ["T1218.010"]),
         
        (r'(?i)Import-Module|IEX.*DownloadString',
         "Reflective code loading / memory execution",
         ["T1620", "T1059.001"]),

        # Linux / macOS (v1.0.0 addition)
        (r'(?i)/etc/passwd|/etc/shadow|getpwnam',
         "Unix credential file access",
         ["T1003.008", "T1552.001"]),

        (r'(?i)chmod\s+[0-7]*[46][0-7]{2}|chmod\s+\+s',
         "SUID/SGID bit set — privilege escalation",
         ["T1548.001"]),

        (r'(?i)LD_PRELOAD|/etc/ld\.so\.preload',
         "Shared library hijacking (Linux)",
         ["T1574.006"]),

        (r'(?i)launchctl\s+load|Library/LaunchAgents',
         "macOS LaunchAgent persistence",
         ["T1543.001"]),

        (r'(?i)osascript\s+-e|do shell script',
         "macOS AppleScript execution",
         ["T1059.002"]),

        (r'(?i)curl\s+-[sS].*\|\s*(?:bash|sh)|wget.*-O-.*\|\s*(?:bash|sh)',
         "Download and pipe to shell execution",
         ["T1059.004", "T1105"]),

        (r'(?i)nc\s+-[le]|\bncat\b.*-[le]',
         "Netcat reverse/bind shell",
         ["T1059.004"]),

        # JavaScript / Web (v1.0.0 addition)
        (r'(?i)eval\s*\(\s*(?:atob|unescape|decodeURI)',
         "JavaScript eval with decoded payload",
         ["T1059.007", "T1027"]),

        (r'(?i)document\.write\s*\(\s*unescape',
         "JavaScript DOM injection with encoded payload",
         ["T1059.007"]),

        (r'(?i)XMLHttpRequest|fetch\s*\(\s*["\']https?://',
         "JavaScript outbound HTTP request",
         ["T1071.001"]),

        # Python RAT patterns (v1.0.0 addition)
        (r'(?i)paramiko|ssh\.connect\(',
         "SSH connection via paramiko",
         ["T1021.004"]),

        (r'(?i)keylogger|pynput\.keyboard|keyboard\.on_press',
         "Python keylogger",
         ["T1056.001"]),

        (r'(?i)subprocess\.Popen.*PIPE.*shell=True',
         "Shell subprocess with pipe (code exec pattern)",
         ["T1059.006"]),
    ]

    
    def extract(self, code: str) -> list[AttackEvidence]:
        """Returns a list of attack evidences with candidate MITRE techniques."""
        if not code:
            return []
            
        evidences = []
        for pattern, behavior, techniques in self.BEHAVIOR_EXTRACTORS:
            match = re.search(pattern, code)
            if match:
                evidences.append(AttackEvidence(
                    behavior=behavior,
                    techniques=techniques,
                    code_snippet=match.group(0)
                ))
        return evidences
    
    def validate_mitre_in_record(self, mitre_ids: list[str], code: str) -> tuple[list[str], list[str]]:
        """
        Compares claimed MITRE IDs against actual code evidences.
        Returns (validated_mitre_ids, stripped_mitre_ids)
        """
        evidences = self.extract(code)
        
        # Build a set of all supported techniques, plus their parent techniques
        supported_techniques = set()
        for e in evidences:
            for t in e.techniques:
                supported_techniques.add(t)
                # If T1059.001 is supported, T1059 is also supported
                if "." in t:
                    supported_techniques.add(t.split(".")[0])
        
        validated = []
        stripped = []
        
        for mitre_id in mitre_ids:
            # We enforce prefix matching as well for robustness
            mitre_id_upper = mitre_id.upper().strip()
            
            # Strict MITRE Validation
            if mitre_id_upper in code.upper():
                validated.append(mitre_id)
            elif mitre_id_upper in supported_techniques:
                validated.append(mitre_id)
            elif not evidences:
                stripped.append(mitre_id)
            else:
                # We could allow it if it shares a parent with a supported technique
                parent_id = mitre_id_upper.split(".")[0] if "." in mitre_id_upper else mitre_id_upper
                if parent_id in supported_techniques:
                    validated.append(mitre_id)
                else:
                    stripped.append(mitre_id)
                    
        return validated, stripped
