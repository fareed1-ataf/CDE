[SYSTEM]
CURRENT TASK: Security Code Review Dataset Generation (CodeReview Schema)

REQUIRED JSON KEYS:
{
  "code":              "<exact code from the source input>",
  "language":          "<language name>",
  "vulnerabilities":   [
    {
      "line_ref":  "<line number or function name>",
      "vuln_type": "<specific flaw class>",
      "cwe_id":    "<CWE ID>",
      "severity":  "<HIGH|MEDIUM|LOW|INFO>",
      "fix":       "<brief description of the fix>"
    }
  ],
  "overall_risk":      "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
  "summary":           "<expert security analysis: explain root causes and impact>",
  "secure_version":    "<corrected code with the vulnerability fixed — syntactically valid>"
}

SCHEMA SPECIFIC RULES:
- Root Cause Analysis: Explain the exact line causing the vulnerability and WHY it is exploitable in the summary.
- Fix Quality: The secure_version must actually fix the root cause, not just add a comment. Use the correct secure API or pattern.
- If the code is secure: vulnerabilities=[], overall_risk="INFO", secure_version="" (empty string).

[FEW_SHOT]
FORMAT EXAMPLE:
{"code":"@app.route('/user')\ndef get_user():\n    username = request.args.get('username')\n    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n    cursor.execute(query)\n    return cursor.fetchall()","language":"Python","vulnerabilities":[{"line_ref":"line 4","vuln_type":"SQL Injection","cwe_id":"CWE-89","severity":"CRITICAL","fix":"Use parameterized queries instead of string formatting to prevent user input from modifying the SQL logic"}],"overall_risk":"CRITICAL","summary":"The application is vulnerable to SQL Injection. By directly concatenating the user-controlled 'username' parameter into the SQL query string using an f-string, an attacker can input crafted SQL payloads (e.g., ' OR 1=1 --) to alter the query logic. This allows bypassing authentication, reading arbitrary database records, or potentially executing destructive operations.","secure_version":"@app.route('/user')\ndef get_user():\n    username = request.args.get('username')\n    query = \"SELECT * FROM users WHERE username = %s\"\n    cursor.execute(query, (username,))\n    return cursor.fetchall()"}
