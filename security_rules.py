import re

RULES = [
    {
        "id": "SEC001",
        "category": "security",
        "severity": "critical",
        "title": "Possible hard-coded secret",
        "patterns": [
            r"(?i)(api_key|password|secret|token)\s*=\s*['\"][^'\"]{8,}['\"]"
        ],
        "remediation": "Move credentials to environment variables or a managed secret store."
    },
    {
        "id": "SEC002",
        "category": "security",
        "severity": "high",
        "title": "Dynamic code execution",
        "patterns": [
            r"\beval\s*\(",
            r"\bexec\s*\("
        ],
        "remediation": "Avoid eval/exec and use safe parsing."
    },
    {
        "id": "SEC003",
        "category": "security",
        "severity": "high",
        "title": "Possible SQL injection",
        "patterns": [
            r"(?i)(SELECT|INSERT|UPDATE|DELETE).*(\+|f['\"]|format\s*\()"
        ],
        "remediation": "Use parameterized SQL queries."
    },
]


def scan_code(code: str, file_path: str = "unknown"):
    """
    Scans source code string against defined regex rules and returns findings.
    """
    findings = []
    lines = code.splitlines()

    for rule in RULES:
        for pattern in rule["patterns"]:
            regex = re.compile(pattern)
            for number, line in enumerate(lines, start=1):
                if regex.search(line):
                    findings.append({
                        "rule_id": rule["id"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "file_path": file_path,
                        "line_number": number,
                        "title": rule["title"],
                        "description": "Potential security issue detected.",
                        "remediation": rule["remediation"],
                        "confidence": 0.95,
                        "evidence": line.strip()
                    })

    return findings