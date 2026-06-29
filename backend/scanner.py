import re

# ---------------------------------------------------------------------------
# Rule-based SAST engine.
# Each rule = (rule_id, regex_pattern, human message, raw_severity)
# Patterns are intentionally simple/readable so they're easy to extend.
# ---------------------------------------------------------------------------

COMMON_RULES = [
    (
        "hardcoded-credential",
        re.compile(r"""(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*['"][^'"]{3,}['"]""", re.IGNORECASE),
        "Hardcoded credential or secret found in source code.",
        "ERROR",
    ),
    (
        "sql-injection-string-concat",
        re.compile(r"""(SELECT|INSERT|UPDATE|DELETE)\b.{0,80}['"]\s*\+|\+\s*['"].{0,40}(SELECT|INSERT|UPDATE|DELETE)\b""", re.IGNORECASE),
        "SQL query appears to be built using string concatenation, which can lead to SQL injection.",
        "ERROR",
    ),
    (
        "command-injection",
        re.compile(r"""\b(os\.system|os\.popen|subprocess\.call|subprocess\.run|exec|child_process\.exec)\s*\("""),
        "Potential command injection: user-influenced input passed to a shell/command execution function.",
        "ERROR",
    ),
    (
        "insecure-eval",
        re.compile(r"""\b(eval|exec)\s*\("""),
        "Use of eval()/exec() can allow arbitrary code execution if input is not strictly controlled.",
        "WARNING",
    ),
    (
        "weak-hash",
        re.compile(r"""\b(md5|sha1)\s*\(""", re.IGNORECASE),
        "Use of a weak/broken hashing algorithm (MD5/SHA1) for security-sensitive purposes.",
        "WARNING",
    ),
    (
        "insecure-deserialization",
        re.compile(r"""\b(pickle\.loads|yaml\.load\s*\((?!.*Loader)|ObjectInputStream)\b"""),
        "Insecure deserialization of untrusted data can lead to remote code execution.",
        "ERROR",
    ),
    (
        "debug-mode-enabled",
        re.compile(r"""\bDEBUG\s*=\s*True\b"""),
        "Debug mode appears to be enabled, which can leak sensitive information in production.",
        "WARNING",
    ),
    (
        "insecure-random",
        re.compile(r"""\bMath\.random\(\)|\brandom\.random\(\)"""),
        "Use of a non-cryptographic random generator for what may be a security-sensitive value.",
        "INFO",
    ),
    (
        "disabled-tls-verification",
        re.compile(r"""verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"""),
        "TLS/SSL certificate verification appears to be disabled.",
        "ERROR",
    ),
    (
        "open-redirect-or-xss-sink",
        re.compile(r"""innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML"""),
        "Potential XSS sink: untrusted data may be rendered directly into the DOM/HTML.",
        "WARNING",
    ),
]

LANGUAGE_LABEL = {
    "python": "Python",
    "javascript": "JavaScript",
    "typescript": "TypeScript",
    "java": "Java",
}


def run_semgrep(code: str, language: str):
    """
    Scans the given code string against a built-in set of vulnerability
    patterns and returns a normalized list of findings:
    [{ "line": int, "rule": str, "message": str, "raw_severity": str, "snippet": str }]

    Named run_semgrep for compatibility with the rest of the app, but this
    is a pure-Python rule engine — no external scanning binary required,
    so it works identically on every platform.
    """
    code_lines = code.split("\n")
    findings = []

    for line_number, line_text in enumerate(code_lines, start=1):
        for rule_id, pattern, message, raw_severity in COMMON_RULES:
            if pattern.search(line_text):
                context_start = max(0, line_number - 3)
                context_end = min(len(code_lines), line_number + 2)
                snippet = "\n".join(code_lines[context_start:context_end])

                findings.append({
                    "line": line_number,
                    "rule": rule_id,
                    "message": message,
                    "raw_severity": raw_severity,
                    "snippet": snippet,
                })

    return findings
