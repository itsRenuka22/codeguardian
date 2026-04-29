"""
LineDetector: maps vulnerability types to specific lines in submitted code.
Uses regex patterns to pinpoint the exact lines containing security issues.
"""
import re
from typing import List

# Per-vuln patterns: list of (reason, regex)
_PATTERNS = {
    "sql_injection": [
        ("Unsanitized user input in query", r'\$_(GET|POST|REQUEST|COOKIE)\['),
        ("Raw SQL query execution",          r'(mysqli_query|mysql_query|pg_query|sqlite_query|\.execute)\s*\('),
        ("SQL string concatenation",         r'(SELECT|INSERT|UPDATE|DELETE|WHERE).{0,60}\$'),
        ("String-format SQL query",          r'("|\')SELECT.+%s'),
        ("ORM raw query with user input",    r'(raw|extra|RawSQL)\s*\('),
    ],
    "xss": [
        ("Unsanitized echo of user input",   r'echo\s+.*\$_(GET|POST|REQUEST|COOKIE)'),
        ("Unescaped print statement",        r'(print|echo)\s+.*\$_(GET|POST|REQUEST)'),
        ("innerHTML assignment",             r'\.innerHTML\s*='),
        ("document.write with variable",     r'document\.write\s*\('),
        ("Reflected template variable",      r'\{\{\s*\w+\s*\}\}'),
    ],
    "command_injection": [
        ("Shell exec with user input",       r'(shell_exec|passthru|popen)\s*\(.*\$_(GET|POST|REQUEST)'),
        ("system() with user input",         r'system\s*\(.*\$_(GET|POST|REQUEST)'),
        ("os.system with concatenation",     r'os\.(system|popen)\s*\(.+[\+\%]'),
        ("subprocess with shell=True",       r'subprocess\.(call|run|Popen).+shell\s*=\s*True'),
        ("Backtick command execution",       r'`[^`]*\$_(GET|POST|REQUEST)[^`]*`'),
    ],
    "path_traversal": [
        ("File open with user-supplied path", r'(fopen|file_get_contents|readfile|open)\s*\(.*\$_(GET|POST)'),
        ("Directory traversal pattern",       r'\.\./'),
        ("Include with user input",           r'(include|require)\s*\(.*\$_(GET|POST|REQUEST)'),
    ],
    "file_inclusion": [
        ("Dynamic include with user input",   r'(include|require|include_once|require_once)\s*\(.*\$_(GET|POST|REQUEST)'),
        ("Remote file inclusion",             r'(include|require)\s*\(\s*["\']https?://'),
    ],
    "insecure_deserialization": [
        ("Unsafe PHP unserialize",            r'unserialize\s*\('),
        ("Python pickle.loads",               r'pickle\.(loads|load)\s*\('),
        ("Unsafe YAML load",                  r'yaml\.load\s*\([^,)]+\)'),
        ("Java ObjectInputStream",            r'ObjectInputStream'),
    ],
    "code_injection": [
        ("eval() with user input",            r'eval\s*\(.*\$_(GET|POST|REQUEST)'),
        ("exec() with user input",            r'exec\s*\(.*\$_(GET|POST|REQUEST)'),
        ("Dynamic code via compile()",        r'compile\s*\(.*input'),
    ],
    "ldap_injection": [
        ("LDAP search with user input",       r'ldap_(search|bind)\s*\(.*\$_(GET|POST)'),
        ("Unescaped LDAP filter",             r'ldap_escape\s*\('),
    ],
    "xxe": [
        ("XML parsed without protection",     r'(simplexml_load_string|DOMDocument|XMLReader|xml\.etree|lxml)'),
        ("External entity declaration",       r'<!ENTITY'),
        ("DOCTYPE with SYSTEM",               r'<!DOCTYPE.+SYSTEM'),
    ],
    "ssrf": [
        ("HTTP request with user URL",        r'(curl_setopt|file_get_contents|requests\.(get|post)|urllib)\s*\(.*\$_(GET|POST)'),
        ("URL from request parameter",        r'(http|https)://.*\$_(GET|POST|REQUEST)'),
        ("fetch() with user-controlled URL",  r'fetch\s*\(.*\+'),
    ],
    "authentication_bypass": [
        ("MD5 for password hashing",          r'\bmd5\s*\('),
        ("SHA1 for password hashing",         r'\bsha1\s*\('),
        ("Hardcoded credential",              r'(password|passwd|secret|token)\s*=\s*["\'][^"\']{4,}["\']'),
        ("SQL OR 1=1 bypass",                 r"OR\s+['\"]?1['\"]?\s*=\s*['\"]?1"),
    ],
    "buffer_overflow": [
        ("Unsafe strcpy/strcat",              r'\b(strcpy|strcat|sprintf|gets)\s*\('),
        ("Unbounded memory allocation",       r'\bmalloc\s*\(.+\*'),
    ],
}

# Language-agnostic signals always checked
_GENERIC = [
    ("Unsanitized user input",   r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\['),
    ("Dangerous eval/exec",      r'\b(eval|exec|shell_exec|system|passthru)\s*\('),
    ("Hardcoded secret value",   r'(?i)(api_key|secret_key|password|auth_token)\s*=\s*["\'][A-Za-z0-9+/=_\-]{8,}["\']'),
]


def detect_vulnerable_lines(code: str, vuln_types: list) -> list:
    """
    Returns [{line_num, content, vuln_type, reason}, …] for each line that
    matches a vulnerability pattern for the detected vuln types.
    Sorted by line number; at most one finding per (line, vuln_type) pair.
    """
    if not code:
        return []

    lines = code.split("\n")
    findings = []
    seen: set = set()

    # Build pattern list for detected vuln types
    checks = []
    for vt in (vuln_types or []):
        for reason, pattern in _PATTERNS.get(vt, []):
            checks.append((vt, reason, pattern))
    for reason, pattern in _GENERIC:
        checks.append(("general", reason, pattern))

    for i, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        # Skip blank/comment lines
        if not stripped or stripped.startswith(("//", "#", "*", "/*", "<!--")):
            continue

        for vt, reason, pattern in checks:
            if re.search(pattern, raw_line, re.IGNORECASE):
                key = (i, vt)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "line_num": i,
                        "content":  raw_line.rstrip(),
                        "vuln_type": vt,
                        "reason":   reason,
                    })

    findings.sort(key=lambda x: x["line_num"])
    return findings
