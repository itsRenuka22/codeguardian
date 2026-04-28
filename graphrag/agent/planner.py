"""
Planner: inspects the input code and produces an AnalysisPlan — a ranked
list of search queries plus metadata the executor and critic need.
No LLM required; all heuristics are rule-based.
"""
import re
from dataclasses import dataclass, field


# ── language detection ────────────────────────────────────────────────────────

_LANG_SIGNATURES = {
    "php":    [r"<\?php", r"\$_GET\b", r"\$_POST\b", r"mysqli_", r"echo\s"],
    "python": [r"def\s+\w+\s*\(", r"import\s+\w+", r"request\.args", r"os\.system"],
    "java":   [r"public\s+(class|void|static)", r"System\.out", r"getParameter\s*\("],
    "ruby":   [r"\bparams\[", r"def\s+\w+\b", r"puts\b", r"\.each\s+do"],
    "javascript": [r"function\s+\w+\s*\(", r"var\s+\w+", r"document\.", r"eval\s*\("],
}

_VULN_SIGNATURES = {
    "sql_injection": [
        r"mysqli_query\s*\(", r"mysql_query\s*\(", r"executeQuery\s*\(",
        r"cursor\.execute\s*\(", r"SELECT\s.+WHERE", r"INSERT\s+INTO",
        r'"\s*\+\s*\$', r'"\s*\.\s*\$',
    ],
    "xss": [
        r"\becho\b.*\$_(GET|POST|REQUEST)", r"innerHTML\s*=",
        r"document\.write\s*\(", r"render_template_string\s*\(",
        r"getWriter\(\)\.print",
    ],
    "command_injection": [
        r"\bsystem\s*\(", r"\bexec\s*\(", r"\bpassthru\s*\(",
        r"Runtime\.exec\s*\(", r"os\.system\s*\(", r"subprocess\.(run|call|Popen)\s*\(",
    ],
    "path_traversal": [
        r"\.\./", r"file_get_contents\s*\(", r"include\s*\(", r"require\s*\(",
        r"open\s*\(.*\$_(GET|POST)", r"readFile\s*\(",
    ],
    "code_injection": [
        r"\beval\s*\(", r"preg_replace\s*\(.*\/e", r"assert\s*\(",
        r"ScriptEngine", r"__import__\s*\(",
    ],
    "insecure_deserialization": [
        r"unserialize\s*\(", r"pickle\.loads\s*\(", r"yaml\.load\s*\(",
        r"ObjectInputStream\s*\(",
    ],
    "auth_bypass": [
        r"strcmp\s*\(.*==\s*0", r"md5\s*\(", r"sha1\s*\(",
        r"password\s*==\s*", r"token\s*==\s*",
    ],
    "ssrf": [
        r"curl_init\s*\(", r"file_get_contents\s*\(.*http",
        r"requests\.get\s*\(", r"urllib\.request",
    ],
}


def detect_language(code: str) -> str:
    scores = {}
    for lang, patterns in _LANG_SIGNATURES.items():
        scores[lang] = sum(1 for p in patterns if re.search(p, code, re.IGNORECASE))
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "unknown"


def detect_vuln_hints(code: str) -> list:
    hits = []
    for vtype, patterns in _VULN_SIGNATURES.items():
        if any(re.search(p, code, re.IGNORECASE) for p in patterns):
            hits.append(vtype)
    return hits


# ── plan dataclass ────────────────────────────────────────────────────────────

@dataclass
class AnalysisPlan:
    language: str
    suspected_vulns: list = field(default_factory=list)
    queries: list = field(default_factory=list)   # ordered: most specific first
    top_k: int = 5
    attempt: int = 0


# ── planner ───────────────────────────────────────────────────────────────────

class Planner:
    def plan(self, code: str) -> AnalysisPlan:
        language = detect_language(code)
        suspected = detect_vuln_hints(code)

        queries = self._build_queries(code, language, suspected)
        return AnalysisPlan(
            language=language,
            suspected_vulns=suspected,
            queries=queries,
            top_k=5,
        )

    def replan(self, code: str, prev_plan: AnalysisPlan, reason: str) -> AnalysisPlan:
        """Widen the search on retry: more generic queries, larger top_k."""
        plan = self.plan(code)
        plan.attempt = prev_plan.attempt + 1
        plan.top_k = min(prev_plan.top_k + 3, 10)
        # add a broad fallback query
        plan.queries.append(f"{prev_plan.language} vulnerability security")
        return plan

    # ── private ───────────────────────────────────────────────────────────────

    def _build_queries(self, code: str, language: str, suspected: list) -> list:
        queries = []

        # 1. Raw code snippet (most specific — let the embeddings do the work)
        queries.append(code[:800])

        # 2. One targeted query per suspected vuln type
        for vtype in suspected:
            label = vtype.replace("_", " ")
            queries.append(f"{language} {label} vulnerability exploit")

        # 3. Language-level fallback
        if language != "unknown":
            queries.append(f"{language} security vulnerability injection")

        return queries
