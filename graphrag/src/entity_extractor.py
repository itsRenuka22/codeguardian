import re

# Each entry is (display_name, regex_pattern)
FUNCTION_PATTERNS = {
    "php": [
        ("mysqli_query",      r"\bmysqli_query\b"),
        ("mysql_query",       r"\bmysql_query\b"),
        ("echo",              r"\becho\b"),
        ("print",             r"\bprint\b"),
        ("system",            r"\bsystem\b"),
        ("exec",              r"\bexec\b"),
        ("passthru",          r"\bpassthru\b"),
        ("shell_exec",        r"\bshell_exec\b"),
        ("eval",              r"\beval\b"),
        ("preg_replace",      r"\bpreg_replace\b"),
        ("file_get_contents", r"\bfile_get_contents\b"),
        ("include",           r"\binclude\b"),
        ("require",           r"\brequire\b"),
        ("header",            r"\bheader\b"),
        ("setcookie",         r"\bsetcookie\b"),
        ("unserialize",       r"\bunserialize\b"),
        ("base64_decode",     r"\bbase64_decode\b"),
    ],
    "java": [
        ("executeQuery",      r"\bexecuteQuery\b"),
        ("executeUpdate",     r"\bexecuteUpdate\b"),
        ("prepareStatement",  r"\bprepareStatement\b"),
        ("createQuery",       r"\bcreateQuery\b"),
        ("getParameter",      r"\bgetParameter\b"),
        ("getHeader",         r"\bgetHeader\b"),
        ("getCookies",        r"\bgetCookies\b"),
        ("Runtime.exec",      r"\bRuntime\b.*\bexec\b"),
        ("ProcessBuilder",    r"\bProcessBuilder\b"),
        ("ScriptEngine",      r"\bScriptEngine\b"),
        ("ObjectInputStream", r"\bObjectInputStream\b"),
        ("DocumentBuilder",   r"\bDocumentBuilder\b"),
        ("SAXParser",         r"\bSAXParser\b"),
        ("getWriter",         r"\bgetWriter\b"),
        ("getOutputStream",   r"\bgetOutputStream\b"),
    ],
    "python": [
        ("eval",                   r"\beval\b"),
        ("exec",                   r"\bexec\b"),
        ("os.system",              r"\bos\.system\b"),
        ("os.popen",               r"\bos\.popen\b"),
        ("subprocess.call",        r"\bsubprocess\.call\b"),
        ("subprocess.run",         r"\bsubprocess\.run\b"),
        ("subprocess.Popen",       r"\bsubprocess\.Popen\b"),
        ("pickle.loads",           r"\bpickle\.loads\b"),
        ("yaml.load",              r"\byaml\.load\b"),
        ("open",                   r"\bopen\b"),
        ("cursor.execute",         r"\bcursor\.execute\b"),
        ("render_template_string", r"\brender_template_string\b"),
        ("render",                 r"\brender\b"),
        ("__import__",             r"\b__import__\b"),
    ],
    "ruby": [
        ("eval",    r"\beval\b"),
        ("system",  r"\bsystem\b"),
        ("exec",    r"\bexec\b"),
        ("shell",   r"\bshell\b"),
        ("open",    r"\bopen\b"),
        ("load",    r"\bload\b"),
        ("send",    r"\bsend\b"),
    ],
}

SOURCE_PATTERNS = {
    "php": [
        ("$_GET",     r"\$_GET\b"),
        ("$_POST",    r"\$_POST\b"),
        ("$_REQUEST", r"\$_REQUEST\b"),
        ("$_COOKIE",  r"\$_COOKIE\b"),
        ("$_SERVER",  r"\$_SERVER\b"),
        ("$_FILES",   r"\$_FILES\b"),
        ("$_SESSION", r"\$_SESSION\b"),
    ],
    "java": [
        ("getParameter",  r"\bgetParameter\b"),
        ("getHeader",     r"\bgetHeader\b"),
        ("getCookies",    r"\bgetCookies\b"),
        ("getQueryString",r"\bgetQueryString\b"),
    ],
    "python": [
        ("request.args",    r"\brequest\.args\b"),
        ("request.form",    r"\brequest\.form\b"),
        ("request.data",    r"\brequest\.data\b"),
        ("request.json",    r"\brequest\.json\b"),
        ("request.cookies", r"\brequest\.cookies\b"),
        ("request.headers", r"\brequest\.headers\b"),
        ("input",           r"\binput\b"),
        ("sys.argv",        r"\bsys\.argv\b"),
        ("os.environ",      r"\bos\.environ\b"),
    ],
    "ruby": [
        ("params",           r"\bparams\["),
        ("request.params",   r"\brequest\.params\b"),
        ("request.body",     r"\brequest\.body\b"),
        ("cookies",          r"\bcookies\["),
        ("ENV",              r"\bENV\["),
    ],
}


def _strip_comments(code: str) -> str:
    return "\n".join(
        line for line in code.splitlines()
        if not re.match(r"^\s*(#|//|--)", line)
    )


class EntityExtractor:
    def extract_functions(self, code: str, language: str) -> list:
        lang = language.lower()
        pairs = FUNCTION_PATTERNS.get(lang, [])
        clean = _strip_comments(code)
        return [
            name for name, pattern in pairs
            if re.search(pattern, clean, re.IGNORECASE)
        ]

    def extract_sources(self, code: str, language: str) -> list:
        lang = language.lower()
        pairs = SOURCE_PATTERNS.get(lang, [])
        clean = _strip_comments(code)
        return [
            name for name, pattern in pairs
            if re.search(pattern, clean, re.IGNORECASE)
        ]

    def extract_entities(self, code_item: dict) -> dict:
        code = code_item.get("code", "")
        language = code_item.get("language", "")
        return {
            "code_id":   code_item.get("item_id", ""),
            "functions": self.extract_functions(code, language),
            "sources":   self.extract_sources(code, language),
            "language":  language,
        }
