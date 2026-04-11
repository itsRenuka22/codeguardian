"""
Extract vulnerable Java code examples from WebGoat (OWASP deliberately insecure app).
Source: GitHub API + raw download — WebGoat/WebGoat (no local clone required)
Output: data/raw/v2/webgoat/webgoat_vulnerable_code.json + metadata.json

Inline quality filtering: boilerplate detection, pattern scoring, recategorization.

Run from the codeguardian directory:
    python scripts/data_collection/extract_webgoat.py
"""

import json
import logging
import re
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

GITHUB_REPO     = "WebGoat/WebGoat"
GITHUB_BRANCH   = "main"
LESSONS_PATH    = "src/main/java/org/owasp/webgoat/lessons"
GITHUB_API_BASE = f"https://api.github.com/repos/{GITHUB_REPO}/contents"
GITHUB_RAW_BASE = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}"

DELAY_BETWEEN_DOWNLOADS = 0.3   # seconds — respect GitHub rate limits

OUTPUT_DIR    = Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "v2" / "webgoat"
OUTPUT_FILE   = OUTPUT_DIR / "webgoat_vulnerable_code.json"
METADATA_FILE = OUTPUT_DIR / "metadata.json"
LOG_FILE      = Path(__file__).resolve().parent.parent.parent / "logs" / "webgoat_extraction.log"

MIN_FILE_SIZE    = 1800   # bytes — raised from 1500; smaller = Spring Boot boilerplate
MIN_QUALITY_SCORE = 0.4  # 0.0–1.0; files below this threshold are skipped

EXCLUDE_SUBDIRS  = {"mitigation", "secure"}
EXCLUDE_SUFFIXES = {"Mitigation.java", "Secure.java"}
SKIP_CATEGORIES  = {"challenges", "lessontemplate", "webgoatintroduction", "webwolfintroduction"}

CATEGORY_MAPPING = {
    "sqlinjection":        "sql_injection",
    "xss":                 "xss",
    "csrf":                "csrf",
    "xxe":                 "xxe",
    "pathtraversal":       "path_traversal",
    "deserialization":     "deserialization",
    "ssrf":                "ssrf",
    "idor":                "auth_bypass",
    "authbypass":          "auth_bypass",
    "insecurelogin":       "auth_bypass",
    "hijacksession":       "auth_bypass",
    "jwt":                 "auth_bypass",
    "passwordreset":       "auth_bypass",
    "spoofcookie":         "auth_bypass",
    "missingac":           "auth_bypass",
    "openredirect":        "other_injection",
    "bypassrestrictions":  "other_injection",
    "cryptography":        "other_injection",
    "clientsidefiltering": "other_injection",
}


# ──────────────────────────────────────────────
# Vulnerable pattern detection
# ──────────────────────────────────────────────

# Each group maps a category label to a list of compiled regexes.
# A group "matches" if ANY of its patterns are found in the file.
_PATTERN_GROUPS: dict[str, list] = {
    "sql_injection": [
        re.compile(r'createStatement\s*\(', re.IGNORECASE),
        re.compile(r'executeQuery\s*\(', re.IGNORECASE),
        re.compile(r'executeUpdate\s*\(', re.IGNORECASE),
        re.compile(r'"SELECT\s+.*\s+FROM', re.IGNORECASE),
        re.compile(r'"INSERT\s+INTO', re.IGNORECASE),
        re.compile(r'"UPDATE\s+.*\s+SET', re.IGNORECASE),
        re.compile(r'\+\s*\w+\s*\+.*".*SELECT', re.IGNORECASE),  # string concat in SQL
    ],
    "path_traversal": [
        re.compile(r'new\s+File\s*\(', re.IGNORECASE),
        re.compile(r'\.getName\s*\(\)', re.IGNORECASE),
        re.compile(r'\.getPath\s*\(\)', re.IGNORECASE),
        re.compile(r'ZipEntry', re.IGNORECASE),
        re.compile(r'\.\.\/', re.IGNORECASE),
    ],
    "command_injection": [
        re.compile(r'Runtime\.getRuntime\(\)\.exec', re.IGNORECASE),
        re.compile(r'ProcessBuilder', re.IGNORECASE),
        re.compile(r'\.exec\s*\(', re.IGNORECASE),
    ],
    "xss": [
        re.compile(r'@RequestParam', re.IGNORECASE),
        re.compile(r'HttpServletRequest', re.IGNORECASE),
        re.compile(r'\.getParameter\s*\(', re.IGNORECASE),
        re.compile(r'\.innerHTML', re.IGNORECASE),
        re.compile(r'document\.write', re.IGNORECASE),
    ],
    "xxe": [
        re.compile(r'DocumentBuilderFactory', re.IGNORECASE),
        re.compile(r'SAXParserFactory', re.IGNORECASE),
        re.compile(r'XMLInputFactory', re.IGNORECASE),
        re.compile(r'setFeature\s*\(', re.IGNORECASE),
    ],
    "deserialization": [
        re.compile(r'ObjectInputStream', re.IGNORECASE),
        re.compile(r'readObject\s*\(', re.IGNORECASE),
        re.compile(r'XMLDecoder', re.IGNORECASE),
    ],
    "ssrf": [
        re.compile(r'\bURL\s*\(', re.IGNORECASE),
        re.compile(r'HttpClient', re.IGNORECASE),
        re.compile(r'\.connect\s*\(', re.IGNORECASE),
        re.compile(r'URLConnection', re.IGNORECASE),
    ],
    "auth_bypass": [
        re.compile(r'@RequestParam.*userId', re.IGNORECASE),
        re.compile(r'@RequestParam.*\buser\b', re.IGNORECASE),
        re.compile(r'@RequestParam.*account', re.IGNORECASE),
        re.compile(r'session\.getAttribute', re.IGNORECASE),
        re.compile(r'\bJWT\b', re.IGNORECASE),
        re.compile(r'getParameter.*user', re.IGNORECASE),
    ],
}

# Interesting Java keywords used by the quality scorer
_INTERESTING_KEYWORDS = [
    "Connection", "Statement", "ResultSet",       # JDBC
    "File", "InputStream", "OutputStream",        # file I/O
    "HttpServletRequest", "HttpServletResponse",  # HTTP
    "ObjectInputStream", "XMLDecoder",            # deserialization
]


def detect_java_vulnerable_patterns(code: str) -> tuple[bool, list[str]]:
    """
    Check code against all pattern groups.
    Returns (found_any, list_of_matched_group_names).
    """
    matched = [
        group
        for group, patterns in _PATTERN_GROUPS.items()
        if any(p.search(code) for p in patterns)
    ]
    return bool(matched), matched


def calculate_code_quality_score(code: str) -> float:
    """
    Heuristic quality score in [0.0, 1.0].
    Combines: vulnerable-pattern presence, logic density, interesting-keyword count.
    """
    score = 0.0

    # Component 1 — vulnerable patterns found (+0.4)
    has_patterns, _ = detect_java_vulnerable_patterns(code)
    if has_patterns:
        score += 0.4

    # Component 2 — logic density: not mostly if/return validation (+0.3)
    code_lines = [
        l.strip() for l in code.splitlines()
        if l.strip() and not l.strip().startswith("//")
    ]
    if_count     = sum(1 for l in code_lines if "if (" in l)
    return_count = sum(1 for l in code_lines if l.startswith("return "))
    other_count  = len(code_lines) - if_count - return_count
    # Files that are mostly if/return are validation-only boilerplate
    if other_count > 0 and (if_count + return_count) <= other_count * 2:
        score += 0.3

    # Component 3 — interesting keyword density (+0.3 / +0.15)
    keyword_hits = sum(1 for kw in _INTERESTING_KEYWORDS if kw in code)
    if keyword_hits >= 2:
        score += 0.3
    elif keyword_hits == 1:
        score += 0.15

    return score


def is_validation_boilerplate(code: str) -> bool:
    """
    Return True if the file is primarily if/equals validation logic
    with no real vulnerability demonstration.
    """
    # Many validation checks of the form: if (x.equals(y)) { return failed/success; }
    validation_matches = len(re.findall(
        r'if\s*\([^)]+\.(equals|matches)\([^)]+\)\s*\)\s*\{[^}]*return\s+(failed|success)',
        code, re.DOTALL | re.IGNORECASE,
    ))
    if validation_matches > 5:
        return True

    # Has @RequestParam but no dangerous operations and very little logic
    has_request_param = "@RequestParam" in code
    has_dangerous_ops = any(op in code for op in [
        "executeQuery", "executeUpdate", "createStatement",
        "new File", "Runtime.exec", "ProcessBuilder",
        "ObjectInputStream", "XMLDecoder", "readObject",
    ])
    if has_request_param and not has_dangerous_ops:
        boilerplate_keywords = {
            "import", "package", "@", "public class", "public interface",
            "return failed", "return success", "if (", "}",
        }
        non_boilerplate = [
            l for l in code.splitlines()
            if l.strip() and not l.strip().startswith("//")
            and not any(kw in l for kw in boilerplate_keywords)
        ]
        if len(non_boilerplate) < 10:
            return True

    return False


# ──────────────────────────────────────────────
# Recategorization
# ──────────────────────────────────────────────

def recategorize_if_needed(
    vuln_type: str,
    category: str,
    code: str,
    patterns: list[str],
) -> tuple[Optional[str], str]:
    """
    Apply recategorization rules for 'other_injection' files.
    Returns (new_category_or_None, reason_string).
    None means the file should be removed.
    """
    if category != "other_injection":
        return category, "kept"

    if "bypassrestrictions" in vuln_type:
        if is_validation_boilerplate(code):
            return None, "bypassrestrictions (validation boilerplate)"
        return "auth_bypass", f"bypassrestrictions → auth_bypass"

    if "clientsidefiltering" in vuln_type:
        return "auth_bypass", f"clientsidefiltering → auth_bypass"

    # Generic other_injection: keep only if patterns detected
    if not patterns:
        return None, f"other_injection with no detectable patterns"

    return category, "kept"


# ──────────────────────────────────────────────
# Lesson type detection
# ──────────────────────────────────────────────

def detect_lesson_type(file_path: str) -> str:
    """Infer lesson type from directory structure and filename."""
    path_lower = file_path.lower()
    stem_lower = Path(file_path).stem.lower()

    # Directory takes precedence
    if "/introduction/" in path_lower:
        return "introduction"
    if "/advanced/" in path_lower:
        return "advanced"
    if "/assignment/" in path_lower:
        return "assignment"
    if "/attack/" in path_lower:
        return "attack"

    # Fall back to filename
    if "assignment" in stem_lower:
        return "assignment"
    if "lesson" in stem_lower:
        if "intro" in stem_lower:
            return "introduction"
        if "advanced" in stem_lower:
            return "advanced"
        return "lesson"

    return "other"


# ──────────────────────────────────────────────
# GitHub API helpers
# ──────────────────────────────────────────────

def api_list(path: str) -> Optional[list]:
    """Call GitHub Contents API and return the JSON list, or None on failure."""
    url = f"{GITHUB_API_BASE}/{path}?ref={GITHUB_BRANCH}"
    try:
        resp = requests.get(url, timeout=15, headers={"Accept": "application/vnd.github.v3+json"})
        if resp.status_code == 404:
            logging.debug(f"API 404: {url}")
            return None
        if resp.status_code != 200:
            logging.warning(f"API HTTP {resp.status_code}: {url}")
            return None
        return resp.json()
    except requests.RequestException as e:
        logging.warning(f"API error for {path}: {e}")
        return None


def download_raw(file_path: str) -> Optional[str]:
    """Download raw file content from GitHub. Returns None on failure."""
    url = f"{GITHUB_RAW_BASE}/{file_path}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            logging.debug(f"Raw HTTP {resp.status_code}: {url}")
            return None
        content = resp.text
        if content.strip().lower().startswith("<!doctype") or "<html" in content[:200].lower():
            logging.debug(f"HTML response for {url}")
            return None
        return content
    except requests.RequestException as e:
        logging.warning(f"Download error for {file_path}: {e}")
        return None


# ──────────────────────────────────────────────
# Recursive file finder
# ──────────────────────────────────────────────

def find_java_files(api_path: str, category_dir: str) -> list[dict]:
    """
    Recursively list .java files under api_path via GitHub API.
    Returns list of {name, path, size} dicts that pass structural pre-filters.
    """
    entries = api_list(api_path)
    if not entries:
        return []

    results = []
    for entry in entries:
        if entry["type"] == "dir":
            if entry["name"].lower() in EXCLUDE_SUBDIRS:
                logging.debug(f"Skipping secure subdir: {entry['path']}")
                continue
            results.extend(find_java_files(entry["path"], category_dir))

        elif entry["type"] == "file" and entry["name"].endswith(".java"):
            name = entry["name"]
            if any(name.endswith(sfx) for sfx in EXCLUDE_SUFFIXES):
                continue
            results.append({
                "name": name,
                "path": entry["path"],
                "size": entry.get("size", 0),
            })

    return results


# ──────────────────────────────────────────────
# Main extraction
# ──────────────────────────────────────────────

def extract_snippets() -> tuple[list, dict]:
    """
    Download and quality-filter Java files for each WebGoat lesson category.
    Returns (snippets_list, skip_reason_counts).
    """
    snippets = []
    skip_reasons = Counter()
    snippet_counter = 0

    top_entries = api_list(LESSONS_PATH)
    if not top_entries:
        logging.error(f"Could not list lessons directory: {LESSONS_PATH}")
        return snippets, dict(skip_reasons)

    for entry in sorted(top_entries, key=lambda e: e["name"]):
        if entry["type"] != "dir":
            continue

        category_dir = entry["name"].lower()

        if category_dir in SKIP_CATEGORIES:
            logging.debug(f"Skipping excluded category: {category_dir}")
            continue

        if category_dir not in CATEGORY_MAPPING:
            logging.debug(f"Unmapped category, skipping: {category_dir}")
            continue

        category = CATEGORY_MAPPING[category_dir]
        logging.info(f"Processing category: {category_dir} → {category}")

        java_files = find_java_files(entry["path"], category_dir)
        time.sleep(0.1)  # pause after API traversal burst

        for file_info in java_files:
            rel_path  = file_info["path"]
            file_name = file_info["name"]
            api_size  = file_info["size"]

            # ── Pre-filter: API-reported size ──
            if api_size > 0 and api_size < MIN_FILE_SIZE:
                print(f"⏭️  Skipped {rel_path} (only {api_size}B)")
                logging.info(f"Skipped (too small, {api_size}B): {rel_path}")
                skip_reasons["too_small"] += 1
                continue

            print(f"⬇️  Fetching {rel_path} ...", end=" ", flush=True)
            code = download_raw(rel_path)
            time.sleep(DELAY_BETWEEN_DOWNLOADS)

            if code is None:
                print("❌ download failed")
                logging.warning(f"Download failed: {rel_path}")
                skip_reasons["download_failed"] += 1
                continue

            actual_size = len(code.encode("utf-8"))

            # ── Filter 1: actual downloaded size ──
            if actual_size < MIN_FILE_SIZE:
                print(f"⏭️  too small ({actual_size}B)")
                logging.info(f"Skipped (actual size {actual_size}B): {rel_path}")
                skip_reasons["too_small"] += 1
                continue

            # ── Filter 2: validation boilerplate ──
            if is_validation_boilerplate(code):
                print(f"⏭️  validation boilerplate")
                logging.info(f"Skipped (validation boilerplate): {rel_path}")
                skip_reasons["validation_boilerplate"] += 1
                continue

            # ── Quality score ──
            quality_score = calculate_code_quality_score(code)

            # ── Filter 3: quality threshold ──
            if quality_score < MIN_QUALITY_SCORE:
                print(f"⏭️  low quality ({quality_score:.2f})")
                logging.info(f"Skipped (quality={quality_score:.2f}): {rel_path}")
                skip_reasons["low_quality_score"] += 1
                continue

            # ── Pattern detection ──
            has_patterns, patterns = detect_java_vulnerable_patterns(code)

            # ── Recategorization / removal ──
            new_category, recat_reason = recategorize_if_needed(
                category_dir, category, code, patterns
            )
            if new_category is None:
                print(f"⏭️  removed ({recat_reason})")
                logging.info(f"Removed ({recat_reason}): {rel_path}")
                skip_reasons["recategorization_removed"] += 1
                continue

            if new_category != category:
                print(f"🔄 recategorized ({recat_reason})", end=" ")
                logging.info(f"Recategorized ({recat_reason}): {rel_path}")

            lesson_type = detect_lesson_type(rel_path)

            snippet_counter += 1
            snippet_id = f"webgoat_{snippet_counter:03d}"
            stem = Path(file_name).stem

            snippet = {
                "snippet_id":             snippet_id,
                "source":                 "WebGoat",
                "language":               "java",
                "category":               new_category,
                "lesson_type":            lesson_type,
                "vulnerability_patterns": patterns,
                "quality_score":          round(quality_score, 2),
                "file_path":              rel_path,
                "file_size":              actual_size,
                "code":                   code,
                "description":            f"WebGoat {category_dir}/{lesson_type} - {stem}",
            }
            snippets.append(snippet)

            pattern_str = f"[{', '.join(patterns)}]" if patterns else "[no patterns]"
            print(f"✅ ({actual_size}B, Q:{quality_score:.2f}) → {new_category} {pattern_str}")
            logging.info(
                f"Extracted [{new_category}] {rel_path} "
                f"({actual_size}B, Q:{quality_score:.2f}) {pattern_str}"
            )

    return snippets, dict(skip_reasons)


# ──────────────────────────────────────────────
# Output builders
# ──────────────────────────────────────────────

def build_statistics(snippets: list) -> dict:
    by_category    = dict(Counter(s["category"] for s in snippets))
    by_lesson_type = dict(Counter(s["lesson_type"] for s in snippets))
    with_patterns  = sum(1 for s in snippets if s["vulnerability_patterns"])
    avg_quality    = (
        round(sum(s["quality_score"] for s in snippets) / len(snippets), 2)
        if snippets else 0.0
    )
    return {
        "by_category":              by_category,
        "by_lesson_type":           by_lesson_type,
        "with_vulnerable_patterns": with_patterns,
        "average_quality_score":    avg_quality,
    }


def build_output(snippets: list, skip_reasons: dict) -> dict:
    stats = build_statistics(snippets)
    return {
        "source":          "WebGoat",
        "extraction_date": datetime.now().date().isoformat(),
        "total_snippets":  len(snippets),
        "skipped_count":   sum(skip_reasons.values()),
        "skip_reasons":    skip_reasons,
        "min_file_size":   MIN_FILE_SIZE,
        "min_quality_score": MIN_QUALITY_SCORE,
        "snippets":        snippets,
        "statistics":      stats,
        "quality_metrics": {
            "with_patterns":          stats["with_vulnerable_patterns"],
            "pattern_percentage":     round(
                stats["with_vulnerable_patterns"] / len(snippets) * 100, 1
            ) if snippets else 0.0,
            "average_quality_score":  stats["average_quality_score"],
        },
    }


def build_metadata(snippets: list, skip_reasons: dict) -> dict:
    stats = build_statistics(snippets)
    return {
        "extraction_date":          datetime.now().isoformat(),
        "source":                   "WebGoat",
        "github_repo":              GITHUB_REPO,
        "github_branch":            GITHUB_BRANCH,
        "total_snippets":           len(snippets),
        "skipped_count":            sum(skip_reasons.values()),
        "skip_reasons":             skip_reasons,
        "min_file_size":            MIN_FILE_SIZE,
        "min_quality_score":        MIN_QUALITY_SCORE,
        "language":                 "java",
        "category_breakdown":       stats["by_category"],
        "lesson_type_breakdown":    stats["by_lesson_type"],
        "with_vulnerable_patterns": stats["with_vulnerable_patterns"],
        "average_quality_score":    stats["average_quality_score"],
        "cleaning_applied":         True,
        "cleaning_rules": {
            "boilerplate_detection":  True,
            "quality_score_filter":   MIN_QUALITY_SCORE,
            "recategorized":          ["bypassrestrictions → auth_bypass", "clientsidefiltering → auth_bypass"],
            "removed_if_no_patterns": ["other_injection"],
        },
        "notes": (
            "Files in mitigation/ and secure/ subdirectories excluded. "
            "Validation boilerplate detected and skipped inline. "
            "Quality score < 0.4 skipped. other_injection recategorized or removed. "
            "Downloaded via GitHub API + raw URLs."
        ),
    }


# ──────────────────────────────────────────────
# Summary printer
# ──────────────────────────────────────────────

def print_summary(snippets: list, skip_reasons: dict):
    stats = build_statistics(snippets)
    with_p = stats["with_vulnerable_patterns"]
    total  = len(snippets)

    print("\n" + "=" * 60)
    print("📊 WebGoat Extraction Summary")
    print("=" * 60)
    print(f"   Total extracted         : {total}")
    print(f"   Total skipped           : {sum(skip_reasons.values())}")

    print("\n   Skip reasons:")
    for reason, count in sorted(skip_reasons.items(), key=lambda x: -x[1]):
        print(f"      {reason:<30}: {count}")

    print(f"\n🎯 Quality Metrics:")
    print(f"   With vulnerable patterns : {with_p}/{total} ({with_p/total*100:.1f}%)" if total else "   No snippets")
    print(f"   Average quality score    : {stats['average_quality_score']:.2f}")

    print("\n   By Category:")
    for cat, count in sorted(stats["by_category"].items()):
        print(f"   {'✅' if count > 0 else '❌'} {cat:<25}: {count}")

    print("\n   By Lesson Type:")
    for ltype, count in sorted(stats["by_lesson_type"].items()):
        print(f"      {ltype:<15}: {count}")

    print("=" * 60)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(str(LOG_FILE)),
            logging.StreamHandler(),
        ],
        force=True,
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    logging.info("=" * 60)
    logging.info("Starting WebGoat Extraction (GitHub API + raw download, inline cleaning)")
    logging.info(f"Repo            : {GITHUB_REPO} @ {GITHUB_BRANCH}")
    logging.info(f"Lessons path    : {LESSONS_PATH}")
    logging.info(f"Output dir      : {OUTPUT_DIR.resolve()}")
    logging.info(f"Min file size   : {MIN_FILE_SIZE}B")
    logging.info(f"Min quality score: {MIN_QUALITY_SCORE}")
    logging.info("=" * 60)

    snippets, skip_reasons = extract_snippets()

    if not snippets:
        logging.error("No snippets extracted — check network or repo structure.")
        print("\n❌ No snippets found. Check your internet connection.")
        return

    output = build_output(snippets, skip_reasons)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    metadata = build_metadata(snippets, skip_reasons)
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    size_kb = OUTPUT_FILE.stat().st_size / 1024
    logging.info(f"Saved {len(snippets)} snippets → {OUTPUT_FILE} ({size_kb:.1f} KB)")
    logging.info(f"Saved metadata → {METADATA_FILE}")

    print_summary(snippets, skip_reasons)
    print(f"\n✅ Output  : {OUTPUT_FILE.resolve()} ({size_kb:.1f} KB)")
    print(f"✅ Metadata: {METADATA_FILE.resolve()}")
    print(f"✅ Log     : {LOG_FILE.resolve()}")


if __name__ == "__main__":
    main()
