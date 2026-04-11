"""
Clean and recategorize the DVWA vulnerable code collection.
Input : data/raw/v2/dvwa/dvwa_vulnerable_code.json
Output: data/raw/v2/dvwa/dvwa_vulnerable_code_cleaned.json
        data/raw/v2/dvwa/metadata_cleaned.json

Run from the codeguardian directory:
    python scripts/data_collection/clean_dvwa_collection.py
"""

import json
import logging
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────

DATA_DIR      = Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "v2" / "dvwa"
INPUT_FILE    = DATA_DIR / "dvwa_vulnerable_code.json"
OUTPUT_FILE   = DATA_DIR / "dvwa_vulnerable_code_cleaned.json"
METADATA_FILE = DATA_DIR / "metadata_cleaned.json"
LOG_FILE      = Path(__file__).resolve().parent.parent.parent / "logs" / "dvwa_cleaning.log"


# ──────────────────────────────────────────────
# Quality thresholds
# ──────────────────────────────────────────────

MIN_PHP_RATIO      = 0.20   # at least 20% of content must be PHP code
MIN_EFFECTIVE_SIZE = 200    # bytes of actual PHP code after stripping HTML/JS


# ──────────────────────────────────────────────
# Categorization rules
# ──────────────────────────────────────────────

RECATEGORIZE = {
    "csp":        "xss",   # CSP bypass is an XSS-adjacent web vuln
    "javascript": "xss",   # Client-side JavaScript issues → XSS
}

REMOVE_CATEGORIES = {
    "cryptography",  # Crypto weaknesses need different tooling; not raw injection patterns
}

# For these vuln types, keep only if specific pattern groups are found
REVIEW_BY_CONTENT = {
    "api": {
        "check_patterns": ["sql", "user_input"],
        "fallback_category": None,  # Remove if patterns not found
    },
    "open_redirect": {
        "check_patterns": ["user_input"],
        "fallback_category": None,
    },
}


# ──────────────────────────────────────────────
# Quality filters
# ──────────────────────────────────────────────

def calculate_php_ratio(code: str) -> float:
    """
    Estimate how much of the file is actual PHP vs HTML/JavaScript template noise.
    Returns a 0.0–1.0 ratio; higher is better.
    """
    if not code:
        return 0.0

    # Remove <script>...</script> blocks
    no_js = re.sub(r"<script[^>]*>.*?</script>", "", code, flags=re.DOTALL | re.IGNORECASE)

    # Remove HTML assignment lines: $html .= "<div>...</div>";
    no_html_assign = re.sub(r'\$html\s*\.?=\s*["\'].*?["\'];', "", no_js, flags=re.DOTALL)

    # Remove standalone HTML tags
    no_html_tags = re.sub(r"<[^>]+>", "", no_html_assign)

    # Remove HTML entities (&amp; &lt; etc.)
    no_entities = re.sub(r"&[a-z]+;", "", no_html_tags, flags=re.IGNORECASE)

    php_code = no_entities.strip()
    return len(php_code) / len(code)


def get_effective_code_size(code: str) -> int:
    """Return byte count of actual PHP code after stripping HTML and JS."""
    no_js   = re.sub(r"<script[^>]*>.*?</script>", "", code, flags=re.DOTALL | re.IGNORECASE)
    no_html = re.sub(r'\$html\s*\.?=\s*["\'].*?["\'];', "", no_js, flags=re.DOTALL)
    clean   = re.sub(r"<[^>]+>", "", no_html)
    return len(clean.strip().encode("utf-8"))


# Pattern groups used by has_vulnerable_patterns AND REVIEW_BY_CONTENT
_PATTERN_GROUPS = {
    "user_input": [
        r"\$_GET\[",
        r"\$_POST\[",
        r"\$_REQUEST\[",
        r"\$_COOKIE\[",
        r"\$_FILES\[",
    ],
    "sql": [
        r"mysql_query\s*\(",
        r"mysqli_query\s*\(",
        r"SELECT\s+.*\s+FROM",
        r"INSERT\s+INTO",
        r"UPDATE\s+.*\s+SET",
        r"DELETE\s+FROM",
    ],
    "command_exec": [
        r"system\s*\(",
        r"exec\s*\(",
        r"shell_exec\s*\(",
        r"passthru\s*\(",
        r"popen\s*\(",
    ],
    "file_ops": [
        r"file_get_contents\s*\(",
        r"fopen\s*\(",
        r"readfile\s*\(",
        r"include\s*\(",
        r"require\s*\(",
        r"move_uploaded_file\s*\(",
    ],
}

_COMPILED_PATTERNS = {
    group: [re.compile(p, re.IGNORECASE) for p in patterns]
    for group, patterns in _PATTERN_GROUPS.items()
}


def has_vulnerable_patterns(code: str) -> tuple[bool, list[str]]:
    """Return (found, matched_groups) where matched_groups is a list of group names."""
    matched = [
        group
        for group, compiled in _COMPILED_PATTERNS.items()
        if any(p.search(code) for p in compiled)
    ]
    return bool(matched), matched


# ──────────────────────────────────────────────
# Per-snippet processing
# ──────────────────────────────────────────────

def process_snippet(snippet: dict, idx: int, total: int) -> tuple[Optional[dict], str, str]:
    """
    Apply quality filters and recategorization rules to one snippet.

    Returns:
        (result_snippet_or_None, status_label, reason_string)
        status_label: "kept" | "recategorized" | "removed"
        reason_string: human-readable explanation
    """
    sid      = snippet["snippet_id"]
    vtype    = snippet["vulnerability_type"]
    category = snippet["category"]

    print(f"\nProcessing snippet {idx}/{total}: {sid} ({vtype}/{snippet.get('security_level', '?')})")
    logging.info(f"Processing {sid} ({vtype}/{snippet.get('security_level', '?')})")

    # ── Immediate category removal ──
    if vtype in REMOVE_CATEGORIES:
        msg = f"Category removed ({vtype})"
        print(f"   ❌ REMOVED: {msg}")
        logging.info(f"  Removed — {msg}")
        return None, "removed", msg

    code = snippet.get("code", "")

    # ── Filter 1: PHP code ratio ──
    php_ratio = calculate_php_ratio(code)
    ratio_pct = f"{php_ratio * 100:.0f}%"
    if php_ratio < MIN_PHP_RATIO:
        msg = "Low PHP code ratio (mostly HTML/JavaScript)"
        print(f"   PHP Ratio: {ratio_pct} ❌ REMOVED: {msg}")
        logging.info(f"  Removed — {msg} (ratio={ratio_pct})")
        return None, "removed", msg
    print(f"   PHP Ratio: {ratio_pct} ✅")

    # ── Filter 2: Vulnerable pattern detection ──
    found_patterns, matched = has_vulnerable_patterns(code)
    if not found_patterns:
        msg = "No vulnerable PHP patterns detected"
        print(f"   Patterns: none ❌ REMOVED: {msg}")
        logging.info(f"  Removed — {msg}")
        return None, "removed", msg
    print(f"   Patterns: {matched} ✅")

    # ── Filter 3: Effective code size ──
    eff_size = get_effective_code_size(code)
    if eff_size < MIN_EFFECTIVE_SIZE:
        msg = f"Effective code size too small (<{MIN_EFFECTIVE_SIZE} bytes)"
        print(f"   Effective Size: {eff_size}B ❌ REMOVED: {msg}")
        logging.info(f"  Removed — {msg} (size={eff_size}B)")
        return None, "removed", msg
    print(f"   Effective Size: {eff_size}B ✅")

    # ── Content-dependent review ──
    if vtype in REVIEW_BY_CONTENT:
        rule = REVIEW_BY_CONTENT[vtype]
        if not any(p in matched for p in rule["check_patterns"]):
            msg = f"Removed {vtype}: no relevant patterns (need {rule['check_patterns']}, got {matched})"
            print(f"   ❌ REMOVED: {msg}")
            logging.info(f"  Removed — {msg}")
            return None, "removed", msg

    # ── Recategorization ──
    if vtype in RECATEGORIZE:
        new_category = RECATEGORIZE[vtype]
        updated = dict(snippet)
        updated["original_category"] = category
        updated["category"] = new_category
        msg = f"{vtype}: {category} → {new_category}"
        print(f"   Status: RECATEGORIZED ({msg})")
        logging.info(f"  Recategorized — {msg}")
        return updated, "recategorized", msg

    # ── Keep unchanged ──
    print(f"   Status: KEPT")
    logging.info(f"  Kept unchanged")
    return snippet, "kept", "kept"


# ──────────────────────────────────────────────
# Statistics helpers
# ──────────────────────────────────────────────

def build_statistics(snippets: list) -> dict:
    return {
        "by_category":       dict(Counter(s["category"] for s in snippets)),
        "by_security_level": dict(Counter(s["security_level"] for s in snippets)),
        "by_vuln_type":      dict(Counter(s["vulnerability_type"] for s in snippets)),
    }


# ──────────────────────────────────────────────
# Summary printer
# ──────────────────────────────────────────────

def print_summary(
    original: list,
    cleaned: list,
    removed_reasons: Counter,
    recategorized: Counter,
    original_cat_counts: dict,
):
    stats = build_statistics(cleaned)

    print("\n" + "=" * 60)
    print("=== Cleaning Summary ===")
    print("=" * 60)
    print(f"   Original snippets : {len(original)}")
    print(f"   Cleaned snippets  : {len(cleaned)}")
    print(f"   Removed           : {len(original) - len(cleaned)}")

    if removed_reasons:
        print("\n   Removed by reason:")
        for reason, count in removed_reasons.most_common():
            print(f"      {reason:<45}: {count}")

    if recategorized:
        print("\n   Recategorized:")
        for change, count in recategorized.most_common():
            print(f"      {change}: {count}")

    print("\n   Final category breakdown:")
    for cat, count in sorted(stats["by_category"].items()):
        orig = original_cat_counts.get(cat, 0)
        diff = count - orig
        diff_str = f"  (was {orig}, {'+' if diff >= 0 else ''}{diff} from recategorization)" if diff != 0 else ""
        print(f"      {cat:<25}: {count}{diff_str}")

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

    if not INPUT_FILE.exists():
        logging.error(f"Input file not found: {INPUT_FILE}")
        print(f"❌ Input file not found: {INPUT_FILE}")
        print("   Run extract_dvwa.py first.")
        return

    with open(INPUT_FILE, encoding="utf-8") as f:
        data = json.load(f)

    original_snippets = data.get("snippets", [])
    original_count    = len(original_snippets)
    original_cat_counts = dict(Counter(s["category"] for s in original_snippets))

    logging.info("=" * 60)
    logging.info(f"Starting DVWA Cleaning — {original_count} snippets")
    logging.info(f"Input : {INPUT_FILE}")
    logging.info(f"Output: {OUTPUT_FILE}")
    logging.info("=" * 60)

    print(f"\n=== DVWA Collection Cleaning ===")
    print(f"Input : {INPUT_FILE}")
    print(f"Total : {original_count} snippets\n")

    cleaned_snippets = []
    removed_reasons  = Counter()
    recategorized    = Counter()

    for idx, snippet in enumerate(original_snippets, start=1):
        result, status, reason = process_snippet(snippet, idx, original_count)

        if status == "removed":
            removed_reasons[reason] += 1
        elif status == "recategorized":
            recategorized[reason] += 1
            cleaned_snippets.append(result)
        else:
            cleaned_snippets.append(result)

    # ── Build output ──
    output = {
        "source":           "DVWA",
        "extraction_date":  data.get("extraction_date", ""),
        "cleaning_date":    datetime.now().isoformat(),
        "original_count":   original_count,
        "cleaned_count":    len(cleaned_snippets),
        "removed_count":    original_count - len(cleaned_snippets),
        "snippets":         cleaned_snippets,
        "cleaning_summary": {
            "removed_by_reason": dict(removed_reasons),
            "recategorized":     dict(recategorized),
        },
        "statistics":       build_statistics(cleaned_snippets),
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # ── Build metadata ──
    stats = build_statistics(cleaned_snippets)
    metadata = {
        "cleaning_date":       datetime.now().isoformat(),
        "source":              "DVWA",
        "original_count":      original_count,
        "cleaned_count":       len(cleaned_snippets),
        "removed_count":       original_count - len(cleaned_snippets),
        "min_php_ratio":       MIN_PHP_RATIO,
        "min_effective_size":  MIN_EFFECTIVE_SIZE,
        "language":            "php",
        "category_breakdown":  stats["by_category"],
        "level_breakdown":     stats["by_security_level"],
        "vuln_type_breakdown": stats["by_vuln_type"],
        "cleaning_applied":    True,
        "cleaning_rules": {
            "recategorized":        RECATEGORIZE,
            "removed_categories":   list(REMOVE_CATEGORIES),
            "content_reviewed":     list(REVIEW_BY_CONTENT.keys()),
        },
        "removed_by_reason":   dict(removed_reasons),
        "recategorized":       dict(recategorized),
    }

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    size_kb = OUTPUT_FILE.stat().st_size / 1024
    logging.info(f"Saved {len(cleaned_snippets)} snippets → {OUTPUT_FILE} ({size_kb:.1f} KB)")
    logging.info(f"Saved metadata → {METADATA_FILE}")

    print_summary(original_snippets, cleaned_snippets, removed_reasons, recategorized, original_cat_counts)

    print(f"\n✅ Cleaned output : {OUTPUT_FILE.resolve()} ({size_kb:.1f} KB)")
    print(f"✅ Metadata       : {METADATA_FILE.resolve()}")
    print(f"✅ Log            : {LOG_FILE.resolve()}")


if __name__ == "__main__":
    main()
