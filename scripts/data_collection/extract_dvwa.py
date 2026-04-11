"""
Extract vulnerable PHP code examples from DVWA (Damn Vulnerable Web Application).
Source: GitHub raw download — digininja/DVWA (no local clone required)
Output: data/raw/v2/dvwa/dvwa_vulnerable_code.json + metadata.json

Run from the codeguardian directory:
    python scripts/data_collection/extract_dvwa.py
"""

import json
import logging
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities"
)
DELAY_BETWEEN_DOWNLOADS = 0.3  # seconds — be polite to GitHub

OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "v2" / "dvwa"
OUTPUT_FILE = OUTPUT_DIR / "dvwa_vulnerable_code.json"
METADATA_FILE = OUTPUT_DIR / "metadata.json"
LOG_FILE = Path(__file__).resolve().parent.parent.parent / "logs" / "dvwa_extraction.log"

MIN_FILE_SIZE = 200  # bytes — skip files smaller than this
SECURITY_LEVELS = ["low", "medium", "high"]  # impossible.php is the secure version — skip

CATEGORY_MAPPING = {
    "sqli":          "sql_injection",
    "sqli_blind":    "sql_injection",
    "xss_d":         "xss",
    "xss_r":         "xss",
    "xss_s":         "xss",
    "exec":          "command_injection",
    "upload":        "file_upload",
    "csrf":          "csrf",
    "authbypass":    "auth_bypass",
    "brute":         "auth_bypass",
    "captcha":       "auth_bypass",
    "bac":           "auth_bypass",
    "weak_id":       "auth_bypass",
    "fi":            "path_traversal",
    "open_redirect": "other_injection",
    "csp":           "other_injection",
    "javascript":    "other_injection",
    "cryptography":  "other_injection",
    "api":           "other_injection",
}


# ──────────────────────────────────────────────
# Download
# ──────────────────────────────────────────────

def download_php(vuln_type: str, level: str) -> Optional[str]:
    """Download a PHP source file from GitHub. Returns None on failure."""
    url = f"{GITHUB_RAW_BASE}/{vuln_type}/source/{level}.php"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 404:
            logging.debug(f"404 Not Found: {url}")
            return None
        if resp.status_code != 200:
            logging.warning(f"HTTP {resp.status_code} for {url}")
            return None

        content = resp.text
        # Reject HTML error pages served instead of raw content
        if content.strip().lower().startswith("<!doctype") or "<html" in content[:200].lower():
            logging.debug(f"HTML response (not PHP) for {url}")
            return None

        return content

    except requests.RequestException as e:
        logging.warning(f"Network error for {vuln_type}/{level}.php: {e}")
        return None


# ──────────────────────────────────────────────
# Extraction
# ──────────────────────────────────────────────

def extract_snippets() -> tuple[list, int]:
    """
    Download low/medium/high PHP files for each DVWA vulnerability type.
    Returns (snippets_list, skipped_count).
    """
    snippets = []
    skipped = 0
    snippet_counter = 0

    for vuln_type, category in sorted(CATEGORY_MAPPING.items()):
        for level in SECURITY_LEVELS:
            rel_path = f"vulnerabilities/{vuln_type}/source/{level}.php"
            print(f"⬇️  Fetching {vuln_type}/{level}.php ...", end=" ", flush=True)

            code = download_php(vuln_type, level)
            time.sleep(DELAY_BETWEEN_DOWNLOADS)

            if code is None:
                print(f"⏭️  Not found")
                logging.info(f"Not found (skipped): {rel_path}")
                skipped += 1
                continue

            file_size = len(code.encode("utf-8"))

            if file_size < MIN_FILE_SIZE:
                print(f"⏭️  Skipped (only {file_size}B)")
                logging.info(f"Skipped (too small, {file_size}B): {rel_path}")
                skipped += 1
                continue

            snippet_counter += 1
            snippet_id = f"dvwa_{snippet_counter:03d}"

            snippet = {
                "snippet_id":         snippet_id,
                "source":             "DVWA",
                "language":           "php",
                "category":           category,
                "security_level":     level,
                "vulnerability_type": vuln_type,
                "file_path":          rel_path,
                "file_size":          file_size,
                "code":               code,
                "description":        f"DVWA {vuln_type} - {level} security level",
            }
            snippets.append(snippet)

            print(f"✅ ({file_size}B) → {category}")
            logging.info(f"Extracted [{category}] {vuln_type}/{level}.php ({file_size}B)")

    return snippets, skipped


# ──────────────────────────────────────────────
# Output builders
# ──────────────────────────────────────────────

def build_statistics(snippets: list) -> dict:
    by_category = dict(Counter(s["category"] for s in snippets))
    by_level = dict(Counter(s["security_level"] for s in snippets))
    by_vuln = dict(Counter(s["vulnerability_type"] for s in snippets))
    return {
        "by_category":       by_category,
        "by_security_level": by_level,
        "by_vuln_type":      by_vuln,
    }


def build_output(snippets: list, skipped: int) -> dict:
    return {
        "source":          "DVWA",
        "extraction_date": datetime.now().date().isoformat(),
        "total_snippets":  len(snippets),
        "skipped_count":   skipped,
        "min_file_size":   MIN_FILE_SIZE,
        "snippets":        snippets,
        "statistics":      build_statistics(snippets),
    }


def build_metadata(snippets: list, skipped: int) -> dict:
    stats = build_statistics(snippets)
    return {
        "extraction_date":     datetime.now().isoformat(),
        "source":              "DVWA",
        "github_repo":         "digininja/DVWA",
        "total_snippets":      len(snippets),
        "skipped_count":       skipped,
        "min_file_size":       MIN_FILE_SIZE,
        "security_levels":     SECURITY_LEVELS,
        "language":            "php",
        "category_breakdown":  stats["by_category"],
        "level_breakdown":     stats["by_security_level"],
        "vuln_type_breakdown": stats["by_vuln_type"],
        "cleaning_applied":    False,
        "notes":               "impossible.php skipped (secure reference implementation). Files downloaded directly from GitHub.",
    }


# ──────────────────────────────────────────────
# Summary printer
# ──────────────────────────────────────────────

def print_summary(snippets: list, skipped: int):
    stats = build_statistics(snippets)

    print("\n" + "=" * 60)
    print("📊 DVWA Extraction Summary")
    print("=" * 60)
    print(f"   Total extracted : {len(snippets)}")
    print(f"   Total skipped   : {skipped}")

    print("\n   By Category:")
    for cat, count in sorted(stats["by_category"].items()):
        print(f"   {'✅' if count > 0 else '❌'} {cat:<25}: {count}")

    print("\n   By Security Level:")
    for level, count in sorted(stats["by_security_level"].items()):
        print(f"      {level:<10}: {count}")

    print("\n   By DVWA Vulnerability Type:")
    for vtype, count in sorted(stats["by_vuln_type"].items()):
        print(f"      {vtype:<20}: {count}")

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
    logging.info("Starting DVWA Extraction (GitHub raw download)")
    logging.info(f"Source       : {GITHUB_RAW_BASE}")
    logging.info(f"Output dir   : {OUTPUT_DIR.resolve()}")
    logging.info(f"Min file size: {MIN_FILE_SIZE}B")
    logging.info(f"Levels       : {SECURITY_LEVELS}")
    logging.info("=" * 60)

    snippets, skipped = extract_snippets()

    if not snippets:
        logging.error("No snippets extracted — check network connectivity.")
        print("\n❌ No snippets found. Check your internet connection.")
        return

    output = build_output(snippets, skipped)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    metadata = build_metadata(snippets, skipped)
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    size_kb = OUTPUT_FILE.stat().st_size / 1024
    logging.info(f"Saved {len(snippets)} snippets → {OUTPUT_FILE} ({size_kb:.1f} KB)")
    logging.info(f"Saved metadata → {METADATA_FILE}")

    print_summary(snippets, skipped)
    print(f"\n✅ Output  : {OUTPUT_FILE.resolve()} ({size_kb:.1f} KB)")
    print(f"✅ Metadata: {METADATA_FILE.resolve()}")
    print(f"✅ Log     : {LOG_FILE.resolve()}")


if __name__ == "__main__":
    main()
