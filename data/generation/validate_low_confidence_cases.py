#!/usr/bin/env python3
"""
Validate the generated low-confidence test cases.
Run: python data/generation/validate_low_confidence_cases.py
"""
import json
import re
import sys
from pathlib import Path

ROOT      = Path(__file__).resolve().parent.parent.parent
PROCESSED = ROOT / "data" / "processed"
LC_PATH   = PROCESSED / "low_confidence_cases.json"
EVAL_PATH = PROCESSED / "evaluation_set.json"
MERGED_PATH = PROCESSED / "evaluation_set_hybrid.json"

VALID_LANGUAGES = {"php", "python", "javascript", "java"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "none"}
CWE_PATTERN     = re.compile(r"^(CWE-\d+|N/A)$")

errors   = []
warnings = []
passed   = []


def ok(msg):
    passed.append(msg)
    print(f"  \033[32m✅\033[0m {msg}")


def fail(msg):
    errors.append(msg)
    print(f"  \033[31m❌\033[0m {msg}")


def warn(msg):
    warnings.append(msg)
    print(f"  \033[33m⚠️ \033[0m {msg}")


def validate():
    print("=" * 70)
    print("Validation Report — Low-Confidence Test Cases")
    print("=" * 70)

    # ── Load file ─────────────────────────────────────────────────────────────
    print("\n1. File loading")
    if not LC_PATH.exists():
        fail(f"File not found: {LC_PATH}")
        fail("Run generate_low_confidence_cases.py first")
        return
    with open(LC_PATH) as f:
        data = json.load(f)
    ok(f"File loaded: {LC_PATH.name}")

    cases = data.get("test_cases", [])

    # ── Count ─────────────────────────────────────────────────────────────────
    print("\n2. Count validation")
    if len(cases) == 30:
        ok(f"Exactly 30 test cases")
    else:
        fail(f"Expected 30 cases, got {len(cases)}")

    # ── Sequential IDs ────────────────────────────────────────────────────────
    print("\n3. Test ID validation")
    ids     = [c.get("test_id", "") for c in cases]
    expected = [f"eval_low_{i:03d}" for i in range(1, 31)]
    id_set  = set(ids)

    if len(id_set) == len(ids):
        ok("All test_ids are unique")
    else:
        dupes = [tid for tid in ids if ids.count(tid) > 1]
        fail(f"Duplicate test_ids: {set(dupes)}")

    if ids == expected:
        ok("test_ids are sequential eval_low_001 through eval_low_030")
    else:
        missing = set(expected) - id_set
        extra   = id_set - set(expected)
        if missing:
            fail(f"Missing IDs: {sorted(missing)}")
        if extra:
            fail(f"Unexpected IDs: {sorted(extra)}")

    # ── Required fields ───────────────────────────────────────────────────────
    print("\n4. Required field validation")
    required_top = ["test_id", "source", "original_id", "type", "language",
                    "code", "ground_truth", "expected_citations", "source_metadata"]
    required_gt  = ["vulnerability_types", "severity", "vulnerable",
                    "explanation", "confidence_expectation", "llm_consultation_expected"]
    required_cit = ["cwe", "cwe_name", "owasp_category"]
    required_meta = ["security_level", "category", "designed_for",
                     "expected_graphrag_confidence"]

    field_errors = []
    for c in cases:
        tid = c.get("test_id", "?")
        for f in required_top:
            if f not in c:
                field_errors.append(f"{tid}: missing '{f}'")
        gt = c.get("ground_truth", {})
        for f in required_gt:
            if f not in gt:
                field_errors.append(f"{tid}.ground_truth: missing '{f}'")
        cit = c.get("expected_citations", {})
        for f in required_cit:
            if f not in cit:
                field_errors.append(f"{tid}.expected_citations: missing '{f}'")
        meta = c.get("source_metadata", {})
        for f in required_meta:
            if f not in meta:
                field_errors.append(f"{tid}.source_metadata: missing '{f}'")

    if not field_errors:
        ok("All required fields present in all cases")
    else:
        for e in field_errors:
            fail(e)

    # ── Language distribution ─────────────────────────────────────────────────
    print("\n5. Language distribution")
    lang_counts = {}
    for c in cases:
        lang = c.get("language", "unknown")
        lang_counts[lang] = lang_counts.get(lang, 0) + 1

    for lang in VALID_LANGUAGES:
        count = lang_counts.get(lang, 0)
        print(f"     {lang:12s}: {count}")

    invalid_langs = {l for l in lang_counts if l not in VALID_LANGUAGES}
    if invalid_langs:
        fail(f"Invalid languages found: {invalid_langs}")
    else:
        ok("All languages are valid")

    # ── Vulnerability distribution ────────────────────────────────────────────
    print("\n6. Vulnerability type distribution")
    vuln_counts = {}
    for c in cases:
        for vt in c.get("ground_truth", {}).get("vulnerability_types", []):
            vuln_counts[vt] = vuln_counts.get(vt, 0) + 1
    clean_count = sum(1 for c in cases if not c.get("ground_truth", {}).get("vulnerable", True))
    for vt, cnt in sorted(vuln_counts.items(), key=lambda x: -x[1]):
        print(f"     {vt:30s}: {cnt}")
    print(f"     {'clean (false positive)':30s}: {clean_count}")
    ok("Vulnerability distribution logged")

    # ── Category distribution ─────────────────────────────────────────────────
    print("\n7. Category distribution")
    cat_counts = {}
    for c in cases:
        cat = c.get("source_metadata", {}).get("category", "unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"     {cat:35s}: {cnt}")

    ambig   = cat_counts.get("ambiguous_sanitization", 0)
    ctx     = sum(cat_counts.get(c, 0) for c in ("context_dependent", "second_order", "mixed_patterns"))
    novel   = sum(cat_counts.get(c, 0) for c in ("novel_pattern", "uncommon_vuln"))
    edge    = cat_counts.get("false_positive_test", 0)

    if ambig == 10:
        ok(f"Ambiguous sanitization: {ambig}/10")
    else:
        fail(f"Ambiguous sanitization: {ambig}/10 (expected 10)")
    if ctx >= 7:
        ok(f"Context-dependent: {ctx} (expected ~8)")
    else:
        warn(f"Context-dependent: {ctx} (expected ~8)")
    if novel >= 7:
        ok(f"Novel patterns: {novel} (expected ~8)")
    else:
        warn(f"Novel patterns: {novel} (expected ~8)")
    if edge >= 2:
        ok(f"Edge cases (clean): {edge} (expected ≥2)")
    else:
        fail(f"Edge cases (clean): {edge} (expected ≥2)")

    # ── Content validation ────────────────────────────────────────────────────
    print("\n8. Content validation")
    content_errors = []
    for c in cases:
        tid = c.get("test_id", "?")
        # code not empty
        if not c.get("code", "").strip():
            content_errors.append(f"{tid}: empty code field")
        # explanation not empty
        if not c.get("ground_truth", {}).get("explanation", "").strip():
            content_errors.append(f"{tid}: empty explanation")
        # vulnerable is boolean
        vuln = c.get("ground_truth", {}).get("vulnerable")
        if not isinstance(vuln, bool):
            content_errors.append(f"{tid}: 'vulnerable' is not boolean ({type(vuln).__name__})")
        # confidence_expectation == "low"
        ce = c.get("ground_truth", {}).get("confidence_expectation", "")
        if ce != "low":
            content_errors.append(f"{tid}: confidence_expectation='{ce}' (expected 'low')")
        # llm_consultation_expected == True
        lce = c.get("ground_truth", {}).get("llm_consultation_expected")
        if lce is not True:
            content_errors.append(f"{tid}: llm_consultation_expected={lce} (expected true)")
        # severity valid
        sev = c.get("ground_truth", {}).get("severity", "")
        if sev not in VALID_SEVERITIES:
            content_errors.append(f"{tid}: invalid severity '{sev}'")
        # CWE format
        cwe = c.get("expected_citations", {}).get("cwe", "")
        if not CWE_PATTERN.match(cwe):
            content_errors.append(f"{tid}: invalid CWE format '{cwe}'")
        # source == synthetic
        if c.get("source") != "synthetic":
            content_errors.append(f"{tid}: source='{c.get('source')}' (expected 'synthetic')")

    if not content_errors:
        ok("All content validations passed")
    else:
        for e in content_errors:
            fail(e)

    # ── Merge validation ──────────────────────────────────────────────────────
    print("\n9. Merge validation")
    if not MERGED_PATH.exists():
        warn("Merged file not found — run with --merge flag to create it")
    else:
        with open(MERGED_PATH) as f:
            merged = json.load(f)
        orig_count = len(json.load(open(EVAL_PATH))["test_cases"]) if EVAL_PATH.exists() else 0
        merged_count = len(merged.get("test_cases", []))
        expected_total = orig_count + len(cases)

        if merged_count == expected_total:
            ok(f"Merged file: {orig_count} + {len(cases)} = {merged_count} total cases")
        else:
            fail(f"Merged count {merged_count} ≠ expected {expected_total}")

        merged_ids = [c["test_id"] for c in merged.get("test_cases", [])]
        if len(merged_ids) == len(set(merged_ids)):
            ok("No test_id collisions in merged file")
        else:
            dupes = [t for t in merged_ids if merged_ids.count(t) > 1]
            fail(f"Collision in merged file: {set(dupes)}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Passed:   {len(passed)}")
    print(f"  Warnings: {len(warnings)}")
    print(f"  Failures: {len(errors)}")

    if not errors:
        print(f"\n\033[32m✅ All validations passed — ready for hybrid evaluation\033[0m")
    else:
        print(f"\n\033[31m❌ {len(errors)} validation(s) failed\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    validate()
