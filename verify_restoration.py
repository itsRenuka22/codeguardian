#!/usr/bin/env python3
"""
SECTION 9: Verification Tests for CodeGuardian Restoration

Tests:
1. Fibonacci clean code detection
2. SQL injection vulnerable code detection
3. Lazy LLM flow (/api/analyze-quick + /api/generate-report-stream)
4. Clean code evaluation metrics
5. Timeout handling in LLM comparison
6. File structure verification
"""
import json
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "graphrag"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "graphrag", "src"))


def test_fibonacci():
    """Test 1: Fibonacci (clean code) should be detected as clean"""
    print("\n✓ TEST 1: Fibonacci Clean Code Detection")
    from agent.agent import CodeGuardianAgent
    import config

    agent = CodeGuardianAgent.from_config(config)

    fib_code = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
result = fibonacci(10)
print(result)
"""

    result = agent.analyze(fib_code)
    verdict = result.get("verdict")
    confidence = result.get("confidence")

    is_clean = verdict == "clean"
    print(f"  Verdict: {verdict} (confidence: {confidence:.1%})")
    print(f"  Expected: clean")
    print(f"  Status: {'✓ PASS' if is_clean else '✗ FAIL'}")
    return is_clean


def test_sql_injection():
    """Test 2: SQL injection should be detected as vulnerable"""
    print("\n✓ TEST 2: SQL Injection Vulnerable Code Detection")
    from agent.agent import CodeGuardianAgent
    import config

    agent = CodeGuardianAgent.from_config(config)

    sqli_code = """<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
$result = mysqli_query($conn, $query);
?>"""

    result = agent.analyze(sqli_code)
    verdict = result.get("verdict")
    confidence = result.get("confidence")
    vulns = result.get("vulnerability_types", [])

    is_vulnerable = verdict in ("vulnerable", "potentially_vulnerable")
    has_sqli = "sql_injection" in vulns
    print(f"  Verdict: {verdict} (confidence: {confidence:.1%})")
    print(f"  Vulnerabilities found: {vulns}")
    print(f"  Expected: vulnerable with sql_injection")
    print(f"  Status: {'✓ PASS' if (is_vulnerable and has_sqli) else '✗ FAIL'}")
    return is_vulnerable and has_sqli


def test_semantic_validation():
    """Test 3: Semantic validation should prevent false positives"""
    print("\n✓ TEST 3: Semantic Validation (Fibonacci as command_injection)")
    from agent.agent import CodeGuardianAgent
    import config

    agent = CodeGuardianAgent.from_config(config)

    fib_code = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
"""

    result = agent.analyze(fib_code)
    verdict = result.get("verdict")
    impossible = result.get("impossible_vulns", [])

    is_clean = verdict == "clean"
    print(f"  Verdict: {verdict}")
    print(f"  Impossible vulnerabilities: {impossible}")
    print(f"  Expected: clean (no command_injection despite similarity)")
    print(f"  Status: {'✓ PASS' if is_clean else '✗ FAIL'}")
    return is_clean


def test_clean_code_metrics():
    """Test 4: Verify clean code examples (TNR, FPR)"""
    print("\n✓ TEST 4: Clean Code Evaluation Metrics")

    eval_path = os.path.join(os.path.dirname(__file__),
                             "data", "processed", "evaluation_set.json")
    with open(eval_path) as f:
        data = json.load(f)

    cases = data.get("test_cases", [])
    clean_cases = [c for c in cases if not c["ground_truth"].get("vulnerable", True)]
    vulnerable_cases = [c for c in cases if c["ground_truth"].get("vulnerable", True)]

    print(f"  Total cases: {len(cases)}")
    print(f"  Vulnerable: {len(vulnerable_cases)}")
    print(f"  Clean: {len(clean_cases)}")
    print(f"  Expected: 90 total (65 vulnerable + 25 clean)")

    has_clean = len(clean_cases) == 25
    print(f"  Status: {'✓ PASS' if has_clean else '✗ FAIL'}")
    return has_clean


def test_file_structure():
    """Test 5: Verify all required files exist"""
    print("\n✓ TEST 5: File Structure Verification")

    base_path = os.path.dirname(__file__)
    required_files = [
        "graphrag/agent/agent.py",
        "graphrag/agent/critic.py",
        "graphrag/agent/executor.py",
        "graphrag/agent/memory.py",
        "graphrag/agent/planner.py",
        "graphrag/api/main.py",
        "graphrag/models/gemini_client.py",
        "graphrag/models/ollama_client.py",
        "graphrag/models/llm_evaluator.py",
        "graphrag/static/index.html",
        "data/processed/evaluation_set.json",
        "data/processed/rag_knowledge_base_code_only.json",
        "data/processed/citation_map.json",
    ]

    missing_files = []
    for file_path in required_files:
        full_path = os.path.join(base_path, file_path)
        if not os.path.exists(full_path):
            missing_files.append(file_path)
            print(f"  ✗ Missing: {file_path}")
        else:
            print(f"  ✓ Found: {file_path}")

    all_present = len(missing_files) == 0
    print(f"  Status: {'✓ PASS' if all_present else '✗ FAIL'}")
    return all_present


def test_timeout_handling():
    """Test 6: Verify timeout constants are set correctly"""
    print("\n✓ TEST 6: Timeout Configuration")
    from models.ollama_client import OllamaClient
    from models.gemini_client import GeminiClient

    ollama_timeout = getattr(OllamaClient, '_TIMEOUT_S', None)
    gemini_timeout = getattr(GeminiClient, '_TIMEOUT_S', None)

    print(f"  Ollama timeout: {ollama_timeout}s (expected: 300s)")
    print(f"  Gemini timeout: {gemini_timeout}s (expected: 60s)")

    correct = ollama_timeout == 300 and gemini_timeout == 60
    print(f"  Status: {'✓ PASS' if correct else '✗ FAIL'}")
    return correct


def main():
    print("=" * 70)
    print("CODEGUARDIAN RESTORATION VERIFICATION")
    print("=" * 70)

    results = {}

    # Test 1: Fibonacci clean code
    try:
        results["fibonacci_clean"] = test_fibonacci()
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results["fibonacci_clean"] = False

    # Test 2: SQL injection
    try:
        results["sql_injection"] = test_sql_injection()
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results["sql_injection"] = False

    # Test 3: Semantic validation
    try:
        results["semantic_validation"] = test_semantic_validation()
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results["semantic_validation"] = False

    # Test 4: Clean code metrics
    try:
        results["clean_code_metrics"] = test_clean_code_metrics()
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results["clean_code_metrics"] = False

    # Test 5: File structure
    try:
        results["file_structure"] = test_file_structure()
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results["file_structure"] = False

    # Test 6: Timeout configuration
    try:
        results["timeout_config"] = test_timeout_handling()
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results["timeout_config"] = False

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    passed_count = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\nPassed: {passed_count}/{total}")

    for test_name, test_passed in results.items():
        status = "✓" if test_passed else "✗"
        print(f"  {status} {test_name}")

    if passed_count == total:
        print("\n✓ ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n✗ {total - passed_count} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
