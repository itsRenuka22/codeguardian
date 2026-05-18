#!/usr/bin/env python3
"""
Test GeminiClient via OpenRouter API.
Run from repo root: python test_openrouter.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "graphrag"))

SAMPLE_SQL_INJECTION = """
<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $query);
while ($row = mysqli_fetch_assoc($result)) {
    echo $row['username'];
}
?>
"""

VULN_ANALYSIS_PROMPT = f"""Analyze this code for security vulnerabilities. Be concise.

Code:
```php
{SAMPLE_SQL_INJECTION.strip()}
```

Respond with:
1. Vulnerability type(s) found
2. Severity (critical/high/medium/low)
3. One-line fix recommendation
"""


def test_basic_generation(client) -> bool:
    print("\n--- Test 1: Basic text generation ---")
    try:
        response = client.generate("Reply with exactly: OPENROUTER_OK")
        ok = "OPENROUTER_OK" in response
        print(f"  Response: {response.strip()}")
        print(f"  {'✅ PASS' if ok else '❌ FAIL'}")
        return ok
    except Exception as e:
        print(f"  ❌ FAIL — {e}")
        return False


def test_vulnerability_analysis(client) -> bool:
    print("\n--- Test 2: SQL injection vulnerability analysis ---")
    try:
        response = client.generate(VULN_ANALYSIS_PROMPT)
        has_sql = "sql" in response.lower() or "injection" in response.lower()
        has_severity = any(s in response.lower() for s in ["critical", "high", "medium", "low"])
        print(f"  Response ({len(response)} chars):\n")
        for line in response.strip().splitlines():
            print(f"    {line}")
        ok = has_sql and has_severity
        print(f"\n  Detected SQL mention: {has_sql}")
        print(f"  Detected severity:    {has_severity}")
        print(f"  {'✅ PASS' if ok else '❌ FAIL'}")
        return ok
    except Exception as e:
        print(f"  ❌ FAIL — {e}")
        return False


def test_generate_raw(client) -> bool:
    print("\n--- Test 3: generate_raw() (used by HybridCritic) ---")
    try:
        result = client.generate_raw(
            system="You are a security expert. Be brief.",
            prompt="Is `eval(user_input)` dangerous? Answer yes/no and one reason.",
        )
        ok = isinstance(result, dict) and "text" in result and len(result["text"]) > 5
        print(f"  Keys returned: {list(result.keys())}")
        print(f"  Text snippet:  {result['text'][:120].strip()}")
        print(f"  {'✅ PASS' if ok else '❌ FAIL'}")
        return ok
    except Exception as e:
        print(f"  ❌ FAIL — {e}")
        return False


def main():
    print("=" * 60)
    print(f"CodeGuardian — OpenRouter Integration Test")
    print("=" * 60)

    # Check API key
    key = os.getenv("OPENROUTER_API_KEY", "")
    if not key:
        print("❌ OPENROUTER_API_KEY not set in environment")
        sys.exit(1)
    print(f"API key: {key[:8]}…{key[-4:]}")

    # Import and init client
    from models.gemini_client import GeminiClient
    client = GeminiClient()
    print(f"Model:   {client.model_name}")
    print(f"Available: {client.is_available}")

    # Run tests
    results = [
        test_basic_generation(client),
        test_vulnerability_analysis(client),
        test_generate_raw(client),
    ]

    # Summary
    passed = sum(results)
    total = len(results)
    print("\n" + "=" * 60)
    print(f"Results: {passed}/{total} tests passed")
    if passed == total:
        print("✅ All tests passed — OpenRouter integration working")
    else:
        print("❌ Some tests failed — check output above")
    print("=" * 60)

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
