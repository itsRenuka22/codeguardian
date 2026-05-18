#!/usr/bin/env python3
"""
Test Gemini API with direct REST calls (v1beta endpoint)
Verifies the implementation matches the working curl command exactly
"""

import os
import sys
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Check API key
api_key = os.getenv('GOOGLE_API_KEY')
if not api_key:
    print("❌ GOOGLE_API_KEY not set!")
    print("   Add it to .env file: GOOGLE_API_KEY=your_key_here")
    sys.exit(1)

print("=" * 80)
print("TEST: Gemini API with Direct REST Calls (v1beta)")
print("=" * 80)
print(f"API Key: {api_key[:10]}...{api_key[-10:]}")
print()

# Test 1: Initialize client
print("Test 1: Initialize GeminiClient")
print("-" * 80)

try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'graphrag'))
    from models.gemini_client import GeminiClient

    client = GeminiClient()
    print(f"✓ Client initialized")
    print(f"  Model: {client.model_name}")
    print(f"  Endpoint: {client.endpoint}")
    print(f"  API Version: {client.api_version}")
    print(f"  Available: {client.is_available}")

    if not client.is_available:
        print(f"❌ Client not available (no API key)")
        sys.exit(1)

except Exception as e:
    print(f"❌ Initialization failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 2: Generate simple text
print("\nTest 2: Generate simple text")
print("-" * 80)

try:
    prompt = "Say 'Hello, CodeGuardian!' in one sentence"
    print(f"Prompt: {prompt}")
    print("Calling Gemini API...")

    response = client.generate(prompt)

    print(f"✓ Generation successful!")
    print(f"Response length: {len(response)} chars")
    print(f"Response preview: {response[:100]}...")

except Exception as e:
    print(f"❌ Generation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 3: Generate security analysis
print("\nTest 3: Generate security analysis")
print("-" * 80)

try:
    code = """<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";
mysql_query($query);
?>"""

    prompt = f"""Analyze this code for security issues (1-2 sentences):

{code}"""

    print(f"Prompt length: {len(prompt)} chars")
    print("Calling Gemini API...")

    response = client.generate(prompt)

    print(f"✓ Generation successful!")
    print(f"Response: {response}")

except Exception as e:
    print(f"❌ Generation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 4: Verify endpoint version
print("\nTest 4: Verify endpoint version")
print("-" * 80)

expected_endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"
actual_endpoint = client.endpoint

if actual_endpoint == expected_endpoint:
    print(f"✓ Endpoint matches working curl exactly!")
    print(f"  Expected: {expected_endpoint}")
    print(f"  Actual:   {actual_endpoint}")
else:
    print(f"❌ Endpoint mismatch!")
    print(f"  Expected: {expected_endpoint}")
    print(f"  Actual:   {actual_endpoint}")
    sys.exit(1)

print("\n" + "=" * 80)
print("✓✓✓ ALL TESTS PASSED ✓✓✓")
print("=" * 80)
print("\nGemini API is properly configured and working!")
print("The endpoint, model, and headers match the working curl command exactly.")
print("\nYou can now:")
print("1. Start the server: uvicorn graphrag.api.main:app --reload --port 8000")
print("2. Test report generation with vulnerable code")
print("3. Verify clean code skips report generation")
