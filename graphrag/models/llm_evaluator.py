"""
LLMEvaluator: run test cases directly through an LLM as a zero-shot classifier.

This is separate from the full GraphRAG pipeline and measures raw LLM
classification ability as a baseline / comparison metric.
"""
import re
import json
import time

_CLASSIFY_SYSTEM = (
    "You are a code security analyzer. "
    "Analyze code for vulnerabilities and respond ONLY with valid JSON — no markdown, no prose."
)

_VULN_TYPES = (
    "sql_injection, xss, command_injection, path_traversal, xxe, ssrf, "
    "open_redirect, insecure_deserialization, broken_authentication, "
    "sensitive_data_exposure, security_misconfiguration, buffer_overflow"
)


def build_classify_prompt(code: str) -> str:
    snippet = code[:800] + ("…" if len(code) > 800 else "")
    return f"""Analyze this code for security vulnerabilities.

Code:
```
{snippet}
```

Return ONLY this JSON object (no markdown, no other text):
{{
  "verdict": "vulnerable",
  "vulnerability_types": ["sql_injection"],
  "severity": "high",
  "reasoning": "brief one-sentence explanation"
}}

Verdict must be one of: vulnerable, likely_vulnerable, likely_safe, safe
Severity must be one of: critical, high, medium, low, none
Use these exact type names where applicable: {_VULN_TYPES}"""


def _extract_json(text: str) -> dict:
    """Robustly extract JSON from LLM output that may include markdown fences."""
    m = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    m = re.search(r'\{[\s\S]*\}', text)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {}


class LLMEvaluator:
    """Evaluates a single code snippet through a raw LLM call (zero-shot classification)."""

    def evaluate_case(self, code: str, llm_client, timeout_s: int = 300) -> dict:
        """
        Returns:
          verdict, vulnerability_types, severity, reasoning,
          cost_usd, latency_s, input_tokens, output_tokens

        Raises:
          TimeoutError: if the LLM call exceeds timeout_s
          RuntimeError: on other LLM errors
        """
        import socket
        import urllib.error

        prompt = build_classify_prompt(code)
        t0 = time.time()

        try:
            raw = llm_client.generate_raw(_CLASSIFY_SYSTEM, prompt)
        except (socket.timeout, urllib.error.URLError) as exc:
            elapsed = time.time() - t0
            raise TimeoutError(
                f"{llm_client.display_name} did not respond within {timeout_s}s "
                f"(elapsed: {elapsed:.1f}s)"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"{llm_client.display_name} error: {str(exc)}") from exc

        latency = time.time() - t0
        parsed = _extract_json(raw["text"])

        return {
            "verdict":            parsed.get("verdict", "safe"),
            "vulnerability_types": parsed.get("vulnerability_types", []),
            "severity":           parsed.get("severity", "none"),
            "reasoning":          parsed.get("reasoning", ""),
            "cost_usd":           raw["cost_usd"],
            "latency_s":          round(latency, 2),
            "input_tokens":       raw["input_tokens"],
            "output_tokens":      raw["output_tokens"],
        }
