"""
Quick smoke test for HybridCritic.

Verifies:
  1. Fast path (no LLM client) returns a valid CriticScore-compatible object
  2. Fast path (high confidence) skips LLM
  3. Slow path (mock LLM, low confidence) gets consulted and merges scores
  4. Stats counters are accurate
  5. HybridCriticScore is accessible from its module

Run from the repo root:
    python tests/quick_test_hybrid.py
"""
import os
import sys
from pathlib import Path

ROOT     = Path(__file__).resolve().parent.parent
GRAPHRAG = ROOT / "graphrag"
sys.path.insert(0, str(GRAPHRAG))
sys.path.insert(0, str(GRAPHRAG / "src"))
sys.path.insert(0, str(GRAPHRAG / "models"))


# ── minimal stubs so we can import without real dependencies ──────────────────

class _FakeQuerier:
    def hybrid_search(self, query, top_k=10):
        return []


def _make_exec_result(matches=None, plan=None):
    from agent.executor import ExecutionResult
    from agent.planner import AnalysisPlan
    p = plan or AnalysisPlan(
        language="python",
        queries=["test query"],
        suspected_vulns=[],
        top_k=5,
        attempt=0,
    )
    return ExecutionResult(plan=p, matches=matches or [])


def _make_critic():
    from agent.hybrid_critic import HybridCritic
    return HybridCritic(llm_client=None, llm_threshold=0.80)


def _make_critic_with_llm(llm_fn):
    from agent.hybrid_critic import HybridCritic
    return HybridCritic(llm_client=llm_fn, llm_threshold=0.80, llm_weight=0.30)


# ── test helpers ──────────────────────────────────────────────────────────────

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
_results = []


def check(name: str, condition: bool, detail: str = ""):
    tag = PASS if condition else FAIL
    suffix = f"  ({detail})" if detail else ""
    print(f"  [{tag}] {name}{suffix}")
    _results.append(condition)


# ── tests ─────────────────────────────────────────────────────────────────────

def test_no_llm_client():
    print("\n--- Test 1: no LLM client (fast path) ---")
    critic = _make_critic()
    result = _make_exec_result()
    score = critic.score("x = 1", result)

    check("returns CriticScore-compatible object", hasattr(score, "confidence"))
    check("verdict is valid string",
          score.verdict in ("vulnerable", "potentially_vulnerable", "clean"))
    check("llm_consulted is False", not score.llm_consulted)
    check("method == graphrag_only", score.method == "graphrag_only")
    check("stats.graphrag_only == 1", critic.stats["graphrag_only"] == 1)
    check("stats.llm_consulted == 0", critic.stats["llm_consulted"] == 0)


def test_high_confidence_skips_llm():
    print("\n--- Test 2: confidence above threshold skips LLM ---")
    consulted = []

    def fake_llm(prompt):
        consulted.append(prompt)
        return '{"verdict":"clean","confidence":0.1,"vulnerability_types":[],"reasoning":"safe"}'

    # Force high confidence by injecting many high-severity matches
    matches = [
        {
            "code_id": f"ex{i}",
            "vulnerability_types": ["sql_injection"],
            "severity": "critical",
            "similarity_distance": 0.10,
            "fix_patterns": [],
            "cwes": [],
            "owasp_docs": [],
        }
        for i in range(10)
    ]
    from agent.hybrid_critic import HybridCritic
    critic = HybridCritic(llm_client=fake_llm, llm_threshold=0.80, llm_weight=0.30)
    result = _make_exec_result(matches=matches)
    score = critic.score(
        "cursor.execute('SELECT * FROM users WHERE id=' + user_id)", result
    )

    check("LLM was NOT called", len(consulted) == 0)
    check("method == graphrag_only", score.method == "graphrag_only")
    check("llm_consulted is False", not score.llm_consulted)


def test_llm_consulted_low_confidence():
    print("\n--- Test 3: low confidence triggers LLM consultation ---")
    llm_calls = []

    def fake_llm(prompt):
        llm_calls.append(prompt)
        return '{"verdict":"vulnerable","confidence":0.75,"vulnerability_types":["sql_injection"],"reasoning":"user input directly in query"}'

    # Zero matches → very low confidence
    from agent.hybrid_critic import HybridCritic
    critic = HybridCritic(llm_client=fake_llm, llm_threshold=0.80, llm_weight=0.30)
    result = _make_exec_result(matches=[])
    score = critic.score(
        "cursor.execute('SELECT * FROM users WHERE id=' + user_id)", result
    )

    check("LLM WAS called", len(llm_calls) == 1)
    check("llm_consulted is True", score.llm_consulted)
    check("method == hybrid", score.method == "hybrid")
    check("llm_verdict stored", score.llm_verdict == "vulnerable")
    check("graphrag_confidence stored", score.graphrag_confidence >= 0.0)
    check("confidence is weighted merge",
          0.0 <= score.confidence <= 1.0,
          f"merged={score.confidence:.3f}")
    check("stats.llm_consulted == 1", critic.stats["llm_consulted"] == 1)


def test_llm_error_falls_back():
    print("\n--- Test 4: LLM error → graceful fallback to GraphRAG result ---")

    def bad_llm(prompt):
        raise RuntimeError("API timeout")

    from agent.hybrid_critic import HybridCritic
    critic = HybridCritic(llm_client=bad_llm, llm_threshold=0.80, llm_weight=0.30)
    result = _make_exec_result(matches=[])
    score = critic.score("def f(): pass", result)

    check("does not raise", True)  # if we got here, no exception
    check("method == graphrag_only", score.method == "graphrag_only")
    check("llm_consulted is False", not score.llm_consulted)
    check("stats.llm_errors == 1", critic.stats["llm_errors"] == 1)


def test_stats_api():
    print("\n--- Test 5: get_stats() returns expected keys ---")
    critic = _make_critic()
    stats = critic.get_stats()

    for key in ("total_cases", "graphrag_only", "llm_consulted",
                "llm_agreed", "llm_disagreed", "llm_rate", "agreement_rate"):
        check(f"stats has '{key}'", key in stats)


def test_hybrid_critic_score_is_importable():
    print("\n--- Test 6: HybridCriticScore importable from module ---")
    try:
        from agent.hybrid_critic import HybridCriticScore
        s = HybridCriticScore(
            confidence=0.5, verdict="clean", should_retry=False,
            retry_reason="", vuln_types_found=[], top_severity="",
        )
        check("HybridCriticScore instantiates", True)
        check("has method field", hasattr(s, "method"))
        check("has llm_consulted field", hasattr(s, "llm_consulted"))
        check("has agreement field", hasattr(s, "agreement"))
    except Exception as exc:
        check("HybridCriticScore instantiates", False, str(exc))


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("HybridCritic Quick Smoke Test")
    print("=" * 60)

    test_no_llm_client()
    test_high_confidence_skips_llm()
    test_llm_consulted_low_confidence()
    test_llm_error_falls_back()
    test_stats_api()
    test_hybrid_critic_score_is_importable()

    passed = sum(_results)
    total  = len(_results)
    print()
    print("=" * 60)
    if passed == total:
        print(f"\033[32mAll {total} checks passed.\033[0m")
    else:
        print(f"\033[31m{total - passed}/{total} checks FAILED.\033[0m")
    print("=" * 60)
    sys.exit(0 if passed == total else 1)
