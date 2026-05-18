"""
Realistic test case: code that GraphRAG struggles with (confidence < 0.80)
but an LLM can confidently evaluate.

This demonstrates the practical value of the hybrid critic:
- GraphRAG finds weak/distant matches (low confidence)
- LLM provides independent analysis (higher confidence)
- Merged score is more reliable than either alone

Run:
    python -m pytest tests/test_hybrid_realistic.py -v -s
or:
    python tests/test_hybrid_realistic.py
"""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT     = Path(__file__).resolve().parent.parent
GRAPHRAG = ROOT / "graphrag"
sys.path.insert(0, str(GRAPHRAG))
sys.path.insert(0, str(GRAPHRAG / "src"))
sys.path.insert(0, str(GRAPHRAG / "models"))


# ── test case: weak retrieval + strong LLM analysis ─────────────────────────

class TestHybridRealisticCase(unittest.TestCase):
    """
    Real-world scenario:
    - Code with a subtle SQL injection that retrieval struggles to match
    - GraphRAG finds only 1-2 weak matches → confidence ~0.45
    - LLM can analyze the code directly → confidence 0.85
    - Hybrid merge → ~0.63 (more reliable than 0.45 alone)
    """

    def setUp(self):
        from agent.planner import AnalysisPlan
        from agent.executor import ExecutionResult
        from agent.hybrid_critic import HybridCritic

        # Real code with a subtle SQL injection
        self.code = """\
def search_user(user_id):
    # User-supplied ID is not validated before query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
"""

        # Plan that suspected SQL injection
        self.plan = AnalysisPlan(
            language="python",
            queries=[
                "string concatenation with user input in SQL",
                "user input directly in database query",
            ],
            suspected_vulns=["sql_injection"],
            top_k=5,
            attempt=0,
        )

        # Weak retrieval: only 1 somewhat-distant match
        self.weak_matches = [
            {
                "code_id": "ex_234",
                "language": "python",
                "vulnerability_types": ["sql_injection"],
                "severity": "high",
                "similarity_distance": 0.42,  # >0.35 → -0.25 penalty
                "fix_patterns": [
                    {
                        "vuln_type": "sql_injection",
                        "description": "Use parameterized queries to prevent injection",
                    }
                ],
                "cwes": ["CWE-89"],
                "owasp_docs": [
                    {"title": "A03:2021 – Injection", "url": "https://owasp.org/..."}
                ],
            }
        ]

        self.exec_result = ExecutionResult(
            plan=self.plan,
            matches=self.weak_matches,
        )

        # Mock LLM that confidently identifies the vuln
        self.llm_response = """{
            "verdict": "vulnerable",
            "confidence": 0.85,
            "vulnerability_types": ["sql_injection"],
            "reasoning": "User-supplied user_id is interpolated directly into SQL query without parameterization."
        }"""

        def mock_llm(prompt):
            return self.llm_response

        self.llm = mock_llm

    def test_graphrag_alone_low_confidence(self):
        """GraphRAG with weak retrieval → low confidence."""
        from agent.hybrid_critic import HybridCritic

        critic = HybridCritic(llm_client=None)
        score = critic.score(self.code, self.exec_result)

        print(f"\n📊 GraphRAG-only score:")
        print(f"   Confidence: {score.confidence:.3f} (threshold=0.80)")
        print(f"   Verdict: {score.verdict}")
        print(f"   Matches: {len(self.weak_matches)}")
        print(f"   Top distance: {self.weak_matches[0]['similarity_distance']:.3f}")

        # With 1 match (0.7 base - 0.25 distance penalty + 0.20 high sev = 0.65)
        # or similar low value
        self.assertLess(score.confidence, 0.80,
                        "GraphRAG should score below threshold with weak retrieval")
        self.assertIn(score.verdict, ("vulnerable", "potentially_vulnerable"))

    def test_llm_alone_high_confidence(self):
        """LLM directly analyzing code → high confidence."""
        # Just parse the LLM response directly
        import json
        llm_data = json.loads(self.llm_response)
        print(f"\n🤖 LLM direct analysis:")
        print(f"   Confidence: {llm_data['confidence']:.3f}")
        print(f"   Verdict: {llm_data['verdict']}")
        print(f"   Reasoning: {llm_data['reasoning']}")

        self.assertGreater(llm_data["confidence"], 0.80)
        self.assertEqual(llm_data["verdict"], "vulnerable")

    def test_hybrid_merge_balances_both(self):
        """HybridCritic consults LLM when GraphRAG is weak."""
        from agent.hybrid_critic import HybridCritic

        hybrid_critic = HybridCritic(
            llm_client=self.llm,
            llm_threshold=0.80,
            llm_weight=0.30,  # 30% LLM, 70% GraphRAG
        )

        score = hybrid_critic.score(self.code, self.exec_result)

        print(f"\n🔀 Hybrid merge (70% GraphRAG + 30% LLM):")
        print(f"   GraphRAG confidence: {score.graphrag_confidence:.3f}")
        print(f"   LLM confidence: {score.llm_confidence:.3f}")
        print(f"   Merged confidence: {score.confidence:.3f}")
        print(f"   Final verdict: {score.verdict}")
        print(f"   Method: {score.method}")
        print(f"   LLM consulted: {score.llm_consulted}")
        print(f"   Agreement: {score.agreement}")

        # Verify hybrid path was taken
        self.assertTrue(score.llm_consulted, "LLM should be consulted")
        self.assertEqual(score.method, "hybrid")

        # GraphRAG was weak
        self.assertLess(score.graphrag_confidence, 0.80)

        # LLM was confident
        self.assertGreater(score.llm_confidence, 0.80)

        # Merged is between them (closer to GraphRAG due to weight)
        merged_expected = round(
            score.graphrag_confidence * 0.70 + score.llm_confidence * 0.30, 3
        )
        self.assertAlmostEqual(score.confidence, merged_expected, places=2)

        # Both agreed it's vulnerable
        self.assertTrue(score.agreement)

    def test_stats_track_hybrid_usage(self):
        """Stats correctly track that LLM was consulted."""
        from agent.hybrid_critic import HybridCritic

        hybrid_critic = HybridCritic(
            llm_client=self.llm,
            llm_threshold=0.80,
        )

        score = hybrid_critic.score(self.code, self.exec_result)
        stats = hybrid_critic.get_stats()

        print(f"\n📈 HybridCritic stats after 1 case:")
        print(f"   Total cases: {stats['total_cases']}")
        print(f"   GraphRAG-only: {stats['graphrag_only']}")
        print(f"   LLM consulted: {stats['llm_consulted']}")
        print(f"   LLM agreed: {stats['llm_agreed']}")
        print(f"   LLM disagreed: {stats['llm_disagreed']}")
        print(f"   LLM rate: {stats['llm_rate']:.1%}")
        print(f"   Agreement rate: {stats['agreement_rate']:.1%}")

        self.assertEqual(stats["total_cases"], 1)
        self.assertEqual(stats["llm_consulted"], 1)
        self.assertEqual(stats["llm_agreed"], 1)
        self.assertEqual(stats["llm_rate"], 1.0)
        self.assertEqual(stats["agreement_rate"], 1.0)

    def test_disagreement_case(self):
        """What if LLM disagrees with GraphRAG?"""
        from agent.hybrid_critic import HybridCritic

        # LLM thinks it's clean (false negative from LLM)
        llm_disagree = """{
            "verdict": "clean",
            "confidence": 0.70,
            "vulnerability_types": [],
            "reasoning": "Variable interpolation is normal in Python"
        }"""

        def mock_llm_disagree(prompt):
            return llm_disagree

        hybrid_critic = HybridCritic(
            llm_client=mock_llm_disagree,
            llm_threshold=0.80,
            llm_weight=0.30,
        )

        score = hybrid_critic.score(self.code, self.exec_result)

        print(f"\n⚠️  Disagreement case (GraphRAG: vulnerable, LLM: clean):")
        print(f"   GraphRAG verdict: {score.graphrag_verdict}")
        print(f"   LLM verdict: {score.llm_verdict}")
        print(f"   Agreement: {score.agreement}")
        print(f"   Final verdict: {score.verdict}")
        print(f"   Final confidence: {score.confidence:.3f}")

        self.assertFalse(score.agreement)
        # Final verdict still likely "vulnerable" due to GraphRAG weight (0.70)
        # but with lower confidence due to LLM disagreement


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
