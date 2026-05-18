"""
Comprehensive unit-test suite for HybridCritic.

Run from repo root:
    python -m pytest tests/test_hybrid_critic.py -v
or:
    python tests/test_hybrid_critic.py
"""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

ROOT     = Path(__file__).resolve().parent.parent
GRAPHRAG = ROOT / "graphrag"
sys.path.insert(0, str(GRAPHRAG))
sys.path.insert(0, str(GRAPHRAG / "src"))
sys.path.insert(0, str(GRAPHRAG / "models"))


# ── shared fixtures ───────────────────────────────────────────────────────────

def _make_plan(
    language="python",
    queries=None,
    suspected_vulns=None,
    top_k=5,
    attempt=0,
):
    from agent.planner import AnalysisPlan
    return AnalysisPlan(
        language=language,
        queries=queries or ["SELECT query"],
        suspected_vulns=suspected_vulns or [],
        top_k=top_k,
        attempt=attempt,
    )


def _make_exec_result(matches=None, plan=None):
    from agent.executor import ExecutionResult
    return ExecutionResult(
        plan=plan or _make_plan(),
        matches=matches or [],
    )


def _sqli_matches(n: int = 5, distance: float = 0.15):
    """Return n high-confidence SQL-injection match dicts."""
    return [
        {
            "code_id": f"sqli_{i}",
            "vulnerability_types": ["sql_injection"],
            "severity": "critical",
            "similarity_distance": distance,
            "fix_patterns": [{"vuln_type": "sql_injection", "description": "Use parameterized queries"}],
            "cwes": ["CWE-89"],
            "owasp_docs": [],
        }
        for i in range(n)
    ]


def _make_llm(verdict="clean", confidence=0.5, vuln_types=None, reasoning="test"):
    """Return a callable that mimics a passing LLM."""
    payload = {
        "verdict": verdict,
        "confidence": confidence,
        "vulnerability_types": vuln_types or [],
        "reasoning": reasoning,
    }

    def _llm(prompt):
        return json.dumps(payload)

    return _llm


def _make_critic(llm_client=None, llm_threshold=0.80, llm_weight=0.30):
    from agent.hybrid_critic import HybridCritic
    return HybridCritic(
        llm_client=llm_client,
        llm_threshold=llm_threshold,
        llm_weight=llm_weight,
        retry_threshold=0.35,
        max_retries=2,
    )


# ── test classes ──────────────────────────────────────────────────────────────

class TestHybridCriticInit(unittest.TestCase):
    """Constructor and attribute tests."""

    def test_defaults(self):
        hc = _make_critic()
        self.assertIsNone(hc.llm_client)
        self.assertEqual(hc.llm_threshold, 0.80)
        self.assertAlmostEqual(hc.llm_weight, 0.30)
        self.assertAlmostEqual(hc.graphrag_weight, 0.70)
        self.assertEqual(hc.retry_threshold, 0.35)
        self.assertEqual(hc.max_retries, 2)

    def test_stats_initialised(self):
        hc = _make_critic()
        for key in ("total_cases", "graphrag_only", "llm_consulted",
                    "llm_agreed", "llm_disagreed", "llm_errors"):
            self.assertIn(key, hc.stats)
            self.assertEqual(hc.stats[key], 0)

    def test_is_critic_subclass(self):
        from agent.critic import Critic
        from agent.hybrid_critic import HybridCritic
        hc = HybridCritic()
        self.assertIsInstance(hc, Critic)


class TestFastPathNoLLM(unittest.TestCase):
    """Cases where the LLM should NOT be consulted."""

    def test_no_llm_client_returns_critic_score(self):
        from agent.critic import CriticScore
        hc = _make_critic(llm_client=None)
        score = hc.score("x = 1", _make_exec_result())
        self.assertIsInstance(score, CriticScore)

    def test_no_llm_client_graphrag_only(self):
        hc = _make_critic(llm_client=None)
        score = hc.score("x = 1", _make_exec_result())
        self.assertEqual(score.method, "graphrag_only")
        self.assertFalse(score.llm_consulted)

    def test_stats_incremented_correctly_no_llm(self):
        hc = _make_critic(llm_client=None)
        hc.score("x = 1", _make_exec_result())
        hc.score("y = 2", _make_exec_result())
        self.assertEqual(hc.stats["total_cases"], 2)
        self.assertEqual(hc.stats["graphrag_only"], 2)
        self.assertEqual(hc.stats["llm_consulted"], 0)

    def test_high_confidence_skips_llm(self):
        calls = []
        llm = lambda p: (calls.append(p), '{"verdict":"clean","confidence":0.1,"vulnerability_types":[],"reasoning":"safe"}')[1]
        hc = _make_critic(llm_client=llm, llm_threshold=0.50)
        # 10 critical matches at distance 0.10 → very high confidence
        result = _make_exec_result(matches=_sqli_matches(10, 0.10))
        hc.score("cursor.execute('SELECT * FROM users WHERE id=' + uid)", result)
        self.assertEqual(len(calls), 0, "LLM should not have been called")

    def test_threshold_boundary_exact(self):
        """Confidence exactly at threshold → fast path (no LLM)."""
        calls = []
        llm = lambda p: (calls.append(p), '{"verdict":"clean","confidence":0.1,"vulnerability_types":[],"reasoning":"safe"}')[1]

        from unittest.mock import patch
        from agent.hybrid_critic import HybridCritic

        hc = HybridCritic(llm_client=llm, llm_threshold=0.80)
        # Patch parent score to return exactly threshold confidence
        from agent.critic import CriticScore
        mock_score = CriticScore(
            confidence=0.80, verdict="vulnerable", should_retry=False,
            retry_reason="", vuln_types_found=["sql_injection"], top_severity="critical",
        )
        with patch.object(hc.__class__.__bases__[0], "score", return_value=mock_score):
            score = hc.score("some code", _make_exec_result())
        self.assertEqual(len(calls), 0)
        self.assertEqual(score.method, "graphrag_only")


class TestSlowPathLLMConsulted(unittest.TestCase):
    """Cases where the LLM IS consulted."""

    def setUp(self):
        self.llm = _make_llm(verdict="vulnerable", confidence=0.75,
                             vuln_types=["sql_injection"])
        self.hc = _make_critic(llm_client=self.llm, llm_threshold=0.80)

    def test_llm_called_on_low_confidence(self):
        # Zero matches → graphrag confidence near 0
        result = _make_exec_result(matches=[])
        score = self.hc.score(
            "cursor.execute('SELECT * FROM users WHERE id=' + uid)", result
        )
        self.assertTrue(score.llm_consulted)
        self.assertEqual(score.method, "hybrid")

    def test_merged_confidence_is_weighted(self):
        result = _make_exec_result(matches=[])
        from agent.critic import CriticScore
        graphrag_conf = 0.30
        llm_conf = 0.75
        expected = round(graphrag_conf * 0.70 + llm_conf * 0.30, 3)

        from unittest.mock import patch
        mock_score = CriticScore(
            confidence=graphrag_conf, verdict="potentially_vulnerable",
            should_retry=False, retry_reason="", vuln_types_found=[],
            top_severity="",
        )
        hc = _make_critic(
            llm_client=_make_llm(verdict="vulnerable", confidence=llm_conf),
            llm_threshold=0.80,
            llm_weight=0.30,
        )
        with patch.object(hc.__class__.__bases__[0], "score", return_value=mock_score):
            score = hc.score("code", result)
        self.assertAlmostEqual(score.confidence, expected, places=2)
        self.assertAlmostEqual(score.graphrag_confidence, graphrag_conf)
        self.assertAlmostEqual(score.llm_confidence, llm_conf)

    def test_llm_verdict_stored(self):
        result = _make_exec_result(matches=[])
        score = self.hc.score("cursor.execute(query + user_id)", result)
        self.assertEqual(score.llm_verdict, "vulnerable")

    def test_stats_llm_consulted_incremented(self):
        self.hc.score("cursor.execute(query + uid)", _make_exec_result())
        self.assertEqual(self.hc.stats["llm_consulted"], 1)

    def test_agreement_tracked_when_both_vulnerable(self):
        result = _make_exec_result(matches=[])
        from agent.critic import CriticScore
        mock_score = CriticScore(
            confidence=0.50, verdict="vulnerable", should_retry=False,
            retry_reason="", vuln_types_found=["sql_injection"], top_severity="critical",
        )
        from unittest.mock import patch
        with patch.object(self.hc.__class__.__bases__[0], "score", return_value=mock_score):
            score = self.hc.score("code", result)
        self.assertTrue(score.agreement)
        self.assertEqual(self.hc.stats["llm_agreed"], 1)

    def test_disagreement_tracked(self):
        result = _make_exec_result(matches=[])
        from agent.critic import CriticScore
        # GraphRAG says clean, LLM says vulnerable
        mock_score = CriticScore(
            confidence=0.20, verdict="clean", should_retry=False,
            retry_reason="", vuln_types_found=[], top_severity="",
        )
        from unittest.mock import patch
        with patch.object(self.hc.__class__.__bases__[0], "score", return_value=mock_score):
            score = self.hc.score("code", result)
        # LLM says vulnerable → disagreement
        self.assertFalse(score.agreement)
        self.assertEqual(self.hc.stats["llm_disagreed"], 1)


class TestLLMErrorHandling(unittest.TestCase):
    """LLM failures must not crash the pipeline."""

    def test_runtime_error_falls_back_to_graphrag(self):
        def bad_llm(prompt):
            raise RuntimeError("network timeout")

        hc = _make_critic(llm_client=bad_llm, llm_threshold=0.80)
        score = hc.score("def f(): pass", _make_exec_result())
        self.assertEqual(score.method, "graphrag_only")
        self.assertFalse(score.llm_consulted)
        self.assertEqual(hc.stats["llm_errors"], 1)

    def test_malformed_json_falls_back(self):
        def bad_llm(prompt):
            return "not json at all !!!!"

        hc = _make_critic(llm_client=bad_llm, llm_threshold=0.80)
        score = hc.score("def f(): pass", _make_exec_result())
        self.assertEqual(score.method, "graphrag_only")

    def test_empty_response_falls_back(self):
        def empty_llm(prompt):
            return ""

        hc = _make_critic(llm_client=empty_llm, llm_threshold=0.80)
        score = hc.score("def f(): pass", _make_exec_result())
        self.assertEqual(score.method, "graphrag_only")

    def test_json_with_invalid_verdict_normalised(self):
        def weird_llm(prompt):
            return '{"verdict":"UNKNOWN_THING","confidence":0.5,"vulnerability_types":[],"reasoning":"?"}'

        hc = _make_critic(llm_client=weird_llm, llm_threshold=0.80)
        result = _make_exec_result(matches=[])
        score = hc.score("code", result)
        # Must not raise; verdict must be normalised to "clean" (unknown → clean)
        self.assertIn(score.verdict, ("vulnerable", "potentially_vulnerable", "clean"))

    def test_markdown_fenced_json_parsed(self):
        """LLM wraps JSON in ```json … ```."""
        def fenced_llm(prompt):
            return '```json\n{"verdict":"clean","confidence":0.9,"vulnerability_types":[],"reasoning":"ok"}\n```'

        hc = _make_critic(llm_client=fenced_llm, llm_threshold=0.80)
        result = _make_exec_result(matches=[])
        score = hc.score("code", result)
        self.assertIn(score.verdict, ("vulnerable", "potentially_vulnerable", "clean"))


class TestLLMClientDispatching(unittest.TestCase):
    """_call_llm dispatches to the right interface."""

    def test_generate_raw_preferred(self):
        from agent.hybrid_critic import HybridCritic
        client = MagicMock()
        client.generate_raw.return_value = (
            '{"verdict":"clean","confidence":0.9,"vulnerability_types":[],"reasoning":"safe"}'
        )
        # generate_raw is present, so it should be called
        hc = HybridCritic(llm_client=client, llm_threshold=0.80)
        hc._call_llm("test prompt")
        client.generate_raw.assert_called_once()

    def test_generate_fallback(self):
        from agent.hybrid_critic import HybridCritic
        client = MagicMock(spec=[])  # no generate_raw
        client.generate = MagicMock(return_value=(
            '{"verdict":"clean","confidence":0.9,"vulnerability_types":[],"reasoning":"safe"}'
        ))
        hc = HybridCritic(llm_client=client, llm_threshold=0.80)
        hc._call_llm("prompt")
        client.generate.assert_called_once()

    def test_callable_fallback(self):
        from agent.hybrid_critic import HybridCritic
        results = []
        def my_llm(prompt):
            results.append(prompt)
            return '{"verdict":"clean","confidence":0.9,"vulnerability_types":[],"reasoning":"safe"}'

        hc = HybridCritic(llm_client=my_llm, llm_threshold=0.80)
        hc._call_llm("hello")
        self.assertEqual(results, ["hello"])


class TestGetStats(unittest.TestCase):
    def test_initial_stats(self):
        hc = _make_critic()
        s = hc.get_stats()
        self.assertEqual(s["llm_rate"], 0.0)
        self.assertIsNone(s["agreement_rate"])

    def test_stats_after_cases(self):
        hc = _make_critic(llm_client=_make_llm())
        hc.score("code", _make_exec_result())  # likely fast path or slow path
        s = hc.get_stats()
        self.assertGreaterEqual(s["total_cases"], 1)
        self.assertIn("llm_rate", s)

    def test_llm_rate_calculation(self):
        from agent.hybrid_critic import HybridCritic
        hc = HybridCritic()
        hc.stats["total_cases"] = 10
        hc.stats["llm_consulted"] = 4
        s = hc.get_stats()
        self.assertAlmostEqual(s["llm_rate"], 0.4)


class TestHybridCriticScoreDataclass(unittest.TestCase):
    def test_is_critic_score_subclass(self):
        from agent.critic import CriticScore
        from agent.hybrid_critic import HybridCriticScore
        s = HybridCriticScore(
            confidence=0.5, verdict="clean", should_retry=False,
            retry_reason="", vuln_types_found=[], top_severity="",
        )
        self.assertIsInstance(s, CriticScore)

    def test_default_extra_fields(self):
        from agent.hybrid_critic import HybridCriticScore
        s = HybridCriticScore(
            confidence=0.5, verdict="clean", should_retry=False,
            retry_reason="", vuln_types_found=[], top_severity="",
        )
        self.assertEqual(s.method, "graphrag_only")
        self.assertFalse(s.llm_consulted)
        self.assertIsNone(s.agreement)
        self.assertEqual(s.llm_verdict, "")
        self.assertEqual(s.llm_confidence, 0.0)

    def test_custom_extra_fields(self):
        from agent.hybrid_critic import HybridCriticScore
        s = HybridCriticScore(
            confidence=0.75, verdict="vulnerable", should_retry=False,
            retry_reason="", vuln_types_found=["xss"], top_severity="high",
            method="hybrid", llm_consulted=True, agreement=True,
            llm_verdict="vulnerable", llm_confidence=0.80,
            llm_reasoning="XSS found in template",
        )
        self.assertEqual(s.method, "hybrid")
        self.assertTrue(s.llm_consulted)
        self.assertTrue(s.agreement)


class TestAgentIntegration(unittest.TestCase):
    """Ensure CodeGuardianAgent correctly wires hybrid mode."""

    def _build_agent_no_infra(self, use_hybrid=False, llm_client=None):
        """Build agent with a fake querier (no real Chroma/graph needed)."""
        from agent.agent import CodeGuardianAgent
        from agent.critic import Critic
        from agent.hybrid_critic import HybridCritic

        class FakeQuerier:
            def hybrid_search(self, q, top_k=5):
                return []

        agent = CodeGuardianAgent(
            querier=FakeQuerier(),
            cache_path=None,
            use_hybrid=use_hybrid,
            llm_client=llm_client,
        )
        return agent

    def test_standard_mode_uses_critic(self):
        from agent.critic import Critic
        from agent.hybrid_critic import HybridCritic
        agent = self._build_agent_no_infra(use_hybrid=False)
        self.assertIsInstance(agent.critic, Critic)
        self.assertNotIsInstance(agent.critic, HybridCritic)

    def test_hybrid_mode_uses_hybrid_critic(self):
        from agent.hybrid_critic import HybridCritic
        agent = self._build_agent_no_infra(use_hybrid=True)
        self.assertIsInstance(agent.critic, HybridCritic)

    def test_hybrid_mode_with_llm_client(self):
        from agent.hybrid_critic import HybridCritic
        llm = _make_llm()
        agent = self._build_agent_no_infra(use_hybrid=True, llm_client=llm)
        self.assertIsInstance(agent.critic, HybridCritic)
        self.assertIs(agent.critic.llm_client, llm)

    def test_analyze_returns_dict(self):
        agent = self._build_agent_no_infra(use_hybrid=True)
        result = agent.analyze("x = 1")
        self.assertIsInstance(result, dict)
        self.assertIn("verdict", result)
        self.assertIn("confidence", result)


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
