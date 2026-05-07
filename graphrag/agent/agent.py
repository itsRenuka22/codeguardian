"""
CodeGuardianAgent: orchestrates the planner → executor → critic loop.

Usage:
    from agent.agent import CodeGuardianAgent
    agent = CodeGuardianAgent.from_config(config)
    result = agent.analyze(code_snippet)
"""
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from .planner import Planner
from .executor import Executor
from .critic import Critic
from .memory import Memory
from line_detector import detect_vulnerable_lines


class CodeGuardianAgent:
    def __init__(self, querier, cache_path: str = None):
        self.planner = Planner()
        self.executor = Executor(querier)
        self.critic = Critic(retry_threshold=0.35, max_retries=2)
        cache_path = cache_path or os.path.join(
            os.path.dirname(__file__), "..", "data", "agent_cache.json"
        )
        self.memory = Memory(cache_path)

    # ── factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config):
        """Build a ready-to-use agent from the project config module."""
        import chromadb
        from graph_store import make_graph_store
        from graph_builder import GraphBuilder
        from vector_indexer import VectorIndexer
        from hybrid_querier import HybridQuerier

        graph_local = os.path.join(os.path.dirname(config.__file__), "data", "graph_db")
        store = make_graph_store(
            neo4j_uri=config.NEO4J_URI,
            neo4j_user=config.NEO4J_USER,
            neo4j_password=config.NEO4J_PASSWORD,
            local_path=graph_local,
        )

        if store.count("CodeExample") == 0:
            print("Graph empty — building...")
            with open(config.KNOWLEDGE_BASE_PATH) as f:
                kb = json.load(f)
            with open(config.CITATION_MAP_PATH) as f:
                cm = json.load(f)
            GraphBuilder(store).build_complete_graph(kb, cm)

        indexer = VectorIndexer(config.CHROMA_PATH, config.EMBEDDING_MODEL)
        indexer._get_or_create_collection()
        if indexer.collection.count() == 0:
            print("Vector index empty — indexing...")
            with open(config.KNOWLEDGE_BASE_PATH) as f:
                kb = json.load(f)
            indexer.index_all_code(kb)

        chroma_client = chromadb.PersistentClient(path=config.CHROMA_PATH)
        querier = HybridQuerier(store, chroma_client, config.CHROMA_COLLECTION_NAME)

        cache_path = os.path.join(os.path.dirname(config.__file__), "data", "agent_cache.json")
        return cls(querier=querier, cache_path=cache_path)

    # ── main API ──────────────────────────────────────────────────────────────

    def analyze(self, code: str) -> dict:
        """
        Full planner → executor → critic pipeline with retry on low confidence.
        Returns a structured result dict.
        """
        # cache hit
        cached = self.memory.get(code)
        if cached:
            return {**cached, "from_cache": True}

        plan = self.planner.plan(code)
        iterations = 0

        while True:
            iterations += 1
            exec_result = self.executor.execute(plan)
            score = self.critic.score(code, exec_result)

            if not score.should_retry:
                break
            plan = self.planner.replan(code, plan, score.retry_reason)

        output = self._format(code, plan, exec_result, score, iterations)
        self.memory.store(code, output)
        return output

    # ── formatting ────────────────────────────────────────────────────────────

    def _format(self, code, plan, exec_result, score, iterations) -> dict:
        matches = exec_result.matches
        is_clean   = score.verdict == "clean"
        impossible = set(score.impossible_vulns)
        possible_vulns = [v for v in score.vuln_types_found if v not in impossible]

        evidence = []
        for m in matches[:5]:
            evidence.append({
                "code_id":            m.get("code_id", ""),
                "language":           m.get("language", ""),
                "severity":           m.get("severity", ""),
                "vulnerability_types":m.get("vulnerability_types", []),
                "similarity_distance":round(m.get("similarity_distance", 1.0), 4),
                "cwes":               m.get("cwes", []),
                "owasp_docs":         [{"title": o["title"], "url": o["url"]}
                                       for o in m.get("owasp_docs", [])],
            })

        fix_guidance = []
        seen_fixes = set()
        for m in matches:
            for fp in m.get("fix_patterns", []):
                desc = fp.get("description", "")
                vt   = fp.get("vuln_type", "")
                if desc and desc not in seen_fixes and vt not in impossible:
                    seen_fixes.add(desc)
                    fix_guidance.append({
                        "vuln_type":   vt,
                        "description": desc,
                    })

        line_findings = detect_vulnerable_lines(code, possible_vulns)

        return {
            "verdict":              score.verdict,
            "confidence":           score.confidence,
            "vulnerability_types":  possible_vulns,
            "all_matched_vulns":    score.vuln_types_found,
            "top_severity":         "" if is_clean else score.top_severity,
            "language_detected":    plan.language,
            "suspected_by_planner": plan.suspected_vulns,
            "evidence":             [] if is_clean else evidence,
            "fix_guidance":         [] if is_clean else fix_guidance,
            "line_findings":        [] if is_clean else line_findings,
            "total_matches":        len(matches),
            "iterations":           iterations,
            "impossible_vulns":     score.impossible_vulns,
            "patterns_found":       score.patterns_found,
            "from_cache":           False,
        }

    # ── utilities ─────────────────────────────────────────────────────────────

    def memory_stats(self) -> dict:
        return self.memory.stats()

    def clear_cache(self):
        self.memory.clear()
