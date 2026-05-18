"""
HybridCritic: combines GraphRAG scoring with optional LLM validation for
uncertain cases (confidence below llm_threshold).

Flow:
  1. Always run GraphRAG-based Critic (parent class) first
  2. If confidence >= llm_threshold OR no llm_client → return GraphRAG result
  3. Otherwise consult the LLM for a second opinion
  4. Merge: 70% GraphRAG weight + 30% LLM weight
  5. Re-derive verdict from merged confidence

The returned object is always a CriticScore (fully compatible with the
existing pipeline), extended with hybrid metadata fields.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Optional

from .critic import Critic, CriticScore, _SEV_RANK
from .executor import ExecutionResult


@dataclass
class HybridCriticScore(CriticScore):
    """CriticScore extended with hybrid-specific metadata."""
    method: str = "graphrag_only"           # "graphrag_only" | "hybrid"
    llm_consulted: bool = False
    agreement: Optional[bool] = None        # True/False/None
    graphrag_confidence: float = 0.0
    graphrag_verdict: str = ""
    llm_verdict: str = ""
    llm_confidence: float = 0.0
    llm_reasoning: str = ""


_VERDICT_SCORE = {
    "vulnerable": 0.85,
    "potentially_vulnerable": 0.60,
    "clean": 0.20,
}

_LLM_SYSTEM_PROMPT = """\
You are a strict security code reviewer. Analyse the provided code snippet for \
security vulnerabilities and respond ONLY with valid JSON — no markdown, no prose.

Response schema:
{
  "verdict": "vulnerable" | "potentially_vulnerable" | "clean",
  "confidence": <float 0.0-1.0>,
  "vulnerability_types": [<string>, ...],
  "reasoning": "<one concise sentence>"
}"""

_LLM_USER_TEMPLATE = """\
Code to analyse:
```
{code}
```

GraphRAG pre-analysis context (do NOT simply repeat this — form your own view):
- GraphRAG verdict: {graphrag_verdict}
- GraphRAG confidence: {graphrag_confidence:.2f}
- Suspected vulnerability types: {suspected_vulns}
- Top matching evidence snippets: {evidence_summary}

Respond with JSON only."""


class HybridCritic(Critic):
    """
    Drop-in replacement for Critic that optionally consults an LLM when the
    GraphRAG confidence is below `llm_threshold`.
    """

    def __init__(
        self,
        llm_client=None,
        llm_threshold: float = 0.85,
        llm_weight: float = 0.30,
        retry_threshold: float = 0.35,
        max_retries: int = 2,
    ):
        super().__init__(retry_threshold=retry_threshold, max_retries=max_retries)
        self.llm_client = llm_client
        self.llm_threshold = llm_threshold
        self.llm_weight = llm_weight
        self.graphrag_weight = 1.0 - llm_weight

        self.stats: dict = {
            "total_cases": 0,
            "graphrag_only": 0,
            "llm_consulted": 0,
            "llm_agreed": 0,
            "llm_disagreed": 0,
            "llm_errors": 0,
        }

    # ── main entry point ──────────────────────────────────────────────────────

    def score(self, code: str, result: ExecutionResult) -> CriticScore:
        """Override Critic.score — returns a HybridCriticScore."""
        graphrag_score: CriticScore = super().score(code, result)
        self.stats["total_cases"] += 1

        top_distance = self._top_distance(result)

        # Fast path — GraphRAG is already confident enough
        if graphrag_score.confidence >= self.llm_threshold or self.llm_client is None:
            self.stats["graphrag_only"] += 1
            return self._wrap_graphrag_only(graphrag_score, top_distance)

        # Slow path — ask the LLM
        self.stats["llm_consulted"] += 1
        llm_result = self._consult_llm(code, result, graphrag_score)

        if llm_result is None:
            # LLM failed — fall back gracefully
            self.stats["llm_errors"] += 1
            self.stats["graphrag_only"] += 1
            return self._wrap_graphrag_only(graphrag_score, top_distance)

        return self._merge(graphrag_score, llm_result, top_distance)

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _top_distance(result: ExecutionResult) -> float:
        distances = [m.get("similarity_distance", 1.0) for m in result.matches]
        return min(distances) if distances else 1.0

    def _wrap_graphrag_only(
        self, graphrag_score: CriticScore, top_distance: float
    ) -> HybridCriticScore:
        """Promote a plain CriticScore to HybridCriticScore with graphrag_only metadata."""
        return HybridCriticScore(
            # ── CriticScore fields ──
            confidence=graphrag_score.confidence,
            verdict=graphrag_score.verdict,
            should_retry=graphrag_score.should_retry,
            retry_reason=graphrag_score.retry_reason,
            vuln_types_found=graphrag_score.vuln_types_found,
            top_severity=graphrag_score.top_severity,
            impossible_vulns=graphrag_score.impossible_vulns,
            patterns_found=graphrag_score.patterns_found,
            # ── hybrid metadata ──
            method="graphrag_only",
            llm_consulted=False,
            agreement=None,
            graphrag_confidence=graphrag_score.confidence,
            graphrag_verdict=graphrag_score.verdict,
            llm_verdict="",
            llm_confidence=0.0,
            llm_reasoning="",
        )

    def _consult_llm(
        self,
        code: str,
        result: ExecutionResult,
        graphrag_score: CriticScore,
    ) -> Optional[dict]:
        """
        Ask the LLM to evaluate the code.  Returns a dict with keys:
          verdict, confidence, vulnerability_types, reasoning
        or None on error.
        """
        evidence_summary = self._build_evidence_summary(result.matches)
        prompt = _LLM_USER_TEMPLATE.format(
            code=code[:3000],  # cap to avoid token explosion
            graphrag_verdict=graphrag_score.verdict,
            graphrag_confidence=graphrag_score.confidence,
            suspected_vulns=", ".join(result.plan.suspected_vulns) or "none",
            evidence_summary=evidence_summary,
        )

        try:
            raw = self._call_llm(prompt)
            return self._parse_llm_response(raw)
        except Exception:
            return None

    def _call_llm(self, prompt: str) -> str:
        """Dispatch to whatever LLM client is available."""
        # GeminiClient (direct REST) via generate_raw()
        # generate_raw() returns a dict {"text": ..., ...} — extract just the text
        if hasattr(self.llm_client, "generate_raw"):
            result = self.llm_client.generate_raw(_LLM_SYSTEM_PROMPT, prompt)
            if isinstance(result, dict):
                return result.get("text", "")
            return result
        # OllamaClient via generate()
        if hasattr(self.llm_client, "generate"):
            full_prompt = f"{_LLM_SYSTEM_PROMPT}\n\n{prompt}"
            return self.llm_client.generate(full_prompt)
        # Callable fallback
        if callable(self.llm_client):
            return self.llm_client(prompt)
        raise TypeError(f"Unsupported LLM client type: {type(self.llm_client)}")

    @staticmethod
    def _parse_llm_response(raw: str) -> Optional[dict]:
        """Extract the JSON payload from the LLM response."""
        if not raw:
            return None
        # strip markdown fences if present
        text = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()
        # try to find the outermost JSON object
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None
        payload = json.loads(match.group())
        verdict = payload.get("verdict", "").lower()
        if verdict not in ("vulnerable", "potentially_vulnerable", "clean"):
            verdict = "clean"
        confidence = float(payload.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))
        return {
            "verdict": verdict,
            "confidence": confidence,
            "vulnerability_types": payload.get("vulnerability_types", []),
            "reasoning": payload.get("reasoning", ""),
        }

    def _merge(
        self,
        graphrag_score: CriticScore,
        llm_result: dict,
        top_distance: float,
    ) -> HybridCriticScore:
        """
        Merge GraphRAG and LLM scores.

        When the two sources disagree on the binary clean/not-clean axis, the
        LLM verdict wins outright — it was specifically invoked to resolve the
        low-confidence case and has broader context than the similarity index.
        When they agree, confidence is boosted via a weighted average.
        """
        g_conf = graphrag_score.confidence
        l_conf = llm_result["confidence"]
        g_verdict = graphrag_score.verdict
        l_verdict = llm_result["verdict"]

        # Agreement: do the verdicts agree on the binary clean/not-clean axis?
        g_is_vuln = g_verdict != "clean"
        l_is_vuln = l_verdict != "clean"
        agreed = g_is_vuln == l_is_vuln

        if agreed:
            self.stats["llm_agreed"] += 1
            # Both agree — weighted merge boosts confidence
            merged_conf = round(
                g_conf * self.graphrag_weight + l_conf * self.llm_weight, 3
            )
            merged_conf = max(0.0, min(1.0, merged_conf))
            merged_verdict = self._verdict_from_score(merged_conf, top_distance)
            final_conf = merged_conf
        else:
            # Disagreement — LLM overrides GraphRAG
            self.stats["llm_disagreed"] += 1
            merged_verdict = l_verdict
            final_conf = round(l_conf, 3)
            print(
                f"  🔄 OVERRIDE: GraphRAG={g_verdict}({g_conf:.2f}) → "
                f"LLM={l_verdict}({l_conf:.2f})"
            )

        # Combine vuln types (GraphRAG is authoritative; LLM supplements)
        combined_vulns = list(dict.fromkeys(
            graphrag_score.vuln_types_found + llm_result.get("vulnerability_types", [])
        ))

        # Highest severity stays from GraphRAG
        top_severity = graphrag_score.top_severity

        # Retry decision stays consistent with the base class
        all_impossible = (
            bool(combined_vulns)
            and len(graphrag_score.impossible_vulns) == len(combined_vulns)
        )
        should_retry = (
            final_conf < self.retry_threshold
            and graphrag_score.vuln_types_found
            and not all_impossible
        )

        return HybridCriticScore(
            # ── CriticScore fields ──
            confidence=final_conf,
            verdict=merged_verdict,
            should_retry=should_retry,
            retry_reason=graphrag_score.retry_reason if should_retry else "",
            vuln_types_found=combined_vulns,
            top_severity=top_severity,
            impossible_vulns=graphrag_score.impossible_vulns,
            patterns_found=graphrag_score.patterns_found,
            # ── hybrid metadata ──
            method="hybrid",
            llm_consulted=True,
            agreement=agreed,
            graphrag_confidence=g_conf,
            graphrag_verdict=g_verdict,
            llm_verdict=l_verdict,
            llm_confidence=l_conf,
            llm_reasoning=llm_result.get("reasoning", ""),
        )

    @staticmethod
    def _build_evidence_summary(matches: list) -> str:
        """Summarise top-3 matches into a compact string for the LLM prompt."""
        parts = []
        for m in matches[:3]:
            vts = ", ".join(m.get("vulnerability_types", []))
            dist = m.get("similarity_distance", 1.0)
            parts.append(f"[{vts or 'unknown'} dist={dist:.3f}]")
        return "; ".join(parts) if parts else "none"

    # ── analytics ─────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return a snapshot of LLM-consultation statistics."""
        s = dict(self.stats)
        total = s["total_cases"]
        s["llm_rate"] = round(s["llm_consulted"] / total, 3) if total else 0.0
        s["agreement_rate"] = (
            round(s["llm_agreed"] / s["llm_consulted"], 3)
            if s["llm_consulted"] else None
        )
        return s
