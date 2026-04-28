"""
Critic: scores an ExecutionResult and decides whether the agent should
retry with a widened query plan.

Confidence formula:
  - Base: min(matches / 3, 1.0)           → 3+ matches = full base score
  - +0.2 if top match severity is critical/high
  - +0.15 if planner suspected vulns appear in matches
  - +0.1 if multiple distinct vuln types found
  - -0.2 if top similarity distance > 0.6  (poor vector match)
  Clamped to [0, 1].

Verdict thresholds:
  >= 0.75 → "vulnerable"
  >= 0.45 → "likely_vulnerable"
  >= 0.20 → "unclear"
  <  0.20 → "likely_clean"
"""
from dataclasses import dataclass
from .executor import ExecutionResult


@dataclass
class CriticScore:
    confidence: float           # 0.0 – 1.0
    verdict: str                # "vulnerable" | "likely_vulnerable" | "unclear" | "likely_clean"
    should_retry: bool
    retry_reason: str
    vuln_types_found: list
    top_severity: str


_VERDICT_THRESHOLDS = [
    (0.75, "vulnerable"),
    (0.45, "likely_vulnerable"),
    (0.20, "unclear"),
    (0.0,  "likely_clean"),
]

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}


class Critic:
    def __init__(self, retry_threshold: float = 0.35, max_retries: int = 2):
        self.retry_threshold = retry_threshold
        self.max_retries = max_retries

    def score(self, result: ExecutionResult) -> CriticScore:
        matches = result.matches
        plan = result.plan

        # ── gather facts ──────────────────────────────────────────────────────
        all_vuln_types = []
        severities = []
        top_distance = 1.0

        for m in matches:
            all_vuln_types.extend(m.get("vulnerability_types", []))
            sev = m.get("severity", "")
            if sev:
                severities.append(sev)
            d = m.get("similarity_distance", 1.0)
            if d < top_distance:
                top_distance = d

        unique_vulns = list(dict.fromkeys(all_vuln_types))  # preserve order, dedupe
        top_severity = min(severities, key=lambda s: _SEV_RANK.get(s, 4), default="")

        # ── confidence score ──────────────────────────────────────────────────
        conf = min(len(matches) / 3.0, 1.0)                       # base

        if top_severity in ("critical", "high"):
            conf += 0.20
        elif top_severity == "medium":
            conf += 0.10

        suspected = set(plan.suspected_vulns)
        if suspected and suspected.intersection(unique_vulns):
            conf += 0.15                                           # planner was right

        if len(set(unique_vulns)) > 1:
            conf += 0.10                                           # diverse findings

        if top_distance > 0.6:
            conf -= 0.20                                           # poor vector match

        conf = round(max(0.0, min(1.0, conf)), 3)

        # ── verdict ───────────────────────────────────────────────────────────
        verdict = "likely_clean"
        for threshold, label in _VERDICT_THRESHOLDS:
            if conf >= threshold:
                verdict = label
                break

        # ── retry decision ────────────────────────────────────────────────────
        should_retry = (
            conf < self.retry_threshold
            and plan.attempt < self.max_retries
        )
        retry_reason = ""
        if should_retry:
            if len(matches) == 0:
                retry_reason = "no matches found"
            elif top_distance > 0.6:
                retry_reason = "poor vector similarity"
            else:
                retry_reason = f"low confidence ({conf})"

        return CriticScore(
            confidence=conf,
            verdict=verdict,
            should_retry=should_retry,
            retry_reason=retry_reason,
            vuln_types_found=unique_vulns,
            top_severity=top_severity,
        )
