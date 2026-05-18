"""
Critic: scores an ExecutionResult with semantic validation to prevent false positives.

Confidence formula:
  - Base: min(matches / 5, 0.7)            → more conservative
  - +0.20 if top match severity is critical/high
  - +0.15 if planner suspected vulns appear in matches
  - +0.10 if multiple distinct vuln types found
  - Tiered distance penalties:
      > 0.50  →  -0.40
      > 0.35  →  -0.25
      > 0.25  →  -0.10
  - Semantic penalty: -0.30 per impossible vulnerability
  - If ALL flagged vulns are impossible → floor score at 0.1
  Clamped to [0, 1].

Verdict thresholds (distance-aware):
  top_distance < 0.25  →  vulnerable_threshold = 0.60
  top_distance < 0.35  →  vulnerable_threshold = 0.75
  top_distance >= 0.35 →  vulnerable_threshold = 0.90
  >= vulnerable_threshold  →  "vulnerable"
  >= 0.55                  →  "potentially_vulnerable"
  <  0.55                  →  "clean"
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .executor import ExecutionResult


@dataclass
class CriticScore:
    confidence: float
    verdict: str                 # "vulnerable" | "potentially_vulnerable" | "clean"
    should_retry: bool
    retry_reason: str
    vuln_types_found: list
    top_severity: str
    impossible_vulns: list = field(default_factory=list)
    patterns_found: dict  = field(default_factory=dict)


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}


class Critic:
    def __init__(self, retry_threshold: float = 0.35, max_retries: int = 2):
        self.retry_threshold = retry_threshold
        self.max_retries     = max_retries

    # ── semantic validation ───────────────────────────────────────────────────

    def _validate_semantic_possibility(
        self, code: str, flagged_vulns: List[str]
    ) -> Dict[str, Any]:
        """
        Check if flagged vulnerabilities are semantically possible in the code.

        Returns a dict with 'impossible_vulns' and 'patterns_found'.
        """
        patterns = {
            "has_os_calls":   bool(re.search(
                r"(os\.|subprocess|exec|system|popen|spawn)", code, re.IGNORECASE)),
            "has_file_ops":   bool(re.search(
                r"(open\(|Path\(|\.read|\.write|file|fopen|fwrite)", code, re.IGNORECASE)),
            "has_sql":        bool(re.search(
                r"(execute\(|cursor|query|SELECT|INSERT|UPDATE|DELETE|prepare)",
                code, re.IGNORECASE)),
            "has_network":    bool(re.search(
                r"(requests\.|urllib|socket|http|fetch|curl)", code, re.IGNORECASE)),
            "has_eval":       bool(re.search(r"(eval\(|exec\()", code, re.IGNORECASE)),
            "has_user_input": bool(re.search(
                r"(\$_GET|\$_POST|request\.|input\(|argv|args\.|query)", code, re.IGNORECASE)),
        }

        has_any_input = (
            patterns["has_user_input"] or patterns["has_sql"]
            or patterns["has_eval"]    or patterns["has_network"]
        )

        impossible_vulns = []
        for vuln in flagged_vulns:
            if   vuln == "command_injection"  and not patterns["has_os_calls"]:
                impossible_vulns.append(vuln)
            elif vuln == "path_traversal"     and not patterns["has_file_ops"]:
                impossible_vulns.append(vuln)
            elif vuln == "sql_injection"      and not patterns["has_sql"]:
                impossible_vulns.append(vuln)
            elif vuln == "ssrf"               and not patterns["has_network"]:
                impossible_vulns.append(vuln)
            elif vuln in ("code_injection", "rce") and not patterns["has_eval"]:
                impossible_vulns.append(vuln)
            elif vuln == "file_upload"        and not patterns["has_file_ops"]:
                impossible_vulns.append(vuln)
            elif vuln == "auth_bypass"        and not patterns["has_user_input"]:
                impossible_vulns.append(vuln)
            elif vuln in ("other_injection", "ldap_injection", "xxe") and not has_any_input:
                impossible_vulns.append(vuln)

        return {"impossible_vulns": impossible_vulns, "patterns_found": patterns}

    # ── verdict helper ────────────────────────────────────────────────────────

    def _verdict_from_score(self, conf: float, top_distance: float) -> str:
        """Map confidence + distance to a verdict string."""
        if top_distance < 0.25:
            vulnerable_threshold = 0.60   # very similar — trust the match
        elif top_distance < 0.35:
            vulnerable_threshold = 0.75   # moderately similar — be cautious
        else:
            vulnerable_threshold = 0.90   # weak similarity — very conservative

        if conf >= vulnerable_threshold:
            return "vulnerable"
        elif conf >= 0.55:
            return "potentially_vulnerable"
        else:
            return "clean"

    # ── main scoring ──────────────────────────────────────────────────────────

    def score(self, code: str, result: ExecutionResult) -> CriticScore:
        matches = result.matches
        plan    = result.plan

        # ── gather facts ──────────────────────────────────────────────────────
        all_vuln_types: List[str] = []
        severities: List[str]     = []
        top_distance              = 1.0

        for m in matches:
            all_vuln_types.extend(m.get("vulnerability_types", []))
            sev = m.get("severity", "")
            if sev:
                severities.append(sev)
            d = m.get("similarity_distance", 1.0)
            if d < top_distance:
                top_distance = d

        unique_vulns = list(dict.fromkeys(all_vuln_types))   # order-preserving dedup
        top_severity = min(
            severities, key=lambda s: _SEV_RANK.get(s, 4), default=""
        )

        # ── confidence score ──────────────────────────────────────────────────
        conf = min(len(matches) / 5.0, 0.7)                  # conservative base

        if top_severity in ("critical", "high"):
            conf += 0.20
        elif top_severity == "medium":
            conf += 0.10

        suspected = set(plan.suspected_vulns)
        if suspected and suspected.intersection(unique_vulns):
            conf += 0.15                                      # planner was right

        if len(set(unique_vulns)) > 1:
            conf += 0.10                                      # diverse findings

        # Tiered distance penalties
        if top_distance > 0.50:
            conf -= 0.40
        elif top_distance > 0.35:
            conf -= 0.25
        elif top_distance > 0.25:
            conf -= 0.10

        # ── semantic validation ───────────────────────────────────────────────
        semantic_check   = self._validate_semantic_possibility(code, unique_vulns)
        impossible_count = len(semantic_check["impossible_vulns"])
        real_count       = len(unique_vulns) - impossible_count

        if impossible_count > 0:
            if real_count > 0:
                # Some vulns are real — light penalty for noise only
                conf -= min(impossible_count * 0.05, 0.20)
            else:
                # All vulns impossible — heavy penalty
                conf -= impossible_count * 0.30
                # Floor at 0.1 (not zero, just very low)
                if unique_vulns:
                    conf = max(conf, 0.1)

        conf = round(max(0.0, min(1.0, conf)), 3)

        # ── verdict ───────────────────────────────────────────────────────────
        verdict = self._verdict_from_score(conf, top_distance)

        # ── retry decision ────────────────────────────────────────────────────
        # Skip retry if all vulns are semantically impossible — widening the
        # query cannot fix a semantic mismatch between code and flagged vulns.
        all_impossible = bool(unique_vulns) and impossible_count == len(unique_vulns)
        should_retry = (
            conf < self.retry_threshold
            and plan.attempt < self.max_retries
            and not all_impossible
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
            confidence       = conf,
            verdict          = verdict,
            should_retry     = should_retry,
            retry_reason     = retry_reason,
            vuln_types_found = unique_vulns,
            top_severity     = top_severity,
            impossible_vulns = semantic_check["impossible_vulns"],
            patterns_found   = semantic_check["patterns_found"],
        )
