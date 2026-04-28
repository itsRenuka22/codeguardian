"""
Executor: runs each query in the AnalysisPlan through the HybridQuerier,
deduplicates results, and returns a consolidated ExecutionResult.
"""
from dataclasses import dataclass, field
from .planner import AnalysisPlan


@dataclass
class ExecutionResult:
    plan: AnalysisPlan
    matches: list = field(default_factory=list)   # deduplicated enriched hits
    query_hits: dict = field(default_factory=dict) # query -> raw hit list


class Executor:
    def __init__(self, querier):
        self.querier = querier

    def execute(self, plan: AnalysisPlan) -> ExecutionResult:
        result = ExecutionResult(plan=plan)
        seen_ids = set()

        for query in plan.queries:
            hits = self.querier.hybrid_search(query, top_k=plan.top_k)
            result.query_hits[query[:60]] = hits

            for hit in hits:
                code_id = hit.get("code_id", "")
                if code_id and code_id not in seen_ids:
                    seen_ids.add(code_id)
                    result.matches.append(hit)

        # rank: severity first, then by lowest similarity distance
        _severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
        result.matches.sort(key=lambda h: (
            _severity_rank.get(h.get("severity", ""), 4),
            h.get("similarity_distance", 1.0),
        ))

        return result
