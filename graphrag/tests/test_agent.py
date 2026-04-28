import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.planner import Planner, detect_language, detect_vuln_hints
from agent.critic import Critic
from agent.memory import Memory


# ── planner ───────────────────────────────────────────────────────────────────

def test_detect_php():
    assert detect_language("<?php $id = $_GET['id']; echo $id; ?>") == "php"

def test_detect_python():
    assert detect_language("import os\nos.system(request.args.get('cmd'))") == "python"

def test_detect_java():
    assert detect_language("public class Foo { String x = request.getParameter(\"id\"); }") == "java"

def test_vuln_hints_sql():
    hints = detect_vuln_hints("mysqli_query($conn, $query);")
    assert "sql_injection" in hints

def test_vuln_hints_xss():
    hints = detect_vuln_hints("echo $_GET['name'];")
    assert "xss" in hints

def test_vuln_hints_cmd():
    hints = detect_vuln_hints("system($_POST['cmd']);")
    assert "command_injection" in hints

def test_planner_builds_queries():
    plan = Planner().plan("<?php $id = $_GET['id']; mysqli_query($conn, $query); ?>")
    assert len(plan.queries) >= 2
    assert plan.language == "php"
    assert "sql_injection" in plan.suspected_vulns

def test_planner_replan_widens_topk():
    planner = Planner()
    plan = planner.plan("eval($_GET['x']);")
    replan = planner.replan("eval($_GET['x']);", plan, "low confidence")
    assert replan.top_k > plan.top_k
    assert replan.attempt == 1


# ── critic ────────────────────────────────────────────────────────────────────

from agent.planner import AnalysisPlan
from agent.executor import ExecutionResult

def _make_result(matches, suspected=None):
    plan = AnalysisPlan(language="php", suspected_vulns=suspected or [])
    r = ExecutionResult(plan=plan)
    r.matches = matches
    return r

def test_critic_high_confidence():
    matches = [
        {"vulnerability_types": ["sql_injection"], "severity": "critical", "similarity_distance": 0.1},
        {"vulnerability_types": ["sql_injection"], "severity": "high",     "similarity_distance": 0.15},
        {"vulnerability_types": ["sql_injection"], "severity": "critical", "similarity_distance": 0.2},
    ]
    score = Critic().score(_make_result(matches, ["sql_injection"]))
    assert score.confidence >= 0.7
    assert score.verdict in ("vulnerable", "likely_vulnerable")
    assert not score.should_retry

def test_critic_no_matches_suggests_retry():
    score = Critic().score(_make_result([]))
    assert score.should_retry
    assert score.verdict == "likely_clean"

def test_critic_poor_distance_lowers_confidence():
    matches = [{"vulnerability_types": ["xss"], "severity": "low", "similarity_distance": 0.9}]
    score = Critic().score(_make_result(matches))
    assert score.confidence < 0.5

def test_critic_vuln_types_extracted():
    matches = [
        {"vulnerability_types": ["sql_injection"], "severity": "critical", "similarity_distance": 0.1},
        {"vulnerability_types": ["xss"],           "severity": "high",     "similarity_distance": 0.2},
    ]
    score = Critic().score(_make_result(matches))
    assert "sql_injection" in score.vuln_types_found
    assert "xss" in score.vuln_types_found


# ── memory ────────────────────────────────────────────────────────────────────

def test_memory_store_and_retrieve(tmp_path):
    mem = Memory(str(tmp_path / "cache.json"))
    mem.store("SELECT * FROM users", {"verdict": "vulnerable", "confidence": 0.9})
    hit = mem.get("SELECT * FROM users")
    assert hit is not None
    assert hit["verdict"] == "vulnerable"

def test_memory_miss(tmp_path):
    mem = Memory(str(tmp_path / "cache.json"))
    assert mem.get("some unknown code") is None

def test_memory_clear(tmp_path):
    mem = Memory(str(tmp_path / "cache.json"))
    mem.store("code", {"x": 1})
    mem.clear()
    assert mem.get("code") is None

def test_memory_different_code_different_key(tmp_path):
    mem = Memory(str(tmp_path / "cache.json"))
    mem.store("code A", {"verdict": "vulnerable"})
    mem.store("code B", {"verdict": "likely_clean"})
    assert mem.get("code A")["verdict"] == "vulnerable"
    assert mem.get("code B")["verdict"] == "likely_clean"

def test_memory_persists(tmp_path):
    path = str(tmp_path / "cache.json")
    Memory(path).store("persistent code", {"verdict": "unclear"})
    # new instance loads same file
    assert Memory(path).get("persistent code")["verdict"] == "unclear"
