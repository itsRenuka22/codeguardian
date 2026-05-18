"""
Instrumented evaluation: runs the full CodeGuardian pipeline against the
evaluation set while measuring timing (per component), memory delta, token
counts, and retrieval quality for each test case.

Usage:
    python evaluation/run_instrumented_eval.py --model gemini-flash
    python evaluation/run_instrumented_eval.py --model deepseek-r1
    python evaluation/run_instrumented_eval.py --model gemma3-1b

Output:
    evaluation_results/{model}_results.json
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Set up paths
ROOT      = Path(__file__).resolve().parent.parent
GRAPHRAG  = ROOT / "graphrag"
EVAL_SET  = ROOT / "data" / "processed" / "evaluation_set.json"
OUT_DIR   = ROOT / "evaluation_results"

sys.path.insert(0, str(GRAPHRAG))
sys.path.insert(0, str(GRAPHRAG / "src"))
sys.path.insert(0, str(GRAPHRAG / "models"))

# Load environment variables (GOOGLE_API_KEY, etc.) before instantiating LLM clients
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
    load_dotenv(GRAPHRAG / ".env")
except ImportError:
    pass

# Optional psutil for memory tracking
try:
    import psutil
    _PROC = psutil.Process()
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    _PROC = None
    print("⚠️  psutil not installed — memory tracking disabled (pip install psutil)")


def memory_mb() -> float:
    """Resident set size in MB (0 if psutil unavailable)."""
    if not HAS_PSUTIL:
        return 0.0
    return _PROC.memory_info().rss / (1024 * 1024)


def estimate_tokens(text: str) -> int:
    """Rough word-based token estimate (1 token ≈ 0.75 words)."""
    if not text:
        return 0
    return int(len(text.split()) / 0.75)


def make_llm(model_key: str):
    """Build the LLM client for the given key."""
    from models.gemini_client import GeminiClient
    from models.ollama_client import OllamaClient

    if model_key == "gemini-flash":
        return GeminiClient()
    if model_key == "deepseek-r1":
        return OllamaClient(model="deepseek-r1:8b")
    if model_key == "gemma3-1b":
        return OllamaClient(model="gemma2:2b")
    raise ValueError(f"Unknown model: {model_key}")


def run_case(agent, llm, case: dict) -> dict:
    """
    Instruments the planner → executor → critic → LLM-report pipeline for
    a single test case and returns a structured result dict.
    """
    code = case.get("code", "")
    test_id = case.get("test_id", "?")

    timing = {}
    mem_before = memory_mb()
    t_total = time.time()

    # ── Planner ──────────────────────────────────────────────
    t0 = time.time()
    plan = agent.planner.plan(code)
    timing["planner"] = round(time.time() - t0, 4)

    # ── Executor ─────────────────────────────────────────────
    t0 = time.time()
    exec_result = agent.executor.execute(plan)
    timing["executor"] = round(time.time() - t0, 4)

    # ── Critic ───────────────────────────────────────────────
    t0 = time.time()
    score = agent.critic.score(code, exec_result)
    timing["critic"] = round(time.time() - t0, 4)

    # ── Format core result ───────────────────────────────────
    formatted = agent._format(code, plan, exec_result, score, 1)
    verdict = formatted.get("verdict", "unknown")
    confidence = formatted.get("confidence", 0.0)
    vulns = formatted.get("vulnerability_types", [])

    # ── LLM Report (skipped if clean) ────────────────────────
    llm_text = ""
    llm_input_tokens = 0
    llm_output_tokens = 0
    llm_cost = 0.0
    llm_error = None

    t0 = time.time()
    if verdict.lower() == "clean":
        timing["llm_report"] = 0.0  # skipped
    else:
        try:
            report_data = llm.generate_report(formatted, code)
            llm_text = report_data.get("text", "")
            llm_input_tokens = report_data.get("input_tokens", 0) or estimate_tokens(code)
            llm_output_tokens = report_data.get("output_tokens", 0) or estimate_tokens(llm_text)
            llm_cost = report_data.get("cost_usd", 0.0)
        except Exception as exc:
            llm_error = str(exc)
        timing["llm_report"] = round(time.time() - t0, 4)

    timing["total"] = round(time.time() - t_total, 4)
    mem_after = memory_mb()

    # ── Retrieval quality ────────────────────────────────────
    matches = exec_result.matches
    distances = [m.get("similarity_distance", 1.0) for m in matches]
    avg_distance = round(sum(distances) / len(distances), 4) if distances else 1.0
    top_distance = round(min(distances), 4) if distances else 1.0

    return {
        "test_id":      test_id,
        "verdict":      verdict,
        "confidence":   round(confidence, 4),
        "vulnerabilities": vulns,
        "all_matched_vulns": formatted.get("all_matched_vulns", []),
        "language_detected": formatted.get("language_detected", ""),
        "timing":       timing,
        "memory": {
            "before_mb":  round(mem_before, 2),
            "after_mb":   round(mem_after, 2),
            "delta_mb":   round(mem_after - mem_before, 2),
        },
        "tokens": {
            "input":      llm_input_tokens,
            "output":     llm_output_tokens,
            "code_chars": len(code),
        },
        "cost_usd":     round(llm_cost, 6),
        "retrieval": {
            "match_count":  len(matches),
            "avg_distance": avg_distance,
            "top_distance": top_distance,
        },
        "llm_report": {
            "generated": bool(llm_text),
            "length":    len(llm_text),
            "error":     llm_error,
        },
        "ground_truth": case.get("ground_truth", {}),
    }


def main():
    parser = argparse.ArgumentParser(description="Run instrumented evaluation")
    parser.add_argument("--model", required=True,
                        choices=["gemini-flash", "deepseek-r1", "gemma3-1b"])
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of test cases (0 = all)")
    parser.add_argument("--out", default=None,
                        help="Output path (default: evaluation_results/{model}_results.json)")
    args = parser.parse_args()

    # Validate eval set exists
    if not EVAL_SET.exists():
        print(f"❌ Evaluation set not found: {EVAL_SET}")
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else OUT_DIR / f"{args.model}_results.json"

    print("=" * 80)
    print(f"INSTRUMENTED EVALUATION — {args.model}")
    print("=" * 80)
    print(f"Eval set:  {EVAL_SET}")
    print(f"Output:    {out_path}")
    print(f"Memory:    {'enabled (psutil)' if HAS_PSUTIL else 'DISABLED (pip install psutil)'}")
    print()

    # Load eval set
    with open(EVAL_SET) as f:
        eval_data = json.load(f)
    cases = eval_data.get("test_cases", [])
    if args.limit > 0:
        cases = cases[:args.limit]
    print(f"Loaded {len(cases)} test cases")

    # Build agent
    print("Building CodeGuardian agent...")
    os.chdir(GRAPHRAG)
    sys.path.insert(0, str(GRAPHRAG))
    import config
    from agent.agent import CodeGuardianAgent
    agent = CodeGuardianAgent.from_config(config)
    print(f"✓ Agent ready")

    # Build LLM client
    print(f"Building LLM client: {args.model}")
    try:
        llm = make_llm(args.model)
        if not llm.is_available:
            print(f"⚠️  WARNING: {llm.display_name} reports not available — calls may fail")
        else:
            print(f"✓ LLM ready: {llm.display_name}")
    except Exception as exc:
        print(f"❌ Failed to init LLM: {exc}")
        sys.exit(1)

    # Run cases
    print()
    print("─" * 80)
    results = []
    failures = 0
    start_time = time.time()

    for i, case in enumerate(cases, 1):
        elapsed = time.time() - start_time
        eta = (elapsed / max(i - 1, 1)) * (len(cases) - i + 1) if i > 1 else 0

        try:
            result = run_case(agent, llm, case)
            verdict = result["verdict"]
            conf = result["confidence"]
            tot = result["timing"]["total"]
            tag = "✓" if verdict != "error" else "✗"
            print(f"[{i:3d}/{len(cases)}] {tag} {case.get('test_id','?'):>10} → "
                  f"{verdict.upper():22} ({conf*100:5.1f}%)  "
                  f"{tot:6.2f}s  (eta {eta/60:.1f}m)")
            results.append(result)
        except Exception as exc:
            failures += 1
            print(f"[{i:3d}/{len(cases)}] ✗ {case.get('test_id','?')} ERROR: {exc}")
            results.append({
                "test_id": case.get("test_id", "?"),
                "error":   str(exc),
                "ground_truth": case.get("ground_truth", {}),
            })
            # Persist partial results so a crash doesn't lose everything
            try:
                _save_partial(out_path, args.model, results, failures, time.time() - start_time)
            except Exception:
                pass

    total_time = time.time() - start_time

    # Save results
    output = {
        "model":          args.model,
        "model_display":  llm.display_name,
        "timestamp":      datetime.now().isoformat(),
        "eval_set_size":  len(cases),
        "total_runtime_s": round(total_time, 2),
        "failures":       failures,
        "results":        results,
    }
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    # Summary
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Model:          {args.model}")
    print(f"Total runtime:  {total_time/60:.1f} minutes  ({total_time:.0f}s)")
    print(f"Cases run:      {len(results)}")
    print(f"Failures:       {failures}")
    if results:
        ok = [r for r in results if "error" not in r]
        if ok:
            avg_t = sum(r["timing"]["total"] for r in ok) / len(ok)
            print(f"Avg latency:    {avg_t:.2f}s")
    print(f"Output:         {out_path}")


def _save_partial(out_path: Path, model: str, results: list, failures: int, elapsed: float):
    """Write current state to disk so we don't lose progress on a crash."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({
            "model":           model,
            "timestamp":       datetime.now().isoformat(),
            "partial":         True,
            "cases_completed": len(results),
            "failures":        failures,
            "elapsed_s":       round(elapsed, 2),
            "results":         results,
        }, f, indent=2)


if __name__ == "__main__":
    main()
