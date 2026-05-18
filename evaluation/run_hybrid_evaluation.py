"""
Hybrid Evaluation: runs the CodeGuardian pipeline in GraphRAG+LLM mode
against the 120-case evaluation set (90 original + 30 low-confidence).

Usage:
    python evaluation/run_hybrid_evaluation.py --model gemini-flash
    python evaluation/run_hybrid_evaluation.py --model deepseek-r1
    python evaluation/run_hybrid_evaluation.py --model gemma3-1b
    python evaluation/run_hybrid_evaluation.py --model gemini-flash --limit 10

Output:
    evaluation_results/{model}_hybrid_120.json
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT     = Path(__file__).resolve().parent.parent
GRAPHRAG = ROOT / "graphrag"
EVAL_SET = ROOT / "data" / "processed" / "evaluation_set_hybrid.json"
OUT_DIR  = ROOT / "evaluation_results"

sys.path.insert(0, str(GRAPHRAG))
sys.path.insert(0, str(GRAPHRAG / "src"))
sys.path.insert(0, str(GRAPHRAG / "models"))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
    load_dotenv(GRAPHRAG / ".env")
except ImportError:
    pass

try:
    import psutil
    _PROC = psutil.Process()
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    _PROC = None


def memory_mb() -> float:
    return _PROC.memory_info().rss / (1024 * 1024) if HAS_PSUTIL else 0.0


def make_llm(model_key: str):
    from models.gemini_client import GeminiClient
    from models.ollama_client import OllamaClient
    if model_key == "gemini-flash":
        return GeminiClient()
    if model_key == "deepseek-r1":
        return OllamaClient(model="deepseek-r1:8b")
    if model_key == "gemma3-1b":
        return OllamaClient(model="gemma2:2b")
    raise ValueError(f"Unknown model: {model_key}")


def run_case(agent, case: dict) -> dict:
    code    = case.get("code", "")
    test_id = case.get("test_id", "?")

    mem_before = memory_mb()
    t_start    = time.time()

    # ── Planner ──────────────────────────────────────────────────────────────
    t0   = time.time()
    plan = agent.planner.plan(code)
    t_plan = round(time.time() - t0, 4)

    # ── Executor ─────────────────────────────────────────────────────────────
    t0          = time.time()
    exec_result = agent.executor.execute(plan)
    t_exec      = round(time.time() - t0, 4)

    # ── Critic (hybrid) ───────────────────────────────────────────────────────
    t0    = time.time()
    score = agent.critic.score(code, exec_result)
    t_critic = round(time.time() - t0, 4)

    # ── Format result ─────────────────────────────────────────────────────────
    formatted  = agent._format(code, plan, exec_result, score, 1)
    verdict    = formatted.get("verdict", "unknown")
    confidence = formatted.get("confidence", 0.0)

    # ── Hybrid metadata from HybridCriticScore ────────────────────────────────
    llm_consulted       = getattr(score, "llm_consulted", False)
    method              = getattr(score, "method", "graphrag_only")
    graphrag_confidence = getattr(score, "graphrag_confidence", confidence)
    llm_confidence      = getattr(score, "llm_confidence", 0.0)
    llm_verdict         = getattr(score, "llm_verdict", "")
    llm_reasoning       = getattr(score, "llm_reasoning", "")
    agreement           = getattr(score, "agreement", None)

    t_total    = round(time.time() - t_start, 4)
    mem_after  = memory_mb()

    # ── Determine predicted vulnerability ────────────────────────────────────
    predicted_vulnerable = verdict in ("vulnerable", "potentially_vulnerable")

    return {
        "test_id":             test_id,
        "verdict":             verdict,
        "confidence":          round(confidence, 4),
        "predicted_vulnerable": predicted_vulnerable,
        "vulnerability_types": formatted.get("vulnerability_types", []),
        "all_matched_vulns":   formatted.get("all_matched_vulns", []),
        "language_detected":   formatted.get("language_detected", ""),
        "timing": {
            "total":   t_total,
            "planner": t_plan,
            "executor": t_exec,
            "critic":  t_critic,
        },
        "memory": {
            "before_mb": round(mem_before, 2),
            "after_mb":  round(mem_after, 2),
            "delta_mb":  round(mem_after - mem_before, 2),
        },
        "hybrid_info": {
            "method":              method,
            "llm_consulted":       llm_consulted,
            "graphrag_confidence": round(graphrag_confidence, 4),
            "llm_confidence":      round(llm_confidence, 4),
            "llm_verdict":         llm_verdict,
            "llm_reasoning":       llm_reasoning,
            "agreement":           agreement,
        },
        "ground_truth": case.get("ground_truth", {}),
        "from_cache":   formatted.get("from_cache", False),
    }


def compute_classification(results: list) -> dict:
    tp = fp = tn = fn = 0
    for r in results:
        if "error" in r:
            continue
        pred   = r.get("predicted_vulnerable", False)
        actual = r.get("ground_truth", {}).get("vulnerable", False)
        if pred and actual:     tp += 1
        elif pred and not actual: fp += 1
        elif not pred and actual: fn += 1
        else:                   tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy  = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) else 0.0

    return dict(f1=round(f1, 4), precision=round(precision, 4),
                recall=round(recall, 4), accuracy=round(accuracy, 4),
                fpr=round(fpr, 4), tp=tp, fp=fp, tn=tn, fn=fn)


def compute_llm_stats(results: list) -> dict:
    original = [r for r in results if not r["test_id"].startswith("eval_low_")]
    lowconf  = [r for r in results if r["test_id"].startswith("eval_low_")]

    def _rate(subset):
        if not subset:
            return 0, 0, 0.0
        consulted = sum(1 for r in subset if r.get("hybrid_info", {}).get("llm_consulted"))
        return consulted, len(subset), consulted / len(subset)

    all_c,  all_n,  all_r  = _rate(results)
    orig_c, orig_n, orig_r = _rate(original)
    lc_c,   lc_n,   lc_r   = _rate(lowconf)

    agreed    = sum(1 for r in results if r.get("hybrid_info", {}).get("agreement") is True)
    disagreed = sum(1 for r in results if r.get("hybrid_info", {}).get("agreement") is False)

    return {
        "overall_consulted":        all_c,
        "overall_total":            all_n,
        "overall_rate":             round(all_r, 4),
        "original_consulted":       orig_c,
        "original_total":           orig_n,
        "original_rate":            round(orig_r, 4),
        "lowconf_consulted":        lc_c,
        "lowconf_total":            lc_n,
        "lowconf_rate":             round(lc_r, 4),
        "llm_agreed":               agreed,
        "llm_disagreed":            disagreed,
        "agreement_rate":           round(agreed / all_c, 4) if all_c else None,
    }


def main():
    parser = argparse.ArgumentParser(description="Run hybrid evaluation")
    parser.add_argument("--model", required=True,
                        choices=["gemini-flash", "deepseek-r1", "gemma3-1b"])
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of test cases (0 = all)")
    parser.add_argument("--threshold", type=float, default=0.85,
                        help="LLM consultation threshold (default: 0.85)")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    if not EVAL_SET.exists():
        print(f"❌ Evaluation set not found: {EVAL_SET}")
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else OUT_DIR / f"{args.model}_hybrid_120.json"

    print("=" * 80)
    print(f"HYBRID EVALUATION — {args.model.upper()}")
    print("=" * 80)
    print(f"Mode:      GraphRAG + LLM (threshold={args.threshold:.0%})")
    print(f"Eval set:  {EVAL_SET}")
    print(f"Output:    {out_path}")
    print(f"Memory:    {'enabled' if HAS_PSUTIL else 'DISABLED (pip install psutil)'}")
    print()

    # Load eval set
    with open(EVAL_SET) as f:
        eval_data = json.load(f)
    cases = eval_data.get("test_cases", [])
    if args.limit > 0:
        cases = cases[:args.limit]
    print(f"Loaded {len(cases)} test cases "
          f"({sum(1 for c in cases if not c['test_id'].startswith('eval_low_'))} original + "
          f"{sum(1 for c in cases if c['test_id'].startswith('eval_low_'))} low-confidence)")

    # Build LLM client
    print(f"\nBuilding LLM client: {args.model}")
    try:
        llm = make_llm(args.model)
        if not llm.is_available:
            print(f"⚠️  {llm.display_name} reports unavailable — LLM consultation will fail")
        else:
            print(f"✓ LLM ready: {llm.display_name}")
    except Exception as exc:
        print(f"❌ Failed to init LLM: {exc}")
        sys.exit(1)

    # Build agent in hybrid mode
    print(f"Building CodeGuardian agent (hybrid mode)...")
    os.chdir(GRAPHRAG)
    import config
    from agent.agent import CodeGuardianAgent
    agent = CodeGuardianAgent.from_config(
        config,
        use_hybrid=True,
        llm_client=llm,
        llm_threshold=args.threshold,
    )
    print(f"✓ Agent ready (hybrid, threshold={agent.critic.llm_threshold:.0%})")

    # Clear cache to ensure fresh evaluation
    agent.clear_cache()

    print()
    print("─" * 80)
    print(f"{'Case':>8}  {'Icon':2}  {'Test ID':>14}  {'Verdict':22}  {'Conf':5}  {'Time':6}  {'Method'}")
    print("─" * 80)

    results  = []
    failures = 0
    t_start  = time.time()

    for i, case in enumerate(cases, 1):
        elapsed = time.time() - t_start
        eta     = (elapsed / i) * (len(cases) - i) if i > 1 else 0

        try:
            r       = run_case(agent, case)
            icon    = "🔍" if r["hybrid_info"]["llm_consulted"] else "⚡"
            verdict = r["verdict"].upper()
            conf    = r["confidence"]
            t_case  = r["timing"]["total"]
            method  = r["hybrid_info"]["method"]

            print(f"[{i:3d}/{len(cases)}]  {icon}  {case['test_id']:>14}  "
                  f"{verdict:22}  {conf*100:4.0f}%  {t_case:5.2f}s  {method}  "
                  f"(eta {eta/60:.1f}m)")
            results.append(r)

        except Exception as exc:
            failures += 1
            print(f"[{i:3d}/{len(cases)}]  ❌  {case.get('test_id','?'):>14}  ERROR: {exc}")
            results.append({
                "test_id":    case.get("test_id", "?"),
                "error":      str(exc),
                "ground_truth": case.get("ground_truth", {}),
            })

    total_time = time.time() - t_start

    # ── Compute metrics ───────────────────────────────────────────────────────
    ok_results = [r for r in results if "error" not in r]
    cls_metrics = compute_classification(ok_results)
    llm_stats   = compute_llm_stats(ok_results)
    critic_stats = agent.critic.get_stats()

    timings = [r["timing"]["total"] for r in ok_results]
    avg_t   = sum(timings) / len(timings) if timings else 0.0

    # ── Print summary ─────────────────────────────────────────────────────────
    print()
    print("=" * 80)
    print(f"SUMMARY — {args.model.upper()}")
    print("=" * 80)
    print(f"\n📊 Classification Metrics:")
    print(f"   F1 Score:    {cls_metrics['f1']:.2%}")
    print(f"   Precision:   {cls_metrics['precision']:.2%}")
    print(f"   Recall:      {cls_metrics['recall']:.2%}")
    print(f"   Accuracy:    {cls_metrics['accuracy']:.2%}")
    print(f"   FPR:         {cls_metrics['fpr']:.2%}")
    print(f"   TP/FP/TN/FN: {cls_metrics['tp']}/{cls_metrics['fp']}/{cls_metrics['tn']}/{cls_metrics['fn']}")

    print(f"\n⏱️  Performance:")
    print(f"   Total time:    {total_time/60:.1f} min ({total_time:.0f}s)")
    print(f"   Avg per case:  {avg_t:.2f}s")
    print(f"   Failures:      {failures}")

    print(f"\n🔍 LLM Consultation:")
    print(f"   Overall:       {llm_stats['overall_consulted']}/{llm_stats['overall_total']} "
          f"({llm_stats['overall_rate']:.1%})")
    print(f"   Original (90): {llm_stats['original_consulted']}/{llm_stats['original_total']} "
          f"({llm_stats['original_rate']:.1%})")
    print(f"   Low-conf (30): {llm_stats['lowconf_consulted']}/{llm_stats['lowconf_total']} "
          f"({llm_stats['lowconf_rate']:.1%})")
    if llm_stats["agreement_rate"] is not None:
        print(f"   Agreement:     {llm_stats['llm_agreed']} agreed / "
              f"{llm_stats['llm_disagreed']} disagreed "
              f"({llm_stats['agreement_rate']:.1%} rate)")

    print(f"\n⚡ Critic Stats (from agent.critic.get_stats()):")
    for k, v in critic_stats.items():
        vstr = f"{v:.1%}" if isinstance(v, float) and v is not None else str(v)
        print(f"   {k:20s}: {vstr}")

    # ── Save output ───────────────────────────────────────────────────────────
    output = {
        "model":             args.model,
        "mode":              "hybrid",
        "threshold":         args.threshold,
        "timestamp":         datetime.now().isoformat(),
        "eval_set_size":     len(cases),
        "total_runtime_s":   round(total_time, 2),
        "failures":          failures,
        "classification":    cls_metrics,
        "llm_consultation":  llm_stats,
        "critic_stats":      critic_stats,
        "latency": {
            "mean":   round(avg_t, 4),
            "total":  round(sum(timings), 2),
        },
        "results": results,
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n✅ Results saved: {out_path}")


if __name__ == "__main__":
    main()
