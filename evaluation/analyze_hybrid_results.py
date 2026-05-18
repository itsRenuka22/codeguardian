"""
Analyze hybrid evaluation results.

Usage:
    python evaluation/analyze_hybrid_results.py evaluation_results/gemini-flash_hybrid_120.json
    python evaluation/analyze_hybrid_results.py evaluation_results/gemini-flash_hybrid_120.json \
        --eval-set data/processed/evaluation_set_hybrid.json
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def analyze(results_path: str, eval_set_path: str = None):
    rpath = Path(results_path)
    if not rpath.exists():
        print(f"❌ Results file not found: {rpath}")
        sys.exit(1)

    with open(rpath) as f:
        data = json.load(f)

    eval_path = Path(eval_set_path) if eval_set_path else (
        ROOT / "data" / "processed" / "evaluation_set_hybrid.json"
    )
    tc_map = {}
    if eval_path.exists():
        with open(eval_path) as f:
            ev = json.load(f)
        tc_map = {c["test_id"]: c for c in ev.get("test_cases", [])}

    results = data.get("results", [])
    model   = data.get("model", "unknown")
    thresh  = data.get("threshold", 0.85)

    print("=" * 80)
    print(f"HYBRID EVALUATION ANALYSIS — {model.upper()}")
    print("=" * 80)
    print(f"Threshold:    {thresh:.0%}")
    print(f"Total cases:  {len(results)}")
    print(f"Timestamp:    {data.get('timestamp', 'unknown')}")

    # ── Split cases ───────────────────────────────────────────────────────────
    original = [r for r in results if not r["test_id"].startswith("eval_low_") and "error" not in r]
    lowconf  = [r for r in results if r["test_id"].startswith("eval_low_") and "error" not in r]
    errors   = [r for r in results if "error" in r]

    def _llm_split(subset):
        consulted     = [r for r in subset if r.get("hybrid_info", {}).get("llm_consulted")]
        not_consulted = [r for r in subset if not r.get("hybrid_info", {}).get("llm_consulted")]
        return consulted, not_consulted

    orig_llm,  orig_fast = _llm_split(original)
    lc_llm,    lc_fast   = _llm_split(lowconf)

    # ── Overview ──────────────────────────────────────────────────────────────
    print(f"\n{'─'*40}")
    print("LLM CONSULTATION BREAKDOWN")
    print(f"{'─'*40}")
    n_orig = len(original)
    n_lc   = len(lowconf)
    print(f"{'Category':25s}  {'Total':>5}  {'LLM':>5}  {'Fast':>5}  {'LLM%':>6}")
    print(f"{'─'*25}  {'─'*5}  {'─'*5}  {'─'*5}  {'─'*6}")
    print(f"{'Original cases':25s}  {n_orig:>5}  {len(orig_llm):>5}  {len(orig_fast):>5}  "
          f"{len(orig_llm)/n_orig*100 if n_orig else 0:5.1f}%")
    print(f"{'Low-confidence cases':25s}  {n_lc:>5}  {len(lc_llm):>5}  {len(lc_fast):>5}  "
          f"{len(lc_llm)/n_lc*100 if n_lc else 0:5.1f}%")
    print(f"{'All cases':25s}  {n_orig+n_lc:>5}  {len(orig_llm)+len(lc_llm):>5}  "
          f"{len(orig_fast)+len(lc_fast):>5}  "
          f"{(len(orig_llm)+len(lc_llm))/(n_orig+n_lc)*100 if (n_orig+n_lc) else 0:5.1f}%")
    if errors:
        print(f"{'Errors':25s}  {len(errors):>5}")

    # ── Classification metrics ────────────────────────────────────────────────
    cls = data.get("classification", {})
    if cls:
        print(f"\n{'─'*40}")
        print("CLASSIFICATION METRICS")
        print(f"{'─'*40}")
        print(f"  F1:        {cls.get('f1', 0):.2%}")
        print(f"  Precision: {cls.get('precision', 0):.2%}")
        print(f"  Recall:    {cls.get('recall', 0):.2%}")
        print(f"  Accuracy:  {cls.get('accuracy', 0):.2%}")
        print(f"  FPR:       {cls.get('fpr', 0):.2%}")
        print(f"  TP/FP/TN/FN: {cls.get('tp',0)}/{cls.get('fp',0)}/{cls.get('tn',0)}/{cls.get('fn',0)}")

    # ── Low-conf cases that DID NOT trigger LLM ───────────────────────────────
    if lc_fast:
        print(f"\n{'─'*40}")
        print(f"⚠️  LOW-CONFIDENCE CASES THAT SKIPPED LLM ({len(lc_fast)}/{n_lc})")
        print(f"{'─'*40}")
        print("These had GraphRAG confidence >= threshold despite being designed as low-confidence.")
        print()
        for r in lc_fast:
            tc   = tc_map.get(r["test_id"], {})
            conf = r.get("confidence", 0)
            gconf = r.get("hybrid_info", {}).get("graphrag_confidence", conf)
            cat  = tc.get("source_metadata", {}).get("category", "unknown")
            vuln = r.get("ground_truth", {}).get("vulnerability_types", [])
            print(f"  {r['test_id']:>16}  conf={gconf:.2f}  cat={cat}")
            print(f"    verdict={r.get('verdict')}  ground_truth_vulns={vuln}")

    # ── LLM-consulted low-conf cases — correctness ────────────────────────────
    if lc_llm:
        print(f"\n{'─'*40}")
        print(f"🔍 LOW-CONFIDENCE CASES THAT TRIGGERED LLM ({len(lc_llm)}/{n_lc})")
        print(f"{'─'*40}")
        correct = 0
        for r in lc_llm:
            pred   = r.get("predicted_vulnerable", False)
            actual = r.get("ground_truth", {}).get("vulnerable", False)
            match  = pred == actual
            if match:
                correct += 1
            icon = "✓" if match else "✗"
            hi   = r.get("hybrid_info", {})
            print(f"  {icon} {r['test_id']:>16}  "
                  f"gr={hi.get('graphrag_confidence',0):.2f}  "
                  f"llm={hi.get('llm_confidence',0):.2f}  "
                  f"final={r.get('confidence',0):.2f}  "
                  f"agree={hi.get('agreement')}  "
                  f"verdict={r.get('verdict')}")
        print(f"\n  Accuracy on LLM-consulted low-conf: {correct}/{len(lc_llm)} "
              f"({correct/len(lc_llm)*100:.1f}%)")

    # ── Original cases where LLM was consulted (interesting) ─────────────────
    if orig_llm:
        print(f"\n{'─'*40}")
        print(f"🔍 ORIGINAL CASES THAT TRIGGERED LLM ({len(orig_llm)}/{n_orig})")
        print(f"{'─'*40}")
        print("(GraphRAG confidence was below threshold on these originally-high-confidence cases)")
        for r in orig_llm[:10]:
            hi = r.get("hybrid_info", {})
            tc = tc_map.get(r["test_id"], {})
            print(f"  {r['test_id']:>10}  gr={hi.get('graphrag_confidence',0):.2f}  "
                  f"llm={hi.get('llm_confidence',0):.2f}  "
                  f"agree={hi.get('agreement')}  "
                  f"verdict={r.get('verdict')}  "
                  f"lang={tc.get('language','?')}")

    # ── LLM agreement analysis ────────────────────────────────────────────────
    all_llm = orig_llm + lc_llm
    if all_llm:
        agreed    = [r for r in all_llm if r.get("hybrid_info", {}).get("agreement") is True]
        disagreed = [r for r in all_llm if r.get("hybrid_info", {}).get("agreement") is False]
        print(f"\n{'─'*40}")
        print(f"AGREEMENT ANALYSIS (all {len(all_llm)} LLM-consulted cases)")
        print(f"{'─'*40}")
        print(f"  Agreed:    {len(agreed)}/{len(all_llm)} ({len(agreed)/len(all_llm)*100:.1f}%)")
        print(f"  Disagreed: {len(disagreed)}/{len(all_llm)} ({len(disagreed)/len(all_llm)*100:.1f}%)")

        if disagreed:
            print(f"\n  Disagreement details (GraphRAG vs LLM):")
            for r in disagreed[:8]:
                hi = r.get("hybrid_info", {})
                print(f"    {r['test_id']:>16}  "
                      f"GraphRAG={hi.get('graphrag_verdict','?'):22}  "
                      f"LLM={hi.get('llm_verdict','?'):22}  "
                      f"final={r.get('verdict')}")

    # ── Timing summary ────────────────────────────────────────────────────────
    lat = data.get("latency", {})
    if lat:
        print(f"\n{'─'*40}")
        print("TIMING")
        print(f"{'─'*40}")
        print(f"  Avg per case:  {lat.get('mean', 0):.2f}s")
        print(f"  Total runtime: {data.get('total_runtime_s', 0)/60:.1f} min")

    # ── Final verdict ─────────────────────────────────────────────────────────
    lc_rate = len(lc_llm) / n_lc * 100 if n_lc else 0
    print(f"\n{'='*80}")
    print("VERDICT")
    print(f"{'='*80}")
    print(f"  LLM consultation rate (low-conf): {lc_rate:.1f}%")
    if lc_rate >= 80:
        print("  ✅ EXCELLENT — ≥80% of low-confidence cases correctly triggered LLM")
    elif lc_rate >= 60:
        print("  ⚠️  GOOD — majority triggered LLM; some have stronger-than-expected GraphRAG matches")
    else:
        print("  ❌ POOR — consider lowering the LLM threshold")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("results_path")
    parser.add_argument("--eval-set", default=None)
    args = parser.parse_args()
    analyze(args.results_path, args.eval_set)
