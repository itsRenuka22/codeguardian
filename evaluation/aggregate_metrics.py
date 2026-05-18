"""
Aggregates per-model evaluation results into a single comprehensive_metrics.json
covering: classification metrics, latency percentiles, memory, cost,
per-vulnerability breakdown, retrieval quality, and confidence calibration.

Usage:
    python evaluation/aggregate_metrics.py
    python evaluation/aggregate_metrics.py --models gemini-flash deepseek-r1 gemma3-1b

Output:
    evaluation_results/comprehensive_metrics.json
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import numpy as np

ROOT     = Path(__file__).resolve().parent.parent
RES_DIR  = ROOT / "evaluation_results"
EVAL_SET = ROOT / "data" / "processed" / "evaluation_set.json"

VULN_TYPES = [
    "sql_injection",
    "xss",
    "auth_bypass",
    "path_traversal",
    "command_injection",
    "other_injection",
    "file_upload",
    "ssrf",
    "csrf",
    "template_injection",
    "rce",
    "xxe",
    "deserialization",
]

# Gemini Flash pricing (Jan 2025)
GEMINI_INPUT_COST_PER_1M  = 0.075
GEMINI_OUTPUT_COST_PER_1M = 0.30


def load_results(model: str) -> dict:
    """Load per-model results. Prefers hybrid_120 over legacy _results files."""
    for candidate in [f"{model}_hybrid_120.json", f"{model}_results.json"]:
        path = RES_DIR / candidate
        if path.exists():
            return json.load(open(path))
    print(f"⚠️  Missing results for {model} (tried hybrid_120 and _results)")
    return None


def safe_div(a, b):
    return round(a / b, 4) if b else 0.0


def classification_metrics(results: list) -> dict:
    """TP/FP/TN/FN, precision, recall, F1, accuracy, FPR, TNR."""
    tp = fp = tn = fn = 0
    for r in results:
        if "error" in r:
            continue
        gt = r.get("ground_truth", {})
        gt_vuln = gt.get("vulnerable", True)
        pred_vuln = r.get("verdict", "").lower() in ("vulnerable", "likely_vulnerable", "potentially_vulnerable")

        if gt_vuln and pred_vuln:       tp += 1
        elif gt_vuln and not pred_vuln: fn += 1
        elif pred_vuln:                 fp += 1
        else:                           tn += 1

    n = tp + fp + tn + fn
    precision = safe_div(tp, tp + fp)
    recall    = safe_div(tp, tp + fn)
    f1        = safe_div(2 * precision * recall, precision + recall)
    accuracy  = safe_div(tp + tn, n)
    fpr       = safe_div(fp, fp + tn)
    tnr       = safe_div(tn, fp + tn)

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": n,
        "precision": precision,
        "recall":    recall,
        "f1":        f1,
        "accuracy":  accuracy,
        "fpr":       fpr,
        "tnr":       tnr,
    }


def latency_stats(results: list) -> dict:
    """Mean / median / P50 / P95 / P99 + per-component breakdown."""
    ok = [r for r in results if "timing" in r and "error" not in r]
    if not ok:
        return {"error": "no completed results"}

    totals = np.array([r["timing"]["total"] for r in ok])
    components = ["planner", "executor", "critic", "llm_report"]
    breakdown = {}
    for c in components:
        vals = np.array([r["timing"].get(c, 0.0) for r in ok])
        breakdown[c] = {
            "mean":   round(float(vals.mean()), 4),
            "median": round(float(np.median(vals)), 4),
            "max":    round(float(vals.max()), 4),
        }

    return {
        "n":       int(len(totals)),
        "mean":    round(float(totals.mean()), 4),
        "median":  round(float(np.median(totals)), 4),
        "std":     round(float(totals.std()), 4),
        "min":     round(float(totals.min()), 4),
        "max":     round(float(totals.max()), 4),
        "p50":     round(float(np.percentile(totals, 50)), 4),
        "p95":     round(float(np.percentile(totals, 95)), 4),
        "p99":     round(float(np.percentile(totals, 99)), 4),
        "by_component": breakdown,
    }


def throughput_stats(model_data: dict) -> dict:
    """Requests per second, codes per minute."""
    runtime = model_data.get("total_runtime_s", 0)
    n = len([r for r in model_data.get("results", []) if "error" not in r])
    if not runtime:
        return {"requests_per_sec": 0, "codes_per_min": 0}
    return {
        "requests_per_sec": round(n / runtime, 4),
        "codes_per_min":    round(n / (runtime / 60), 2),
    }


def memory_stats(results: list) -> dict:
    ok = [r for r in results if "memory" in r and "error" not in r]
    if not ok:
        return {"error": "no memory data"}
    deltas = np.array([r["memory"]["delta_mb"] for r in ok])
    afters = np.array([r["memory"]["after_mb"] for r in ok])
    return {
        "delta_mean_mb": round(float(deltas.mean()), 2),
        "delta_max_mb":  round(float(deltas.max()), 2),
        "rss_mean_mb":   round(float(afters.mean()), 2),
        "rss_max_mb":    round(float(afters.max()), 2),
    }


def cost_stats(results: list, model: str) -> dict:
    """Token/cost summary; uses Gemini pricing for gemini-flash, free for Ollama."""
    ok = [r for r in results if "tokens" in r and "error" not in r]
    if not ok:
        return {"error": "no token data"}

    total_in  = sum(r["tokens"].get("input", 0)  for r in ok)
    total_out = sum(r["tokens"].get("output", 0) for r in ok)
    n = len(ok)

    if model == "gemini-flash":
        cost_per_in_1m  = GEMINI_INPUT_COST_PER_1M
        cost_per_out_1m = GEMINI_OUTPUT_COST_PER_1M
        total_cost = (total_in / 1_000_000) * cost_per_in_1m + \
                     (total_out / 1_000_000) * cost_per_out_1m
    else:
        cost_per_in_1m = cost_per_out_1m = 0.0
        total_cost = 0.0

    return {
        "total_input_tokens":  int(total_in),
        "total_output_tokens": int(total_out),
        "avg_input_tokens":    round(total_in / n, 1),
        "avg_output_tokens":   round(total_out / n, 1),
        "total_cost_usd":      round(total_cost, 4),
        "cost_per_analysis":   round(total_cost / n, 6) if n else 0.0,
        "pricing_per_1m": {
            "input":  cost_per_in_1m,
            "output": cost_per_out_1m,
        },
    }


def per_vulnerability_metrics(results: list) -> dict:
    """Per-vuln-type precision/recall/F1 (using sets of types)."""
    out = {}
    for vt in VULN_TYPES:
        tp = fp = tn = fn = 0
        for r in results:
            if "error" in r:
                continue
            gt_vulns  = set(r.get("ground_truth", {}).get("vulnerability_types", []))
            # hybrid eval stores predicted types in "vulnerability_types"; old eval used "vulnerabilities"
            pred_vulns = set(r.get("vulnerability_types", r.get("vulnerabilities", [])))

            actual = vt in gt_vulns
            predicted = vt in pred_vulns

            if actual and predicted:        tp += 1
            elif actual and not predicted:  fn += 1
            elif predicted and not actual:  fp += 1
            else:                           tn += 1

        precision = safe_div(tp, tp + fp)
        recall    = safe_div(tp, tp + fn)
        f1        = safe_div(2 * precision * recall, precision + recall)

        out[vt] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision,
            "recall":    recall,
            "f1":        f1,
        }
    return out


def retrieval_quality(results: list) -> dict:
    ok = [r for r in results if "retrieval" in r and "error" not in r]
    if not ok:
        return {"error": "no retrieval data"}
    distances = np.array([r["retrieval"]["avg_distance"] for r in ok])
    matches   = np.array([r["retrieval"]["match_count"]  for r in ok])
    tops      = np.array([r["retrieval"]["top_distance"] for r in ok])
    return {
        "avg_distance_mean": round(float(distances.mean()), 4),
        "avg_distance_std":  round(float(distances.std()), 4),
        "top_distance_mean": round(float(tops.mean()), 4),
        "match_count_mean":  round(float(matches.mean()), 2),
        "match_count_min":   int(matches.min()),
        "match_count_max":   int(matches.max()),
    }


def confidence_calibration(results: list) -> dict:
    """Bin by confidence; report avg confidence vs accuracy in each bin."""
    bins = [(0.0, 0.5), (0.5, 0.7), (0.7, 0.85), (0.85, 1.01)]
    out = []
    for lo, hi in bins:
        bin_results = []
        for r in results:
            if "error" in r:
                continue
            c = r.get("confidence", 0.0)
            if lo <= c < hi:
                bin_results.append(r)
        if not bin_results:
            out.append({
                "bin":            f"{lo:.2f}–{hi:.2f}",
                "n":              0,
                "avg_confidence": None,
                "accuracy":       None,
            })
            continue

        correct = 0
        for r in bin_results:
            gt_vuln = r.get("ground_truth", {}).get("vulnerable", True)
            pred_vuln = r.get("verdict", "").lower() in (
                "vulnerable", "likely_vulnerable", "potentially_vulnerable"
            )
            if gt_vuln == pred_vuln:
                correct += 1

        out.append({
            "bin":            f"{lo:.2f}–{hi:.2f}",
            "n":              len(bin_results),
            "avg_confidence": round(float(np.mean([r["confidence"] for r in bin_results])), 4),
            "accuracy":       round(correct / len(bin_results), 4),
        })
    return out


def aggregate_for_model(model: str, model_data: dict) -> dict:
    results = model_data.get("results", [])
    return {
        "model":              model,
        "model_display":      model_data.get("model_display", model),
        "eval_set_size":      model_data.get("eval_set_size", len(results)),
        "total_runtime_s":    model_data.get("total_runtime_s", 0),
        "failures":           model_data.get("failures", 0),
        "classification":     classification_metrics(results),
        "latency":            latency_stats(results),
        "throughput":         throughput_stats(model_data),
        "memory":             memory_stats(results),
        "cost":               cost_stats(results, model),
        "per_vulnerability":  per_vulnerability_metrics(results),
        "retrieval":          retrieval_quality(results),
        "confidence_calibration": confidence_calibration(results),
        # Pass through hybrid-specific stats without modification
        "llm_consultation":   model_data.get("llm_consultation", {}),
        "critic_stats":       model_data.get("critic_stats", {}),
        "mode":               model_data.get("mode", "standard"),
        "threshold":          model_data.get("threshold", None),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="+",
                        default=["gemini-flash", "deepseek-r1", "gemma3-1b"])
    parser.add_argument("--out", default=str(RES_DIR / "comprehensive_metrics.json"))
    args = parser.parse_args()

    print("=" * 80)
    print("AGGREGATING METRICS")
    print("=" * 80)

    out = {
        "generated_at": datetime.now().isoformat(),
        "vulnerability_types": VULN_TYPES,
        "models": {},
    }
    found = 0
    for m in args.models:
        data = load_results(m)
        if data is None:
            continue
        out["models"][m] = aggregate_for_model(m, data)
        found += 1
        cls = out["models"][m]["classification"]
        lat = out["models"][m]["latency"]
        cost = out["models"][m]["cost"]
        print(f"\n✓ {m}")
        print(f"    F1={cls['f1']:.3f}  P={cls['precision']:.3f}  R={cls['recall']:.3f}  Acc={cls['accuracy']:.3f}")
        print(f"    Latency: mean={lat.get('mean','—')}s  P95={lat.get('p95','—')}s")
        print(f"    Cost: ${cost.get('total_cost_usd', 0):.4f} (${cost.get('cost_per_analysis', 0):.6f}/case)")

    if found == 0:
        print("\n❌ No model results found. Run run_instrumented_eval.py first.")
        sys.exit(1)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print()
    print("=" * 80)
    print(f"✓ Saved: {out_path}")
    print(f"  Models aggregated: {found}/{len(args.models)}")


if __name__ == "__main__":
    main()
