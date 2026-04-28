"""
CLI entry point for CodeGuardian agent.

Usage:
    python analyze.py --file path/to/code.php
    python analyze.py --code '$id = $_GET["id"]; mysqli_query($conn, $query);'
    python analyze.py --eval               # run all 65 eval cases
    python analyze.py --cache-stats
    python analyze.py --clear-cache
"""
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.dirname(__file__))

import config
from agent.agent import CodeGuardianAgent


def print_result(result: dict, verbose: bool = False):
    v = result["verdict"].upper()
    conf = f"{result['confidence']:.0%}"
    lang = result["language_detected"]
    vulns = ", ".join(result["vulnerability_types"]) or "none detected"
    sev = result["top_severity"] or "unknown"
    cached = " [cached]" if result.get("from_cache") else ""
    iters = result.get("iterations", 1)

    print(f"\n{'='*60}")
    print(f"  VERDICT     : {v} (confidence {conf}){cached}")
    print(f"  Language    : {lang}")
    print(f"  Vulns found : {vulns}")
    print(f"  Severity    : {sev}")
    print(f"  Matches     : {result['total_matches']}  |  Iterations: {iters}")
    print(f"{'='*60}")

    if result["fix_guidance"]:
        print("\nFix Guidance:")
        for fg in result["fix_guidance"][:3]:
            print(f"  [{fg['vuln_type']}]  {fg['description'][:100]}")

    if verbose and result["evidence"]:
        print("\nTop Evidence:")
        for e in result["evidence"][:3]:
            cwes = ", ".join(c["id"] for c in e["cwes"]) or "—"
            print(f"  {e['code_id']} ({e['language']}, {e['severity']}) "
                  f"dist={e['similarity_distance']}  CWEs={cwes}")

    print()


def run_eval(agent: CodeGuardianAgent):
    with open(config.EVALUATION_SET_PATH) as f:
        ev = json.load(f)

    cases = ev.get("test_cases", [])
    print(f"Running {len(cases)} evaluation cases...\n")

    tp = fp = tn = fn = 0
    results_log = []

    for case in cases:
        gt = case["ground_truth"]
        gt_vulnerable = gt.get("vulnerable", True)
        gt_vulns = set(gt.get("vulnerability_types", []))

        result = agent.analyze(case["code"])
        predicted_vulnerable = result["verdict"] in ("vulnerable", "likely_vulnerable")
        predicted_vulns = set(result["vulnerability_types"])

        vuln_match = bool(gt_vulns & predicted_vulns) if gt_vulns else True

        if gt_vulnerable and predicted_vulnerable:
            outcome = "TP"
            tp += 1
        elif gt_vulnerable and not predicted_vulnerable:
            outcome = "FN"
            fn += 1
        elif not gt_vulnerable and predicted_vulnerable:
            outcome = "FP"
            fp += 1
        else:
            outcome = "TN"
            tn += 1

        results_log.append({
            "test_id":      case["test_id"],
            "outcome":      outcome,
            "gt_verdict":   gt_vulnerable,
            "pred_verdict": predicted_vulnerable,
            "confidence":   result["confidence"],
            "gt_vulns":     list(gt_vulns),
            "pred_vulns":   list(predicted_vulns),
            "vuln_match":   vuln_match,
        })

        status = "✓" if outcome in ("TP", "TN") else "✗"
        print(f"  {status} {case['test_id']} [{outcome}] conf={result['confidence']:.2f} "
              f"pred={','.join(predicted_vulns) or 'none'}")

    # metrics
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall    = tp / (tp + fn) if (tp + fn) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy  = (tp + tn) / len(cases) if cases else 0

    vuln_matches = sum(1 for r in results_log if r["vuln_match"] and r["gt_verdict"])
    gt_positives = sum(1 for r in results_log if r["gt_verdict"])
    vuln_type_accuracy = vuln_matches / gt_positives if gt_positives else 0

    print(f"\n{'='*60}")
    print("EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"  Cases       : {len(cases)}  (TP={tp} FP={fp} TN={tn} FN={fn})")
    print(f"  Accuracy    : {accuracy:.1%}")
    print(f"  Precision   : {precision:.1%}")
    print(f"  Recall      : {recall:.1%}")
    print(f"  F1 Score    : {f1:.1%}")
    print(f"  Vuln-type   : {vuln_type_accuracy:.1%}  (correct type among TPs)")
    print(f"{'='*60}\n")

    out_path = os.path.join(os.path.dirname(__file__), "data", "eval_results.json")
    with open(out_path, "w") as f:
        json.dump({
            "metrics": {
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "vuln_type_accuracy": round(vuln_type_accuracy, 4),
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            },
            "cases": results_log,
        }, f, indent=2)
    print(f"Full results saved to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="CodeGuardian vulnerability analyzer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file",        help="Path to source file to analyze")
    group.add_argument("--code",        help="Code snippet (inline string)")
    group.add_argument("--eval",        action="store_true", help="Run full evaluation suite")
    group.add_argument("--cache-stats", action="store_true", help="Show cache statistics")
    group.add_argument("--clear-cache", action="store_true", help="Clear the analysis cache")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show evidence details")
    parser.add_argument("--json",        action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    agent = CodeGuardianAgent.from_config(config)

    if args.cache_stats:
        print(json.dumps(agent.memory_stats(), indent=2))
        return

    if args.clear_cache:
        agent.clear_cache()
        print("Cache cleared.")
        return

    if args.eval:
        run_eval(agent)
        return

    if args.file:
        with open(args.file) as f:
            code = f.read()
    else:
        code = args.code

    result = agent.analyze(code)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_result(result, verbose=args.verbose)


if __name__ == "__main__":
    main()
