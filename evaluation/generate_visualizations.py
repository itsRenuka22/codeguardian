"""
Generate publication-quality figures and tables from comprehensive_metrics.json.

Outputs (in report_figures/):
    fig1_model_comparison.png         — F1/Precision/Recall/Accuracy grouped bars
    fig2_latency_breakdown.png        — Stacked bars by component
    fig3_per_vulnerability_heatmap.png — Per-vuln-type Precision/Recall/F1
    fig4_confusion_matrices.png       — 1 row × N model confusion matrices
    fig5_confidence_calibration.png   — Confidence vs accuracy by bin
    table1_performance_summary.csv/.md
    table2_latency_cost.csv/.md

Usage:
    python evaluation/generate_visualizations.py
"""
import json
import sys
from pathlib import Path

ROOT       = Path(__file__).resolve().parent.parent
METRICS_PATH = ROOT / "evaluation_results" / "comprehensive_metrics.json"
FIG_DIR    = ROOT / "report_figures"

# Teal palette (project theme)
TEAL_PALETTE = ["#028090", "#00A896", "#02C39A", "#014F59"]
MODEL_DISPLAY = {
    "gemini-flash": "Gemini Flash",
    "deepseek-r1":  "DeepSeek R1",
    "gemma3-1b":    "Gemma 3 1B",
}
VULN_DISPLAY = {
    "sql_injection":    "SQL Injection",
    "xss":              "XSS",
    "auth_bypass":      "Auth Bypass",
    "path_traversal":   "Path Traversal",
    "command_injection": "Cmd Injection",
    "other_injection":  "Other Injection",
    "file_upload":      "File Upload",
    "ssrf":             "SSRF",
    "csrf":             "CSRF",
    "template_injection": "Template Injection",
    "rce":              "RCE",
    "xxe":              "XXE",
    "deserialization":  "Deserialization",
}


def require_libs():
    """Fail early with a helpful message if matplotlib/seaborn/pandas missing."""
    missing = []
    for mod in ("matplotlib", "seaborn", "pandas"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        print(f"   Install with: pip install {' '.join(missing)}")
        sys.exit(1)


def load_metrics() -> dict:
    if not METRICS_PATH.exists():
        print(f"❌ Metrics file not found: {METRICS_PATH}")
        print("   Run aggregate_metrics.py first.")
        sys.exit(1)
    with open(METRICS_PATH) as f:
        return json.load(f)


def model_label(key: str) -> str:
    return MODEL_DISPLAY.get(key, key)


GEMINI_QUOTA_NOTE = "* Quota limited: 10% LLM rate (40 errors)"

def _model_label_with_note(model_key: str, m: dict) -> str:
    """Append quota note to Gemini label if LLM errors occurred."""
    label = model_label(model_key)
    errors = m.get("critic_stats", {}).get("llm_errors", 0)
    if errors > 0:
        label += " *"
    return label


# ── FIGURE 1 ─────────────────────────────────────────────────────────────
def fig1_model_comparison(metrics, plt, sns, pd):
    rows = []
    for model_key, m in metrics["models"].items():
        cls = m["classification"]
        rows.append({
            "Model":     _model_label_with_note(model_key, m),
            "F1":        cls["f1"],
            "Precision": cls["precision"],
            "Recall":    cls["recall"],
            "Accuracy":  cls["accuracy"],
        })
    df = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(12, 6))
    df.plot(x="Model", kind="bar", ax=ax, color=TEAL_PALETTE, edgecolor="white", width=0.75)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score")
    ax.set_title("Model Performance Comparison — 120-Case Hybrid Evaluation Set",
                 fontsize=14, fontweight="bold")
    ax.legend(loc="lower right", framealpha=0.9)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    # Value labels
    for container in ax.containers:
        ax.bar_label(container, fmt="%.2f", padding=2, fontsize=8)

    # Quota footnote
    ax.annotate(f"* {GEMINI_QUOTA_NOTE}", xy=(0.01, 0.01),
                xycoords="axes fraction", fontsize=8, color="gray", style="italic")

    plt.tight_layout()
    out = FIG_DIR / "fig1_model_comparison.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out.name}")


# ── FIGURE 2 ─────────────────────────────────────────────────────────────
def fig2_latency_breakdown(metrics, plt, sns, pd):
    components = ["planner", "executor", "critic", "llm_report"]
    rows = []
    for model_key, m in metrics["models"].items():
        breakdown = m.get("latency", {}).get("by_component", {})
        row = {"Model": model_label(model_key)}
        for c in components:
            row[c.replace("_", " ").title()] = breakdown.get(c, {}).get("mean", 0.0)
        rows.append(row)
    df = pd.DataFrame(rows).set_index("Model")

    fig, ax = plt.subplots(figsize=(11, 6))
    df.plot(kind="bar", stacked=True, ax=ax, color=TEAL_PALETTE, edgecolor="white", width=0.6)
    ax.set_ylabel("Latency (seconds)")
    ax.set_title("Per-Component Latency Breakdown (mean per case)",
                 fontsize=14, fontweight="bold")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    ax.legend(title="Component", loc="upper right", framealpha=0.9)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    # Totals on top
    totals = df.sum(axis=1)
    for i, total in enumerate(totals):
        ax.text(i, total + 0.2, f"{total:.1f}s", ha="center", fontsize=10, fontweight="bold")

    plt.tight_layout()
    out = FIG_DIR / "fig2_latency_breakdown.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out.name}")


# ── FIGURE 3 ─────────────────────────────────────────────────────────────
def fig3_per_vulnerability_heatmap(metrics, plt, sns, pd):
    """One subplot per model showing per-vuln-type Precision/Recall/F1."""
    models = list(metrics["models"].keys())
    n = len(models)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 9), squeeze=False)

    for i, model_key in enumerate(models):
        per = metrics["models"][model_key].get("per_vulnerability", {})
        rows = []
        index = []
        for vt in metrics.get("vulnerability_types", list(per.keys())):
            d = per.get(vt, {})
            rows.append([d.get("precision", 0), d.get("recall", 0), d.get("f1", 0)])
            index.append(VULN_DISPLAY.get(vt, vt))
        df = pd.DataFrame(rows, index=index, columns=["Precision", "Recall", "F1"])
        sns.heatmap(df, annot=True, fmt=".2f", cmap="YlGnBu", vmin=0, vmax=1,
                    ax=axes[0, i], cbar=(i == n - 1), linewidths=0.5)
        axes[0, i].set_title(model_label(model_key), fontsize=12, fontweight="bold")
        if i > 0:
            axes[0, i].set_ylabel("")

    fig.suptitle("Per-Vulnerability Performance (Precision / Recall / F1)",
                 fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    out = FIG_DIR / "fig3_per_vulnerability_heatmap.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out.name}")


# ── FIGURE 4 ─────────────────────────────────────────────────────────────
def fig4_confusion_matrices(metrics, plt, sns, pd):
    models = list(metrics["models"].keys())
    n = len(models)
    fig, axes = plt.subplots(1, n, figsize=(4.5 * n, 4.5), squeeze=False)

    for i, model_key in enumerate(models):
        cls = metrics["models"][model_key]["classification"]
        matrix = [[cls["tn"], cls["fp"]],
                  [cls["fn"], cls["tp"]]]
        df = pd.DataFrame(matrix,
                          index=["Actually Clean", "Actually Vuln"],
                          columns=["Pred Clean", "Pred Vuln"])
        sns.heatmap(df, annot=True, fmt="d", cmap="YlGnBu",
                    ax=axes[0, i], cbar=False, linewidths=0.5, annot_kws={"fontsize": 14})
        m = metrics["models"][model_key]
        quota_note = f"\n{GEMINI_QUOTA_NOTE}" if m.get("critic_stats", {}).get("llm_errors", 0) > 0 else ""
        axes[0, i].set_title(
            f"{model_label(model_key)}\nF1={cls['f1']:.2f}  FP={cls['fp']}  FPR={cls['fpr']:.0%}{quota_note}",
            fontsize=10, fontweight="bold"
        )

    fig.suptitle("Confusion Matrices — 120-Case Hybrid Evaluation Set",
                 fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    out = FIG_DIR / "fig4_confusion_matrices.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out.name}")


# ── FIGURE 5 ─────────────────────────────────────────────────────────────
def fig5_confidence_calibration(metrics, plt, sns, pd):
    """One subplot per model: avg confidence vs actual accuracy by bin."""
    models = list(metrics["models"].keys())
    n = len(models)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 5), squeeze=False)

    import numpy as np
    for i, model_key in enumerate(models):
        cal = metrics["models"][model_key].get("confidence_calibration", [])
        labels = [c["bin"] for c in cal]
        confidences = [c["avg_confidence"] if c["avg_confidence"] is not None else 0 for c in cal]
        accuracies  = [c["accuracy"]       if c["accuracy"]       is not None else 0 for c in cal]
        ns = [c["n"] for c in cal]

        x = np.arange(len(labels))
        width = 0.4
        ax = axes[0, i]
        ax.bar(x - width/2, confidences, width, label="Avg Confidence", color=TEAL_PALETTE[0])
        ax.bar(x + width/2, accuracies,  width, label="Actual Accuracy", color=TEAL_PALETTE[2])
        # Perfect-calibration diagonal reference
        ax.plot([0, len(labels)-1], [0.25, 0.95], "k--", alpha=0.3, linewidth=1, label="Ideal")

        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=15, fontsize=9)
        ax.set_ylim(0, 1.1)
        ax.set_ylabel("Score")
        ax.set_title(f"{model_label(model_key)}", fontsize=12, fontweight="bold")
        ax.legend(loc="upper left", fontsize=8)
        ax.grid(axis="y", linestyle="--", alpha=0.5)

        # n= labels
        for j, count in enumerate(ns):
            ax.text(j, 1.02, f"n={count}", ha="center", fontsize=8, color="gray")

    fig.suptitle("Confidence Calibration: Reported vs Actual",
                 fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    out = FIG_DIR / "fig5_confidence_calibration.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out.name}")


# ── TABLES ───────────────────────────────────────────────────────────────
def table1_performance_summary(metrics, pd):
    rows = []
    for model_key, m in metrics["models"].items():
        cls = m["classification"]
        llm = m.get("llm_consultation", {})
        errors = m.get("critic_stats", {}).get("llm_errors", 0)
        llm_rate = llm.get("overall_rate", 0)
        notes = f"Quota limited (10% LLM, 40 errors)" if errors > 0 else "Full hybrid"
        rows.append({
            "Model":     model_label(model_key),
            "F1":        round(cls["f1"], 4),
            "Precision": round(cls["precision"], 4),
            "Recall":    round(cls["recall"], 4),
            "Accuracy":  round(cls["accuracy"], 4),
            "FPR":       round(cls["fpr"], 4),
            "TP": cls["tp"], "FP": cls["fp"], "TN": cls["tn"], "FN": cls["fn"],
            "LLM Rate":  f"{llm_rate:.1%}",
            "Notes":     notes,
        })
    df = pd.DataFrame(rows)
    df.to_csv(FIG_DIR / "table1_performance_summary.csv", index=False)
    with open(FIG_DIR / "table1_performance_summary.md", "w") as f:
        f.write("# Table 1 — Performance Summary\n\n")
        f.write(df.to_markdown(index=False, floatfmt=".4f"))
        f.write("\n\n")
        f.write(f"\\* {GEMINI_QUOTA_NOTE}: API quota limited LLM consultation to 12/120 cases (10%). "
                "Remaining 108 LLM attempts fell back to GraphRAG-only. "
                "Results reflect primarily GraphRAG baseline performance for Gemini Flash.\n")
    print("  ✓ table1_performance_summary.csv/.md")


def table2_latency_cost(metrics, pd):
    rows = []
    for model_key, m in metrics["models"].items():
        lat = m.get("latency", {})
        cost = m.get("cost", {})
        mem = m.get("memory", {})
        thr = m.get("throughput", {})
        cost_str = "Free" if cost.get("total_cost_usd", 0) == 0 else f"${cost.get('cost_per_analysis', 0):.6f}"
        rows.append({
            "Model":             model_label(model_key),
            "Avg Latency (s)":   lat.get("mean", 0),
            "Median Latency":    lat.get("median", 0),
            "P95 Latency":       lat.get("p95", 0),
            "P99 Latency":       lat.get("p99", 0),
            "Throughput (req/s)": thr.get("requests_per_sec", 0),
            "Cost/Analysis":     cost_str,
            "Total Cost":        f"${cost.get('total_cost_usd', 0):.4f}",
            "RSS Memory (MB)":   mem.get("rss_mean_mb", 0),
        })
    df = pd.DataFrame(rows)
    df.to_csv(FIG_DIR / "table2_latency_cost.csv", index=False)
    with open(FIG_DIR / "table2_latency_cost.md", "w") as f:
        f.write("# Table 2 — Latency, Throughput & Cost\n\n")
        f.write(df.to_markdown(index=False))
        f.write("\n")
    print("  ✓ table2_latency_cost.csv/.md")


def main():
    require_libs()
    import matplotlib
    matplotlib.use("Agg")  # headless
    import matplotlib.pyplot as plt
    import seaborn as sns
    import pandas as pd

    sns.set_style("whitegrid")
    plt.rcParams["figure.figsize"] = (10, 6)
    plt.rcParams["font.size"] = 10

    metrics = load_metrics()
    FIG_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("GENERATING VISUALIZATIONS")
    print("=" * 80)
    print(f"Models in metrics: {list(metrics['models'].keys())}")
    print(f"Output:            {FIG_DIR}")
    print()

    print("Figures:")
    fig1_model_comparison(metrics, plt, sns, pd)
    fig2_latency_breakdown(metrics, plt, sns, pd)
    fig3_per_vulnerability_heatmap(metrics, plt, sns, pd)
    fig4_confusion_matrices(metrics, plt, sns, pd)
    fig5_confidence_calibration(metrics, plt, sns, pd)

    print("\nTables:")
    table1_performance_summary(metrics, pd)
    table2_latency_cost(metrics, pd)

    print()
    print("=" * 80)
    print(f"✓ All artifacts written to {FIG_DIR}")


if __name__ == "__main__":
    main()
