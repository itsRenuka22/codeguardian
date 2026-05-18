# CodeGuardian Metrics Collection

End-to-end pipeline for collecting and visualising the 8 evaluation metrics
required by the project report:

1. Latency (mean / P50 / P95 / P99 / per-component)
2. Throughput (requests/sec, codes/min)
3. Memory (RSS mean/max, delta per case)
4. Cost (tokens, $/analysis — Gemini Flash)
5. Per-model performance (F1, Precision, Recall, Accuracy, FPR)
6. Per-vulnerability metrics (7 vulnerability types)
7. Retrieval quality (avg/top distance, match count)
8. Confidence calibration (confidence vs actual accuracy by bin)

---

## Quick Start

### Option A — Run everything (automated)

```bash
./evaluation/run_all_metrics.sh
```

The script tolerates missing services: if Ollama is not running, it skips
DeepSeek/Gemma; if no Gemini key is set, it skips Gemini. Aggregation runs
on whatever results are present.

### Option B — Manual step-by-step

```bash
# Step 1 — run evaluations (~10–60 min per model)
python3 evaluation/run_instrumented_eval.py --model gemini-flash
python3 evaluation/run_instrumented_eval.py --model deepseek-r1
python3 evaluation/run_instrumented_eval.py --model gemma3-1b

# Step 2 — aggregate (seconds)
python3 evaluation/aggregate_metrics.py

# Step 3 — generate figures + tables (seconds)
python3 evaluation/generate_visualizations.py
```

### Smoke test (run on a tiny subset first)

```bash
python3 evaluation/run_instrumented_eval.py --model gemini-flash --limit 3
```

---

## Dependencies

| Package      | Required for                | Install                  |
|--------------|-----------------------------|--------------------------|
| `numpy`      | aggregation (percentiles)   | `pip install numpy`      |
| `requests`   | Gemini API calls            | `pip install requests`   |
| `python-dotenv` | reading `.env`           | `pip install python-dotenv` |
| `psutil`     | memory tracking (optional)  | `pip install psutil`     |
| `matplotlib` | figures                     | `pip install matplotlib` |
| `seaborn`    | heatmaps                    | `pip install seaborn`    |
| `pandas`     | tables                      | `pip install pandas`     |

Install everything in one shot:

```bash
pip install numpy requests python-dotenv psutil matplotlib seaborn pandas
```

If `psutil` is missing the eval script still runs — memory fields will be 0.

---

## Environment

```bash
# For Gemini Flash
export GOOGLE_API_KEY=your_key_here
# (or put it in .env at repo root)

# For DeepSeek R1 / Gemma 3 1B
ollama serve
ollama pull deepseek-r1:8b
ollama pull gemma2:2b
```

Verify before running:

```bash
curl -s http://localhost:11434/api/tags | jq '.models[].name'
echo $GOOGLE_API_KEY | cut -c1-10
```

---

## Output Layout

```
evaluation_results/
├── gemini-flash_results.json     # per-case raw data (model 1)
├── deepseek-r1_results.json      # per-case raw data (model 2)
├── gemma3-1b_results.json        # per-case raw data (model 3)
└── comprehensive_metrics.json    # aggregated across all models

report_figures/
├── fig1_model_comparison.png         # F1/Precision/Recall/Accuracy bars
├── fig2_latency_breakdown.png        # Stacked per-component latency
├── fig3_per_vulnerability_heatmap.png # 7 vuln types × 3 models
├── fig4_confusion_matrices.png       # TP/FP/TN/FN per model
├── fig5_confidence_calibration.png   # Confidence vs accuracy
├── table1_performance_summary.csv    # Performance table
├── table1_performance_summary.md     # Same, markdown
├── table2_latency_cost.csv           # Latency/cost table
└── table2_latency_cost.md            # Same, markdown
```

---

## Per-Case Result Schema

Each entry in `{model}_results.json` looks like:

```json
{
  "test_id":     "tc_001",
  "verdict":     "vulnerable",
  "confidence":  0.85,
  "vulnerabilities": ["sql_injection"],
  "timing": {
    "total":      12.5,
    "planner":     0.5,
    "executor":    5.2,
    "critic":      1.3,
    "llm_report":  5.5
  },
  "memory":   { "before_mb": 410.2, "after_mb": 425.5, "delta_mb": 15.3 },
  "tokens":   { "input": 450, "output": 890, "code_chars": 1234 },
  "cost_usd": 0.000098,
  "retrieval": {
    "match_count":  13,
    "avg_distance": 0.285,
    "top_distance": 0.142
  },
  "llm_report":   { "generated": true, "length": 2480, "error": null },
  "ground_truth": { "vulnerable": true, "vulnerability_types": ["sql_injection"] }
}
```

---

## Pricing Reference (used in cost aggregation)

Hard-coded in `aggregate_metrics.py`:

```python
GEMINI_INPUT_COST_PER_1M  = 0.075   # $0.075 per 1M input tokens
GEMINI_OUTPUT_COST_PER_1M = 0.30    # $0.30 per 1M output tokens
```

DeepSeek R1 and Gemma 3 1B are local (Ollama) — treated as $0 cost.

Update these constants if Google changes pricing.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `❌ Evaluation set not found` | Run from repo root, or check `data/processed/evaluation_set.json` exists |
| `❌ No model results found` | Run `run_instrumented_eval.py` for at least one model first |
| Gemini calls all fail | Check `GOOGLE_API_KEY` is set and valid; test with `test_gemini_direct.py` |
| Ollama calls all fail | Ensure `ollama serve` is running and the model is pulled |
| Per-component timing all = 0 for `llm_report` | Verdict is "clean" — LLM report is intentionally skipped |
| Memory always 0 | `psutil` not installed (`pip install psutil`) |
| Visualizations error on `matplotlib` | `pip install matplotlib seaborn pandas` |
| Eval crashes mid-run | Partial results saved automatically on each failure — resume by re-running |

---

## Notes for the Report

- The same 90-case evaluation set is used for every model (single source of
  truth at `data/processed/evaluation_set.json`), satisfying the
  "same eval set across models" requirement.
- 65 vulnerable + 25 clean cases — supports both TPR and FPR/TNR measurement.
- Per-vulnerability metrics cover the 7 most populated classes; rarer
  classes (XXE, CSRF, SSRF, Deserialization) appear in the raw per-case data
  but are excluded from the headline heatmap for readability.
- Reproducibility: token counts are best-effort estimates when the underlying
  client doesn't return them; Gemini direct-REST does not return token counts,
  so input/output tokens are word-based estimates (1 token ≈ 0.75 words).
