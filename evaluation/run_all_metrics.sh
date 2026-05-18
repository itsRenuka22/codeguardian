#!/usr/bin/env bash
# CodeGuardian — Comprehensive Metrics Collection
#
# Runs instrumented evaluation for all 3 models, aggregates metrics, and
# generates figures + tables. Tolerates per-model failures (e.g., Ollama not
# running) and continues with whatever results are available.

set -u  # error on undefined vars (but keep -e off so one model failure ≠ halt)

cd "$(dirname "$0")/.."  # repo root

echo "================================================================"
echo "CodeGuardian Comprehensive Metrics Collection"
echo "================================================================"
echo "Repo root: $(pwd)"
echo "Started:   $(date)"
echo ""

mkdir -p evaluation_results report_figures

# ── Step 0: Sanity checks ────────────────────────────────────────
EVAL_SET="data/processed/evaluation_set.json"
if [ ! -f "$EVAL_SET" ]; then
    echo "❌ Missing evaluation set: $EVAL_SET"
    exit 1
fi

# Pick python3 over python
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "❌ python3 not found on PATH"
    exit 1
fi
echo "Python:    $($PY --version)"

# Warn if Ollama not reachable
if ! curl -s --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "⚠️  Ollama not reachable at http://localhost:11434 — DeepSeek R1 / Gemma 3 1B will be skipped"
    OLLAMA_UP=0
else
    OLLAMA_UP=1
    echo "Ollama:    up"
fi

# Warn if no Gemini key
if [ -z "${GOOGLE_API_KEY:-}" ] && ! grep -q "^GOOGLE_API_KEY=" .env 2>/dev/null; then
    echo "⚠️  GOOGLE_API_KEY not set — Gemini Flash will be skipped"
    GEMINI_UP=0
else
    GEMINI_UP=1
    echo "Gemini:    key configured"
fi

echo ""
echo "──────────────────────────────────────────────────────────────"
echo "Step 1: Running instrumented evaluations"
echo "──────────────────────────────────────────────────────────────"
echo "This can take 30 min – 3 hours (90 cases × N models)"
echo ""

run_one () {
    local model="$1"
    echo "▶ Running: $model"
    if "$PY" evaluation/run_instrumented_eval.py --model "$model"; then
        echo "✓ $model complete"
    else
        echo "✗ $model FAILED (continuing with others)"
    fi
    echo ""
}

[ "$GEMINI_UP" = "1" ] && run_one "gemini-flash"
[ "$OLLAMA_UP" = "1" ] && run_one "deepseek-r1"
[ "$OLLAMA_UP" = "1" ] && run_one "gemma3-1b"

echo "──────────────────────────────────────────────────────────────"
echo "Step 2: Aggregating metrics"
echo "──────────────────────────────────────────────────────────────"
if ! "$PY" evaluation/aggregate_metrics.py; then
    echo "✗ Aggregation failed — cannot generate visualizations"
    exit 1
fi
echo ""

echo "──────────────────────────────────────────────────────────────"
echo "Step 3: Generating visualizations"
echo "──────────────────────────────────────────────────────────────"
"$PY" evaluation/generate_visualizations.py
echo ""

echo "================================================================"
echo "COMPLETE — $(date)"
echo "================================================================"
echo ""
echo "Results:"
echo "  evaluation_results/comprehensive_metrics.json"
ls -1 report_figures/ 2>/dev/null | sed 's/^/  report_figures\//'
echo ""
