#!/usr/bin/env bash
# Run hybrid evaluation for all 3 models then analyze results.
# Tolerates per-model failures (skips unavailable services).
set -u
cd "$(dirname "$0")/.."  # repo root

EVAL_SET="data/processed/evaluation_set_hybrid.json"
OUT_DIR="evaluation_results"
PY="${PYTHON:-python3}"

echo "================================================================"
echo "CodeGuardian Hybrid Evaluation — All Models (120-case set)"
echo "================================================================"
echo "Repo root: $(pwd)"
echo "Started:   $(date)"
echo ""

# Sanity checks
if [ ! -f "$EVAL_SET" ]; then
    echo "❌ Missing hybrid eval set: $EVAL_SET"
    echo "   Run: python data/generation/generate_low_confidence_cases.py --merge"
    exit 1
fi

if ! command -v "$PY" >/dev/null 2>&1; then
    echo "❌ python3 not found on PATH"; exit 1
fi

echo "Python:  $($PY --version)"
echo "Cases:   $(python3 -c "import json; d=json.load(open('$EVAL_SET')); print(d['total_items'])")"
echo ""

# Check Ollama
if ! curl -s --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "⚠️  Ollama not reachable — DeepSeek R1 / Gemma 3 1B will be skipped"
    OLLAMA_UP=0
else
    OLLAMA_UP=1
    echo "Ollama: up"
fi

# Check Gemini
if [ -z "${GOOGLE_API_KEY:-}" ] && ! grep -q "^GOOGLE_API_KEY=" .env 2>/dev/null; then
    echo "⚠️  GOOGLE_API_KEY not set — Gemini Flash will be skipped"
    GEMINI_UP=0
else
    GEMINI_UP=1
    echo "Gemini: key configured"
fi

echo ""
mkdir -p "$OUT_DIR"

# ── Runner ────────────────────────────────────────────────────────────────────
run_one() {
    local model="$1"
    echo "──────────────────────────────────────────────────────────────"
    echo "▶ Running: $model"
    echo "──────────────────────────────────────────────────────────────"
    if "$PY" evaluation/run_hybrid_evaluation.py --model "$model"; then
        echo "✓ $model complete"
    else
        echo "✗ $model FAILED (continuing with others)"
    fi
    echo ""
}

[ "$GEMINI_UP" = "1" ] && run_one "gemini-flash"
[ "$OLLAMA_UP" = "1" ] && run_one "gemma3-1b"
[ "$OLLAMA_UP" = "1" ] && run_one "deepseek-r1"

# ── Analysis ──────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────"
echo "Analysis"
echo "──────────────────────────────────────────────────────────────"
for model in gemini-flash gemma3-1b deepseek-r1; do
    result_file="${OUT_DIR}/${model}_hybrid_120.json"
    if [ -f "$result_file" ]; then
        echo ""
        echo "--- $model ---"
        "$PY" evaluation/analyze_hybrid_results.py "$result_file"
    fi
done

echo "================================================================"
echo "COMPLETE — $(date)"
echo "================================================================"
echo ""
echo "Results:"
ls -1 "$OUT_DIR"/*hybrid*.json 2>/dev/null | sed 's/^/  /'
echo ""
echo "Next steps:"
echo "  python3 evaluation/aggregate_metrics.py"
echo "  python3 evaluation/generate_visualizations.py"
