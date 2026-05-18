#!/usr/bin/env bash
# Safe background launcher for hybrid evaluation.
# Cleans semaphores, sets single-threaded env, tracks PID.
set -u
cd "$(dirname "$0")/.."

MODEL="${1:-}"
if [ -z "$MODEL" ]; then
    echo "Usage: $0 <model>"
    echo "       Models: gemma3-1b  deepseek-r1  gemini-flash"
    exit 1
fi

OUT_DIR="evaluation_results"
LOGFILE="$OUT_DIR/${MODEL}_eval.log"
PIDFILE="$OUT_DIR/${MODEL}_eval.pid"
mkdir -p "$OUT_DIR"

# ── Kill previous run for this model ─────────────────────────────────────────
if [ -f "$PIDFILE" ]; then
    OLD_PID=$(cat "$PIDFILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "Killing old $MODEL process ($OLD_PID)..."
        kill -9 "$OLD_PID" 2>/dev/null
        sleep 1
    fi
    rm -f "$PIDFILE"
fi

# ── Clean leaked semaphores ───────────────────────────────────────────────────
echo "Cleaning semaphores..."
ipcs -s 2>/dev/null | grep "$(whoami)" | awk '{print $2}' | \
    xargs -I {} sh -c 'ipcrm -s "$1" 2>/dev/null' _ {} || true
sleep 1

# ── Single-threaded environment ───────────────────────────────────────────────
export LOKY_MAX_CPU_COUNT=1
export TOKENIZERS_PARALLELISM=false
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export TQDM_DISABLE=1
export PYTHONUNBUFFERED=1

# ── Launch ────────────────────────────────────────────────────────────────────
echo "Starting $MODEL evaluation → $LOGFILE"
cd graphrag
nohup python3 -u ../evaluation/run_hybrid_safe.py --model "$MODEL" \
    > "../$LOGFILE" 2>&1 &
PID=$!
echo "$PID" > "../$PIDFILE"
cd ..

echo "PID $PID — monitor: tail -f $LOGFILE"
echo ""
sleep 3
tail -8 "$LOGFILE"
