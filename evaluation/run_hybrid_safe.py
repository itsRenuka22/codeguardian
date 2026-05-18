#!/usr/bin/env python3
"""
Safe hybrid evaluation wrapper.

Sets single-threaded environment variables BEFORE any imports to prevent
loky semaphore leaks that cause deadlocks in consecutive background runs.

Usage:
    python evaluation/run_hybrid_safe.py --model deepseek-r1
    python evaluation/run_hybrid_safe.py --model gemini-flash
    python evaluation/run_hybrid_safe.py --model gemma3-1b
"""
import os
import sys

# ── Must be set before any imports ───────────────────────────────────────────
os.environ["LOKY_MAX_CPU_COUNT"]     = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"]        = "1"
os.environ["MKL_NUM_THREADS"]        = "1"
os.environ["NUMEXPR_NUM_THREADS"]    = "1"
os.environ["OPENBLAS_NUM_THREADS"]   = "1"
os.environ["TQDM_DISABLE"]           = "1"   # prevents tty-detection hang in nohup

print("Safe mode: single-threaded, tqdm disabled (nohup-safe)", flush=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from run_hybrid_evaluation import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted — cleaning up.")
        sys.exit(130)
    except Exception as exc:
        import traceback
        print(f"\nFailed: {exc}")
        traceback.print_exc()
        sys.exit(1)
