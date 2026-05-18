# CodeGuardian Multi-Model Evaluation Summary

**Date**: 2026-05-17
**Evaluation set**: 120 cases (90 original + 30 low-confidence)
**Mode**: Hybrid GraphRAG + LLM (threshold = 0.85)

---

## Executive Summary

| Metric | Gemini 2.5 Flash (OpenRouter) | Gemma 3 1B (Ollama) | DeepSeek R1 (Ollama) |
|--------|-------------------------------|---------------------|----------------------|
| **F1 Score** | **95.74%** | 89.76% | 94.05% |
| **Precision** | **93.75%** | 81.42% | 93.55% |
| **Recall** | 97.83% | 100.00% | 94.57% |
| **Accuracy** | 93.33% | 82.50% | 90.83% |
| **FPR** | **21.43%** | 75.00% | 21.43% |
| TP / FP / TN / FN | 90/6/22/2 | 92/21/7/0 | 87/6/22/5 |
| **Runtime** | **0.8 min** | 2.0 min | 80.6 min |
| **Avg latency** | **0.43s** | 1.01s | 40.3s |
| **LLM rate** | 43.3% | 42.5% | 42.5% |
| **LLM errors** | **0 (0%)** | 1 | 1 |
| **Cost (120 cases)** | ~$0.026 | **Free** | **Free** |

---

## Key Findings

### 1. Gemini completed via OpenRouter — 0% quota errors
The previous direct Google API evaluation hit 429 quota errors on 40/52 LLM
consultation attempts (77% failure rate). With OpenRouter, **0 errors** occurred
across all 120 cases. Full hybrid operation was achieved.

### 2. Distinct LLM behaviors — Gemini balances speed, accuracy, and cost
Gemini achieves highest F1 (95.74%) with balanced precision (93.75%) and recall (97.83%).
Gemma prioritizes perfect recall (100%) at cost of high FPR (75%), while
DeepSeek matches Gemini's FPR (21.4%) but is 100× slower.

### 3. Gemini and DeepSeek tie on false positive rate, Gemma trades precision for recall
Gemini (FP=6, TN=22) and DeepSeek (FP=6, TN=22) share the same low FPR (21.4%).
Gemma achieves perfect recall (FN=0, catches every vulnerability) but generates 3.5×
more false alarms (FP=21), which would create developer fatigue in a real deployment.

### 4. Gemini Flash is the clear winner for production use
Best F1 (95.74%), lowest latency (0.43s/case), zero LLM errors, and only $0.026 for
120 scans. DeepSeek matches its precision but takes 80.6 minutes vs 0.8 minutes — a
**100× runtime penalty** for identical FPR with lower recall.

### 5. Cost-performance tradeoff
At ~$0.026 for 120 cases ($0.00022/scan), Gemini Flash delivers the best F1 at negligible
cost. Gemma 3 1B is the best free local option — 40× faster than DeepSeek with higher
recall (100% vs 94.57%), making DeepSeek hard to justify for any use case.

---

## Confusion Matrix Analysis

| Model | True Positives | False Positives | True Negatives | False Negatives |
|-------|---------------|-----------------|----------------|-----------------|
| Gemini Flash | 90 | 6 | 22 | 2 |
| Gemma 3 1B | 92 | 21 | 7 | 0 |
| DeepSeek R1 | 87 | 6 | 22 | 5 |

Gemini and DeepSeek share the same confusion matrix (FP=6, TN=22), confirming their LLMs
make similar override decisions despite vastly different architectures and runtimes.
Gemma's aggressive recall-maximizing behavior produces 3.5× more false positives (FP=21).

---

## Production Deployment Recommendations

| Use Case | Recommended Model | Reason |
|----------|-------------------|--------|
| Real-time IDE integration | **Gemini Flash (OpenRouter)** | Fastest (0.43s), best precision |
| CI/CD pipeline | **Gemma 3 1B (Ollama)** | Free, 1.0s avg, no API dependency |
| Batch overnight scans | **Gemma 3 1B (Ollama)** | DeepSeek too slow (81 min for 120 cases) |
| Air-gapped / offline | **Gemma 3 1B (Ollama)** | No internet required |
| Budget-conscious cloud | **Gemini Flash (OpenRouter)** | ~$0.00022/scan, highest quality |

---

## LLM Consultation Statistics

| Model | Overall Rate | Low-conf Rate | LLM Errors |
|-------|-------------|---------------|------------|
| Gemini Flash | 43.3% | — | **0 (0%)** |
| Gemma 3 1B | 42.5% | 46.7% | 1 |
| DeepSeek R1 | 42.5% | 46.7% | 1 |

*Time saved by reusing existing Gemma + DeepSeek results: ~83 minutes*
