# Table 1 — Performance Summary

| Model        |     F1 |   Precision |   Recall |   Accuracy |    FPR |   TP |   FP |   TN |   FN | LLM Rate   | Notes                              |
|:-------------|-------:|------------:|---------:|-----------:|-------:|-----:|-----:|-----:|-----:|:-----------|:-----------------------------------|
| Gemini Flash | 0.9215 |      0.8889 |   0.9565 |     0.8750 | 0.3929 |   88 |   11 |   17 |    4 | 10.0%      | Quota limited (10% LLM, 40 errors) |
| DeepSeek R1  | 0.9026 |      0.8544 |   0.9565 |     0.8417 | 0.5357 |   88 |   15 |   13 |    4 | 43.3%      | Full hybrid                        |
| Gemma 3 1B   | 0.9026 |      0.8544 |   0.9565 |     0.8417 | 0.5357 |   88 |   15 |   13 |    4 | 43.3%      | Full hybrid                        |

\* * Quota limited: 10% LLM rate (40 errors): API quota limited LLM consultation to 12/120 cases (10%). Remaining 108 LLM attempts fell back to GraphRAG-only. Results reflect primarily GraphRAG baseline performance for Gemini Flash.
