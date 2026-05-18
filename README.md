# CodeGuardian

**AI-Powered Security Code Review using GraphRAG + Hybrid LLM Critic**

CodeGuardian detects security vulnerabilities in code using a GraphRAG agent that retrieves semantically similar known-vulnerable examples, scores confidence, and — for uncertain cases — consults an LLM to override or confirm the verdict. The system produces actionable fix guidance with OWASP, CWE, and CVE citations.

## Team Members

| Name | SJSU ID | Email |
|------|---------|-------|
| Renuka Prasad Patwari | 018179902 | renukaprasad.patwari@sjsu.edu |
| Ekant Kapgate | 015945761 | ekant.kapgate@sjsu.edu |
| Viswa Surya Kumar Suvvada | 018316532 | viswasuryakumar.suvvada@sjsu.edu |

**Course:** CMPE 258 — Deep Learning
**Project Type:** LLMs + AI Agent System (Option 2)

---

## Evaluation Results (120-Case Hybrid Benchmark)

All three models were evaluated on the same 120-case set (90 original + 30 low-confidence cases designed to trigger LLM consultation). The Hybrid Critic consults the LLM when GraphRAG confidence < 0.85 and lets the LLM override the GraphRAG verdict when they disagree.

| Model | F1 | Precision | Recall | FPR | Avg Latency | Cost (120 cases) |
|-------|----|-----------|--------|-----|-------------|------------------|
| **Gemini 2.5 Flash** (OpenRouter) | **95.74%** | **93.75%** | **97.83%** | 21.4% | **0.43s** | ~$0.026 |
| DeepSeek R1 8B (Ollama) | 94.05% | 93.55% | 94.57% | 21.4% | 40.3s | Free |
| Gemma 3 1B (Ollama) | 89.76% | 81.42% | **100.00%** | 75.0% | 1.01s | Free |

**Key findings:**
- Gemini and DeepSeek share the same low FPR (21.4%) with identical confusion matrices (FP=6, TN=22) — their LLMs make similar override decisions despite different architectures
- Gemma 3 1B achieves perfect recall (zero missed vulnerabilities) but at the cost of 3.5× more false positives — it is the most conservative "catch everything" option
- Gemini Flash is **100× faster** than DeepSeek R1 at the same precision, making it the best production choice
- LLM consultation rate: ~43% of cases — the GraphRAG backbone handles 57% confidently on its own

Full results: [`evaluation_results/results_combined.json`](evaluation_results/results_combined.json)
Visualizations: [`report_figures_updated/`](report_figures_updated/)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                          │
│               Web UI (FastAPI) / CLI (analyze.py)               │
└─────────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│                        AI AGENT LAYER                           │
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────────┐   │
│  │ PLANNER  │ →  │ EXECUTOR │ →  │   HYBRID CRITIC        │   │
│  │          │    │          │    │                        │   │
│  │ Detects  │    │ Runs all │    │ 1. GraphRAG score      │   │
│  │ language │    │ queries, │    │ 2. If conf < 0.85:     │   │
│  │ & vuln   │    │ dedupes, │    │    consult LLM         │   │
│  │ hints;   │    │ ranks    │    │ 3. LLM disagrees →     │   │
│  │ builds   │    │ results  │    │    LLM verdict wins    │   │
│  │ query    │    │          │    │ 4. LLM agrees →        │   │
│  │ plan     │    │          │    │    weighted confidence  │   │
│  └──────────┘    └──────────┘    └────────────────────────┘   │
│                       ↑ retry if conf < 0.35                    │
│              ┌─────────────────────────┐                        │
│              │  MEMORY (SHA-256 cache) │                        │
│              └─────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│                        GRAPHRAG LAYER                           │
│                                                                 │
│  ┌──────────────────────┐    ┌──────────────────────┐         │
│  │    GRAPH DATABASE    │    │   VECTOR DATABASE    │         │
│  │  Neo4j / NetworkX    │    │      ChromaDB        │         │
│  │                      │    │                      │         │
│  │  369 nodes           │    │  260 embeddings      │         │
│  │  610 relationships   │    │  all-MiniLM-L6-v2    │         │
│  │  CWE + OWASP links   │    │  (local, no API key) │         │
│  └──────────────────────┘    └──────────────────────┘         │
│                                                                 │
│       Hybrid search → similar code + fix patterns + citations   │
└─────────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│                       DATA FOUNDATION                           │
│   260 code examples  |  120 eval cases  |  673 CVE records     │
│   26 OWASP docs      |  13 vuln types   |  citation map        │
└─────────────────────────────────────────────────────────────────┘
```

### Hybrid Critic — How LLM Overrides Work

GraphRAG retrieves similar code examples and computes a confidence score based on vector distance, match count, and severity. When confidence falls below the 0.85 threshold, the Hybrid Critic calls an LLM with the code and GraphRAG's pre-analysis context:

- **LLM agrees** with GraphRAG → confidence is boosted via weighted merge (70% GraphRAG + 30% LLM)
- **LLM disagrees** → LLM verdict is used directly (overrides GraphRAG)

This design ensures the fast GraphRAG path handles ~57% of cases with no LLM cost, while the LLM resolves ambiguous cases that the similarity index cannot confidently classify.

---

## Dataset

### Code Examples (260 total)

| Source | Count | Language | Notes |
|--------|-------|----------|-------|
| DVWA | 19 | PHP | Educational web security examples |
| OWASP WebGoat | 69 | Java | Official OWASP training lessons |
| OWASP Benchmark | 50 | Java | Test cases with known ground truth |
| Exploit-DB | 109 | Multi | Real-world exploit code |
| GitHub Issues | 13 | Various | Production bugs from open-source projects |

### Evaluation Set (120 cases)

| Split | Count | Purpose |
|-------|-------|---------|
| Original cases | 90 | Standard benchmark (DVWA, WebGoat, Exploit-DB, synthetic) |
| Low-confidence cases | 30 | Designed to score below 0.85 GraphRAG confidence — exercises the LLM path |

### Vulnerability Types Covered (13)

SQL Injection, XSS, Auth Bypass, Command Injection, Path Traversal, Other Injection, File Upload, SSRF, CSRF, Template Injection, RCE, XXE, Deserialization

---

## Quick Start

### Prerequisites

```bash
pip install -r requirements.txt
pip install -r graphrag/requirements.txt
```

For LLM-backed analysis (optional — GraphRAG works without any API key):

```bash
# Gemini Flash via OpenRouter (recommended)
export OPENROUTER_API_KEY=sk-or-...

# Local models via Ollama (free, no API key)
ollama pull gemma3:1b
ollama pull deepseek-r1:8b
```

### Start the Web UI

```bash
cd graphrag
uvicorn api.main:app --reload --port 8000
# Open http://localhost:8000
```

Paste code or upload a file, choose an LLM backend, and view the analysis report with verdict, confidence, vulnerable line highlights, and fix guidance.

### CLI Analysis

```bash
cd graphrag

# Analyze a file
python analyze.py --file path/to/code.php

# Analyze an inline snippet
python analyze.py --code '$id = $_GET["id"]; mysqli_query($conn, $query);'

# JSON output
python analyze.py --code '...' --json

# Cache management
python analyze.py --cache-stats
python analyze.py --clear-cache
```

### Run the Hybrid Evaluation

```bash
# Single model (runs in foreground)
LOKY_MAX_CPU_COUNT=1 TOKENIZERS_PARALLELISM=false TQDM_DISABLE=1 \
  python evaluation/run_hybrid_evaluation.py --model gemini-flash

# Background with safe env setup
bash evaluation/run_background_safe.sh gemini-flash
bash evaluation/run_background_safe.sh gemma3-1b
bash evaluation/run_background_safe.sh deepseek-r1

# Regenerate all visualizations from completed results
python evaluation/combine_and_visualize.py
```

Results are written to `evaluation_results/{model}_hybrid_120.json`.

### Run Tests

```bash
# Unit + integration tests
pytest graphrag/tests/ tests/ -v

# Quick smoke test for HybridCritic
python tests/quick_test_hybrid.py

# OpenRouter integration test
python test_openrouter.py
```

---

## Example Output

```
VERDICT     : VULNERABLE (confidence 92%)
Language    : php
Vulns found : sql_injection, xss
Severity    : critical
Matches     : 7  |  Iterations: 1
Method      : graphrag_only

Fix Guidance:
  [sql_injection]  Use prepared statements with parameterized queries
  [xss]            Escape all output with htmlspecialchars()
```

### JSON result structure

```json
{
  "verdict": "vulnerable",
  "confidence": 0.92,
  "vulnerability_types": ["sql_injection", "xss"],
  "top_severity": "critical",
  "language_detected": "php",
  "evidence": [
    {
      "code_id": "php_sqli_001",
      "severity": "critical",
      "similarity_distance": 0.08,
      "cwes": [{"id": "CWE-89", "name": "SQL Injection"}],
      "owasp_docs": [{"title": "OWASP A03:2021", "url": "..."}]
    }
  ],
  "fix_guidance": [
    {"vuln_type": "sql_injection", "description": "Use prepared statements..."}
  ],
  "line_findings": [{"line": 2, "vuln_type": "sql_injection", "snippet": "..."}],
  "hybrid_info": {
    "method": "hybrid",
    "llm_consulted": true,
    "agreement": false,
    "graphrag_verdict": "potentially_vulnerable",
    "llm_verdict": "vulnerable",
    "graphrag_confidence": 0.72,
    "llm_confidence": 0.95
  }
}
```

---

## Repository Structure

```
codeguardian/
├── README.md
├── requirements.txt
├── test_openrouter.py              # OpenRouter integration test
│
├── data/
│   ├── raw/v2/                     # Source datasets (DVWA, WebGoat, Exploit-DB, CVE, OWASP)
│   ├── processed/
│   │   ├── evaluation_set_hybrid.json   # 120-case evaluation set
│   │   ├── evaluation_set.json          # 90-case original set
│   │   ├── rag_knowledge_base_code_only.json
│   │   ├── citation_map.json
│   │   └── low_confidence_cases.json    # 30 cases designed to test LLM path
│   ├── statistics/                 # Dataset distribution stats
│   └── generation/                 # Scripts that built the low-confidence set
│
├── graphrag/
│   ├── analyze.py                  # CLI entry point
│   ├── build_graph.py              # One-time graph build script
│   ├── index_vectors.py            # One-time ChromaDB indexing
│   ├── config.py                   # Central configuration
│   ├── setup_check.py              # Environment checker
│   ├── requirements.txt
│   │
│   ├── agent/
│   │   ├── agent.py                # CodeGuardianAgent orchestrator
│   │   ├── planner.py              # Language detection + query plan builder
│   │   ├── executor.py             # Runs queries, deduplicates, ranks
│   │   ├── critic.py               # GraphRAG confidence scoring
│   │   ├── hybrid_critic.py        # Hybrid Critic with LLM override logic
│   │   └── memory.py               # SHA-256 JSON cache
│   │
│   ├── models/
│   │   ├── base.py                 # Abstract LLMClient interface
│   │   ├── gemini_client.py        # Gemini 2.5 Flash via OpenRouter
│   │   ├── ollama_client.py        # Ollama (Gemma 3 1B / DeepSeek R1)
│   │   └── report_generator.py     # Formats analysis into structured report
│   │
│   ├── src/
│   │   ├── codeguardian.py         # Top-level facade
│   │   ├── entity_extractor.py     # Extract functions/sources from code
│   │   ├── graph_store.py          # Neo4j + NetworkX dual-backend store
│   │   ├── graph_builder.py        # Builds 369-node / 610-edge knowledge graph
│   │   ├── vector_indexer.py       # ChromaDB indexing (all-MiniLM-L6-v2)
│   │   ├── hybrid_querier.py       # Hybrid graph + vector search
│   │   └── line_detector.py        # Maps vuln types to exact source lines
│   │
│   ├── api/
│   │   └── main.py                 # FastAPI server
│   ├── static/
│   │   └── index.html              # Single-page web UI
│   ├── data/
│   │   ├── graph_db/               # NetworkX graph (auto-created)
│   │   ├── vector_db/              # ChromaDB store (auto-created)
│   │   └── agent_cache.json        # Analysis result cache
│   └── tests/
│       ├── test_agent.py
│       ├── test_entity_extractor.py
│       ├── test_vector_indexer.py
│       └── test_setup.py
│
├── evaluation/
│   ├── run_hybrid_evaluation.py    # Primary evaluation runner (120-case)
│   ├── combine_and_visualize.py    # Combines results + generates all figures
│   ├── analyze_hybrid_results.py   # Per-model result analysis
│   ├── run_background_safe.sh      # Safe background launcher (sets env vars)
│   ├── run_hybrid_safe.py          # Python wrapper with env var setup
│   ├── README_METRICS.md           # Evaluation methodology documentation
│   └── RESULTS_INTERPRETATION.md  # Deployment guide + model selection
│
├── evaluation_results/
│   ├── gemini-flash_hybrid_120.json     # Gemini results (F1=95.74%)
│   ├── gemma3-1b_hybrid_120.json        # Gemma results  (F1=89.76%)
│   ├── deepseek-r1_hybrid_120.json      # DeepSeek results (F1=94.05%)
│   ├── results_combined.json            # Unified comparison JSON
│   └── results_gemini_openrouter.json   # Gemini-only summary
│
├── report_figures_updated/
│   ├── viz_model_comparison.png         # F1/Precision/Recall/FPR bar chart
│   ├── viz_confusion_matrices.png       # Side-by-side confusion matrices
│   ├── viz_runtime_latency.png          # Runtime + avg latency per model
│   ├── viz_vulnerability_heatmap.png    # Per-vulnerability F1 heatmap
│   ├── viz_cost_analysis.png            # Cost comparison
│   ├── EVALUATION_SUMMARY.md           # Full markdown report
│   └── latex_tables.tex                # LaTeX tables for paper
│
└── tests/
    ├── test_hybrid_critic.py       # Unit tests for HybridCritic
    ├── test_hybrid_realistic.py    # Integration test (real low-confidence case)
    └── quick_test_hybrid.py        # Smoke test
```

---

## Agent Architecture Details

### Planner → Executor → Hybrid Critic Loop

1. **Planner** — detects language (PHP/Python/Java/Ruby/JS) and vulnerability hints from code patterns; builds a prioritized list of GraphRAG queries
2. **Executor** — runs all queries against the hybrid querier, deduplicates by `code_id`, ranks by severity then vector distance
3. **Hybrid Critic** — two-stage scoring:
   - **Stage 1 (GraphRAG):** confidence formula based on match count, severity, planner accuracy, and vector distance; semantic validation filters impossible vulns (e.g. SQL injection flagged in code with no DB calls)
   - **Stage 2 (LLM, if needed):** when GraphRAG confidence < 0.85, the LLM receives the code + GraphRAG context and returns a verdict + confidence as JSON; if it disagrees with GraphRAG, its verdict is used directly
4. **Retry** — if final confidence < 0.35, the planner widens the query and tries again (max 2 retries)
5. **Memory** — results cached by SHA-256 of input code; cache survives restarts

### Verdict Thresholds (distance-aware)

| Top vector distance | Vulnerable threshold | Potentially vulnerable | Clean |
|--------------------|---------------------|----------------------|-------|
| < 0.25 (very similar) | ≥ 0.60 | ≥ 0.55 | < 0.55 |
| < 0.35 (moderate) | ≥ 0.75 | ≥ 0.55 | < 0.55 |
| ≥ 0.35 (weak) | ≥ 0.90 | ≥ 0.55 | < 0.55 |

---

## LLM Support

| Model | Provider | Key required | Use case |
|-------|----------|-------------|----------|
| Gemini 2.5 Flash | OpenRouter | `OPENROUTER_API_KEY` | Best overall — fastest, highest F1 |
| Gemma 3 1B | Ollama (local) | None | Best free local — perfect recall |
| DeepSeek R1 8B | Ollama (local) | None | High precision, very slow |

All clients share the same `LLMClient` interface (`models/base.py`). The `HybridCritic` uses `generate_raw()` to get structured JSON responses from whichever client is configured.

### Production Deployment Recommendations

| Use Case | Model | Reason |
|----------|-------|--------|
| Real-time IDE / CI | **Gemini Flash (OpenRouter)** | 0.43s/case, best F1, $0.00022/scan |
| Air-gapped / offline | **Gemma 3 1B (Ollama)** | Free, 1s/case, perfect recall |
| Budget batch scans | **Gemma 3 1B (Ollama)** | DeepSeek 40× slower for same FPR |

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Graph database | Neo4j (with NetworkX fallback for local dev) |
| Vector database | ChromaDB |
| Embeddings | `all-MiniLM-L6-v2` via sentence-transformers (local, no API key) |
| LLM — cloud | Gemini 2.5 Flash via OpenRouter (openai SDK) |
| LLM — local | Gemma 3 1B / DeepSeek R1 8B via Ollama |
| Backend | Python 3.9+ / FastAPI |
| Frontend | HTML + Vanilla JS (single-page, no build step) |
| Testing | pytest |

---

## References

**Security Standards:**
- OWASP Top 10: https://owasp.org/Top10/
- CWE Database: https://cwe.mitre.org/
- CVE / NVD: https://nvd.nist.gov/

**Training Data Sources:**
- DVWA: https://github.com/digininja/DVWA
- OWASP WebGoat: https://github.com/WebGoat/WebGoat
- OWASP Benchmark: https://github.com/OWASP-Benchmark/BenchmarkJava
- Exploit-DB: https://www.exploit-db.com/

**Technologies:**
- Neo4j: https://neo4j.com/
- ChromaDB: https://docs.trychroma.com/
- sentence-transformers: https://www.sbert.net/
- OpenRouter: https://openrouter.ai/
- Ollama: https://ollama.com/
