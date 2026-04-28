# CodeGuardian

**AI-Powered Security Code Review System**

An intelligent system that analyzes code for security vulnerabilities using a GraphRAG-powered agent with a Planner → Executor → Critic loop, persistent caching, and professional references (OWASP, CWE, CVE).

## Team Members

| Name | SJSU ID | Email |
|------|---------|-------|
| Renuka Prasad Patwari | 018179902 | renukaprasad.patwari@sjsu.edu |
| Ekant Kapgate | 015945761 | ekant.kapgate@sjsu.edu |
| Viswa Surya Kumar Suvvada | 018316532 | viswasuryakumar.suvvada@sjsu.edu |

**Course:** CMPE258 - Deep Learning
**Project Type:** LLMs + AI Agent System (Option 2)

---

## Problem Statement

- Security vulnerabilities cost companies billions annually
- Manual code review is slow, expensive, and inconsistent
- Existing static analysis tools produce too many false positives and lack contextual explanation

**CodeGuardian** uses a GraphRAG + agent architecture to automatically detect vulnerabilities, explain their impact, and surface actionable fixes with authoritative citations.

---

## Project Progress

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Data Collection & Preparation | Done |
| 2 | Entity Extraction | Done |
| 3 | Graph Construction (Neo4j / NetworkX) | Done |
| 4 | Vector Indexing (ChromaDB + all-MiniLM-L6-v2) | Done |
| 5 | Hybrid Querier (graph + vector) | Done |
| 6 | Agent Architecture (Planner / Executor / Critic / Memory) | Done |
| 7 | Multi-Model Testing (Claude / GPT-4 / Llama) | Pending |
| 8 | UI Development (FastAPI + React) | Pending |
| 9 | Comprehensive Evaluation & Report | Pending |

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        USER INTERFACE                        │
│               (Web UI / CLI — file or inline code)           │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│                       AI AGENT LAYER                         │
│                                                              │
│  ┌───────────┐   ┌───────────┐   ┌───────────┐             │
│  │  PLANNER  │ → │ EXECUTOR  │ → │  CRITIC   │             │
│  │           │   │           │   │           │             │
│  │ Detects   │   │ Runs all  │   │ Scores    │             │
│  │ language  │   │ queries   │   │ confidence│             │
│  │ + vuln    │   │ dedupes   │   │ decides   │             │
│  │ hints;    │   │ & ranks   │   │ retry or  │             │
│  │ builds    │   │ results   │   │ accept    │             │
│  │ query     │   │           │   │           │             │
│  │ plan      │   │           │   │           │             │
│  └───────────┘   └───────────┘   └───────────┘             │
│                        ↑ retry if low confidence             │
│              ┌──────────────────────┐                       │
│              │   MEMORY (SHA-256    │                       │
│              │   JSON cache)        │                       │
│              └──────────────────────┘                       │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│                      GRAPHRAG LAYER                          │
│                                                              │
│  ┌─────────────────────┐    ┌─────────────────────┐        │
│  │   GRAPH DATABASE    │    │   VECTOR DATABASE   │        │
│  │  Neo4j / NetworkX   │    │     ChromaDB        │        │
│  │                     │    │                     │        │
│  │  369 nodes          │    │  260 embeddings     │        │
│  │  610 relationships  │    │  all-MiniLM-L6-v2   │        │
│  │                     │    │  (local, no API key)│        │
│  └─────────────────────┘    └─────────────────────┘        │
│                                                              │
│  Hybrid search → similar code + CWE + OWASP + fix patterns  │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│                      DATA FOUNDATION                         │
│  260 code examples  |  65 eval cases  |  673 CVE records    │
│  26 OWASP docs      |  12 vuln types  |  citation map       │
└──────────────────────────────────────────────────────────────┘
```

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

### Reference Data

| Source | Count | Purpose |
|--------|-------|---------|
| CVE Database | 673 records | Real vulnerability citations |
| OWASP Docs | 26 pages | Official prevention guides |

### Vulnerability Types Covered (12)

SQL Injection, XSS, Command Injection, Path Traversal, File Inclusion, Authentication Bypass, Insecure Deserialization, XXE, SSRF, Code Injection, LDAP Injection, Buffer Overflow

---

## Quick Start

### Prerequisites

```bash
pip install -r graphrag/requirements.txt
# No API key needed — uses local all-MiniLM-L6-v2 embeddings
```

### Analyze a file

```bash
cd graphrag
python analyze.py --file path/to/code.php
```

### Analyze an inline snippet

```bash
python analyze.py --code '$id = $_GET["id"]; mysqli_query($conn, $query);'
```

### Verbose output (show evidence matches)

```bash
python analyze.py --code '...' --verbose
```

### JSON output

```bash
python analyze.py --code '...' --json
```

### Run the full 65-case evaluation suite

```bash
python analyze.py --eval
# Saves metrics to graphrag/data/eval_results.json
```

### Cache management

```bash
python analyze.py --cache-stats
python analyze.py --clear-cache
```

### Run tests

```bash
cd graphrag
pytest tests/ -v
```

---

## Example Output

```
============================================================
  VERDICT     : VULNERABLE (confidence 92%)
  Language    : php
  Vulns found : sql_injection, xss
  Severity    : critical
  Matches     : 7  |  Iterations: 1
============================================================

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
  "suspected_by_planner": ["sql_injection", "xss"],
  "total_matches": 7,
  "iterations": 1,
  "from_cache": false,
  "evidence": [
    {
      "code_id": "php_sqli_001",
      "language": "php",
      "severity": "critical",
      "similarity_distance": 0.08,
      "cwes": [{"id": "CWE-89", "name": "SQL Injection"}],
      "owasp_docs": [{"title": "OWASP A03:2021", "url": "..."}]
    }
  ],
  "fix_guidance": [
    {"vuln_type": "sql_injection", "description": "Use prepared statements..."}
  ]
}
```

---

## Repository Structure

```
codeguardian/
├── README.md
├── data/
│   ├── raw/                        # Original data from 5 sources
│   └── processed/                  # knowledge_base.json, eval_set.json, citation_map.json
└── graphrag/
    ├── analyze.py                  # CLI entry point
    ├── config.py                   # Central configuration (paths, model names)
    ├── requirements.txt
    ├── src/
    │   ├── entity_extractor.py     # Extract functions/sources from code
    │   ├── graph_store.py          # Neo4j + NetworkX dual-backend graph store
    │   ├── graph_builder.py        # Build 369-node / 610-edge knowledge graph
    │   ├── vector_indexer.py       # ChromaDB indexing with all-MiniLM-L6-v2
    │   └── hybrid_querier.py       # Hybrid graph + vector search
    ├── agent/
    │   ├── agent.py                # CodeGuardianAgent orchestrator
    │   ├── planner.py              # Language detection + query plan builder
    │   ├── executor.py             # Runs queries, deduplicates, ranks results
    │   ├── critic.py               # Confidence scoring + retry decision
    │   └── memory.py               # SHA-256 JSON cache (persistent across runs)
    ├── data/
    │   ├── graph_db/               # NetworkX graph (JSON, auto-created)
    │   ├── vector_db/              # ChromaDB persistent store (auto-created)
    │   └── agent_cache.json        # Analysis result cache
    └── tests/
        ├── test_entity_extractor.py
        ├── test_graph_builder.py
        ├── test_vector_indexer.py
        ├── test_hybrid_querier.py
        └── test_agent.py
```

---

## Agent Architecture (Phase 6)

The agent runs a **Planner → Executor → Critic** loop with automatic retry on low confidence:

1. **Planner** — detects language (PHP/Python/Java/Ruby/JS) and vulnerability hints from code patterns; builds a prioritized list of GraphRAG queries
2. **Executor** — runs all queries against the hybrid querier, deduplicates by `code_id`, ranks by severity then vector distance
3. **Critic** — scores confidence using a heuristic formula:
   - Base: `min(matches / 3, 1.0)`
   - +0.20 for critical/high severity top match
   - +0.15 if planner's suspected vuln types appear in results
   - +0.10 for multiple distinct vuln types found
   - -0.20 if top vector distance > 0.6
4. **Retry** — if confidence < 0.35 and attempts < 2, replanner widens `top_k` and adds a broader fallback query
5. **Memory** — results cached by SHA-256 of input code; cache survives restarts

Verdict thresholds: ≥ 0.75 → `vulnerable` | ≥ 0.45 → `likely_vulnerable` | ≥ 0.20 → `unclear` | < 0.20 → `likely_clean`

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Graph database | Neo4j (with NetworkX fallback for local dev) |
| Vector database | ChromaDB |
| Embeddings | `all-MiniLM-L6-v2` via sentence-transformers (local, no API key) |
| LLMs (Phase 7) | Claude Sonnet 4 / GPT-4o / Llama 3.1 70B |
| Backend (Phase 8) | Python 3.9+ / FastAPI |
| Frontend (Phase 8) | React + Tailwind CSS |
| Testing | pytest |

---

## References

**Security:**
- OWASP Top 10: https://owasp.org/Top10/
- CWE Database: https://cwe.mitre.org/
- CVE / NVD: https://nvd.nist.gov/

**Data Sources:**
- DVWA: https://github.com/digininja/DVWA
- OWASP WebGoat: https://github.com/WebGoat/WebGoat
- OWASP Benchmark: https://github.com/OWASP-Benchmark/BenchmarkJava

**Technologies:**
- Neo4j: https://neo4j.com/
- ChromaDB: https://docs.trychroma.com/
- sentence-transformers: https://www.sbert.net/
