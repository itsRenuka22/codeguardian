CodeGuardian 🛡️
AI-Powered Security Code Review System
An intelligent system that analyzes code for security vulnerabilities, explains them clearly, and provides fixes with professional references (OWASP, CWE, CVE).

Team Members :-
Name-SJSU ID -Email
Renuka Prasad Patwari - 018179902 - renukaprasad.patwari@sjsu.edu 
Ekant Kapgate - 015945761 - ekant.kapgate@sjsu.edu
Viswa Surya Kumar Suvvada - 018316532 - viswasuryakumar.suvvada@sjsu.edu

Course: CMPE258 - Deep Learning
Project Type: LLMs + AI Agent System (Option 2)

What Problem Are We Solving?
The Problem:
Security vulnerabilities cost companies billions annually
Manual code review is slow and expensive
Existing tools give too many false alarms or unclear results
Our Solution: CodeGuardian uses AI to automatically:
Find security vulnerabilities in code
Explain why they're dangerous
Show how to fix them
Provide professional references (OWASP, CWE, CVE)
Example:
php
// User uploads this code:
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";

// CodeGuardian finds:
⚠️ SQL Injection (CRITICAL)
📍 Line 2: User input in SQL query
💡 Fix: Use prepared statements
📖 Reference: CWE-89, OWASP A03:2021


📊 Dataset
We collected data from 7 different sources to train our system:
Code Examples (260 total)
Source  | Files | Language | Purpose
DVWA    |  19    |  PHP    |  Educational web security examples
OWASP WebGoat |69|  Java   | Official OWASP training lessons
OWASP Benchmark | 50| Java | Test cases with known answers
Exploit-DB  | 159   | ulti | Real-world attack code
GitHub Issues| 10   | Various | Production bugs from real projects

## Reference Data

| Source | Count | Purpose |
|--------|-------|---------|
| CVE Database | 673 records | Real vulnerability reports for citations |
| OWASP Docs | 26 pages | Official prevention guides |

Vulnerability Coverage
Our dataset covers 12 types of vulnerabilities: SQL Injection, Cross-Site Scripting (XSS), Command Injection, Path Traversal, File Inclusion, Authentication Bypass, Insecure Deserialization, XML External Entity (XXE), Server-Side Request Forgery (SSRF), Code Injection, LDAP Injection, Buffer Overflow.



System Architecture
┌─────────────────────────────────────────────────────────────┐
│                       USER INTERFACE                        │
│              (Web UI - Upload & View Results)               │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                      AI AGENT LAYER                         │
│                                                             │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│   │   PLANNER    │→ │   EXECUTOR   │→ │    CRITIC    │   │
│   │ (Strategy)   │  │ (Run Tools)  │  │  (Quality)   │   │
│   └──────────────┘  └──────────────┘  └──────────────┘   │
│                            ↓                               │
│              ┌─────────────────────────┐                  │
│              │   MEMORY SYSTEM         │                  │
│              │  (Learning & History)   │                  │
│              └─────────────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                     TOOLS LAYER                             │
│                                                             │
│  ┌────────────────────────────────────────────────────┐   │
│  │              GRAPHRAG (Main Tool)                  │   │
│  │  ┌──────────────────┐    ┌──────────────────┐    │   │
│  │  │ GRAPH DATABASE   │ +  │ VECTOR DATABASE  │    │   │
│  │  │    (Neo4j)       │    │   (ChromaDB)     │    │   │
│  │  │                  │    │                  │    │   │
│  │  │ • 260 Code nodes │    │ • 260 Embeddings │    │   │
│  │  │ • 140+ Other     │    │ • Similarity     │    │   │
│  │  │   nodes          │    │   Search         │    │   │
│  │  │ • 600+ Relations │    │                  │    │   │
│  │  └──────────────────┘    └──────────────────┘    │   │
│  │                                                    │   │
│  │  Returns: Similar code + CWE + OWASP + Fixes     │   │
│  └────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌────────────────────────────────────────────────────┐   │
│  │              OTHER TOOLS                           │   │
│  │  • Citation Lookup (OWASP/CWE/CVE)                │   │
│  │  • Code Analyzers                                  │   │
│  │  • Web Search (optional)                           │   │
│  └────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    LLM PROVIDERS                            │
│        Claude Sonnet 4  |  GPT-4o  |  Llama 3.1 70B        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   DATA FOUNDATION                           │
│                                                             │
│  Knowledge Base: 260 code examples                         │
│  Evaluation Set: 65 test cases                             │
│  Citation Map: 12 vulnerability types                      │
│  CVE Database: 673 records                                  │
│  OWASP Docs: 26 prevention guides                          │
└─────────────────────────────────────────────────────────────┘

How It Works
User uploads code through web interface
Agent plans analysis - decides which tools to use
GraphRAG searches - finds similar vulnerable code + related info
Agent executes - gathers all relevant data
Critic evaluates - checks quality of analysis
Memory stores - learns from this analysis
LLM generates - creates professional security report
User receives - vulnerabilities, fixes, and references


Progress
✅ Completed
-Data Collection & Preparation
-Collected 307 code files from 5 sources (DVWA, WebGoat, OWASP Benchmark, Exploit-DB, GitHub Issues)
-Collected 673 CVE records from National Vulnerability Database
-Collected 26 OWASP documentation pages
-Cleaned and standardized all data
-Created knowledge base with 260 code examples
-Created evaluation set with 65 test cases
-Built citation map linking 12 vulnerability types to CWE, OWASP, CVE, and fixes


⏳ Currently Implementing
-GraphRAG System (Phase 5)
-Entity extraction from code (extracting functions, vulnerabilities, sources)
-Knowledge graph construction in Neo4j (creating nodes and relationships)
-Vector embedding generation using OpenAI
-ChromaDB indexing for similarity search
-Hybrid query interface (combining graph + vector search)


📋 To Do
AI Agent System
-Planner component (strategy and planning)
-Executor component (tool execution)
-Critic component (quality evaluation)
-Stateful memory system (learning and history)
-Tool integration and orchestration

Multi-Model Testing
-Claude Sonnet 4 integration
-GPT-4o integration
-Llama 3.1 70B integration
-Performance comparison and benchmarking

User Interface
-Web application development
-Code upload functionality
-Results visualization
-Analysis history tracking
-Evaluation & Documentation
-Testing on 65-case evaluation set
-Metrics calculation (precision, recall, F1)
-GraphRAG vs simple RAG comparison
-Final project report
-Presentation and demo video

## 🎯 Project Milestones

| Milestone | Status |
|-----------|--------|
| Data Collection Complete | ✅ Done |
| Dataset Preparation Complete | ✅ Done |
| GraphRAG Implementation | ⏳ In Progress |
| AI Agent Development | 📋 To Do |
| Multi-Model Testing | 📋 To Do |
| UI Development | 📋 To Do |
| Comprehensive Evaluation | 📋 To Do |
| Final Deliverables | 📋 To Do |

 How to Use (When Complete)
 # Upload code
user_code = """
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
"""

# Analyze
report = codeguardian.analyze(user_code)

# Get results
print(report['vulnerabilities'])  # SQL Injection found
print(report['fixes'])             # Use prepared statements
print(report['references'])        # CWE-89, OWASP A03:2021


 Repository Structure
 codeguardian/
├── data/
│   ├── raw/                    # Original data from 7 sources
│   └── processed/              # Clean datasets (260 examples + 65 tests)
├── graphrag/                   # GraphRAG implementation (in progress)
│   ├── src/                    # Core GraphRAG code
│   ├── data/                   # Graph and vector databases
│   └── tests/                  # Testing suite
├── agent/                      # AI Agent system (to do)
├── models/                     # LLM clients (to do)
├── api/                        # Backend API (to do)
├── frontend/                   # Web UI (to do)
├── evaluation/                 # Evaluation scripts (to do)
└── README.md

## 🛠️ Technology Stack

**Databases:**
- Neo4j (Graph database for relationships)
- ChromaDB (Vector database for similarity search)

**AI Models:**
- Claude Sonnet 4 (Anthropic)
- GPT-4o (OpenAI)
- Llama 3.1 70B (Meta)

**Backend:**
- Python 3.9+
- FastAPI (REST API)

**Frontend:**
- React
- Tailwind CSS

## 📚 Key References

**Security Resources:**
- OWASP Top 10: https://owasp.org/Top10/
- CWE Database: https://cwe.mitre.org/
- CVE Database: https://nvd.nist.gov/

**Data Sources:**
- DVWA: https://github.com/digininja/DVWA
- OWASP WebGoat: https://github.com/WebGoat/WebGoat
- OWASP Benchmark: https://github.com/OWASP-Benchmark/BenchmarkJava

**Technologies:**
- Neo4j: https://neo4j.com/
- ChromaDB: https://docs.trychroma.com/