import os
from pathlib import Path

# Resolve base dirs robustly regardless of how/where this module is imported.
_THIS_FILE = Path(os.path.abspath(__file__))
# Walk up until we find a directory that contains both "src" and "data" siblings
# (i.e. the graphrag/ root), then go one more level for the project root.
_candidate = _THIS_FILE.parent
while _candidate != _candidate.parent:
    if (_candidate / "src").is_dir() and (_candidate / "data").is_dir():
        break
    _candidate = _candidate.parent

BASE_DIR = _candidate
DATA_DIR = BASE_DIR / "data"
PROJECT_ROOT = BASE_DIR.parent

# Neo4j
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "codeguardian")

# ChromaDB
CHROMA_PATH = str(DATA_DIR / "vector_db")

# Source data
PROCESSED_DATA_DIR = str(PROJECT_ROOT / "data" / "processed")
DATA_PATH = PROCESSED_DATA_DIR
KNOWLEDGE_BASE_PATH = os.path.join(PROCESSED_DATA_DIR, "rag_knowledge_base_code_only.json")
CITATION_MAP_PATH = os.path.join(PROCESSED_DATA_DIR, "citation_map.json")
EVALUATION_SET_PATH = os.path.join(PROCESSED_DATA_DIR, "evaluation_set_hybrid.json")

# Embedding model (local, no API key required)
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
CHROMA_COLLECTION_NAME = "code_embeddings"
