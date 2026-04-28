"""
Index all 260 code examples into ChromaDB using all-MiniLM-L6-v2 (local, no API key).
Run with: python index_vectors.py [--force]
"""
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.dirname(__file__))

import config
from vector_indexer import VectorIndexer


def main():
    force = "--force" in sys.argv

    print(f"ChromaDB path : {config.CHROMA_PATH}")
    print(f"Embedding model: {config.EMBEDDING_MODEL}")

    with open(config.KNOWLEDGE_BASE_PATH) as f:
        knowledge_base = json.load(f)

    indexer = VectorIndexer(
        chroma_path=config.CHROMA_PATH,
        model_name=config.EMBEDDING_MODEL,
    )

    indexer.index_all_code(knowledge_base, force=force)

    stats = indexer.get_collection_stats()
    print(f"\nCollection stats: {stats}")

    ok = indexer.verify_indexing()
    print(f"Verification: {'PASS' if ok else 'FAIL'}")


if __name__ == "__main__":
    main()
