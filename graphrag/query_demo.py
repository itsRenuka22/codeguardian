"""
End-to-end demo: graph traversal + hybrid search using the local embedding model.
No API key required.
"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.dirname(__file__))

import config
from graph_store import make_graph_store
from hybrid_querier import HybridQuerier
import chromadb


def demo_graph_traversal(store, chroma_client):
    print(f"\n{'='*60}")
    print("GRAPH STATS")
    print('='*60)
    for label in ["CodeExample", "VulnerabilityType", "Function",
                  "CWE", "OWASPDoc", "CVE", "FixPattern"]:
        print(f"  {label}: {store.count(label)}")
    print(f"  Relationships: {store.count_rels()}")

    print(f"\n{'='*60}")
    print("GRAPH TRAVERSAL: code_001")
    print('='*60)
    querier = HybridQuerier(store, chroma_client)
    result = querier.graph_traverse("code_001")
    print(json.dumps(result, indent=2))

    print(f"\n{'='*60}")
    print("VECTOR STATS")
    print('='*60)
    try:
        col = chroma_client.get_collection("code_embeddings")
        print(f"  Indexed: {col.count()} items")
    except Exception:
        print("  Not yet indexed — run: python index_vectors.py")


def demo_hybrid_search(store, chroma_client, query_code: str):
    querier = HybridQuerier(store, chroma_client)

    print(f"\n{'='*60}")
    print("HYBRID SEARCH")
    print('='*60)
    print(f"Query:\n{query_code}\n")

    formatted = querier.search_and_format(query_code, top_k=3)
    print(f"Found: {formatted['found']} results")
    print(f"\nSummary:\n{formatted['summary']}")
    if formatted.get("fix_guidance"):
        print("\nFix guidance:")
        for fg in formatted["fix_guidance"][:2]:
            print(f"  - {fg[:120]}")


if __name__ == "__main__":
    graph_local_path = os.path.join(os.path.dirname(__file__), "data", "graph_db")
    store = make_graph_store(
        neo4j_uri=config.NEO4J_URI,
        neo4j_user=config.NEO4J_USER,
        neo4j_password=config.NEO4J_PASSWORD,
        local_path=graph_local_path,
    )
    chroma_client = chromadb.PersistentClient(path=config.CHROMA_PATH)

    demo_graph_traversal(store, chroma_client)

    sample_query = """
<?php
$id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $query);
?>
"""
    try:
        col = chroma_client.get_collection("code_embeddings")
        if col.count() > 0:
            demo_hybrid_search(store, chroma_client, sample_query)
        else:
            print("\nSkipping hybrid search — run python index_vectors.py first.")
    except Exception:
        print("\nSkipping hybrid search — run python index_vectors.py first.")

    store.close()
