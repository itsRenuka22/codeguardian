"""
Build the CodeGuardian knowledge graph.
Uses Neo4j if available, otherwise falls back to local NetworkX store.
"""
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.dirname(__file__))

from graph_store import make_graph_store
from graph_builder import GraphBuilder
import config


def main():
    store = make_graph_store(
        neo4j_uri=config.NEO4J_URI,
        neo4j_user=config.NEO4J_USER,
        neo4j_password=config.NEO4J_PASSWORD,
        local_path=os.path.join(os.path.dirname(__file__), "data", "graph_db"),
    )

    print(f"Backend: {store.backend()}")
    print("Loading data files...")

    with open(config.KNOWLEDGE_BASE_PATH) as f:
        knowledge_base = json.load(f)
    with open(config.CITATION_MAP_PATH) as f:
        citation_map = json.load(f)

    print(f"Knowledge base: {knowledge_base['total_items']} items")
    print(f"Vulnerability types: {len(citation_map['vulnerability_types'])}")

    print("\nClearing existing graph...")
    store.clear()

    builder = GraphBuilder(store)
    builder.build_complete_graph(knowledge_base, citation_map)

    stats = builder.get_statistics()
    print("\nGraph statistics:")
    for label, count in stats.items():
        print(f"  {label}: {count}")

    store.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
