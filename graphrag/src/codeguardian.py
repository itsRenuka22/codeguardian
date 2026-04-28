"""
CodeGuardian: top-level façade that initialises all subsystems and exposes
a single `analyze(code)` method for the agent layer.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import chromadb

from graph_store import make_graph_store
from graph_builder import GraphBuilder
from vector_indexer import VectorIndexer
from hybrid_querier import HybridQuerier


class CodeGuardian:
    def __init__(self, config):
        self.config = config
        self.store = None
        self.indexer = None
        self.querier = None
        self._ready = False

    def initialize(self, rebuild_graph: bool = False, reindex_vectors: bool = False):
        cfg = self.config

        # graph
        graph_local_path = os.path.join(os.path.dirname(cfg.__file__), "data", "graph_db")
        self.store = make_graph_store(
            neo4j_uri=cfg.NEO4J_URI,
            neo4j_user=cfg.NEO4J_USER,
            neo4j_password=cfg.NEO4J_PASSWORD,
            local_path=graph_local_path,
        )

        if rebuild_graph or self.store.count("CodeExample") == 0:
            print("Building graph...")
            with open(cfg.KNOWLEDGE_BASE_PATH) as f:
                kb = json.load(f)
            with open(cfg.CITATION_MAP_PATH) as f:
                cm = json.load(f)
            builder = GraphBuilder(self.store)
            builder.build_complete_graph(kb, cm)

        # vectors (local model, no API key needed)
        self.indexer = VectorIndexer(
            chroma_path=cfg.CHROMA_PATH,
            model_name=cfg.EMBEDDING_MODEL,
        )
        self.indexer._get_or_create_collection()

        if reindex_vectors or self.indexer.collection.count() == 0:
            print("Indexing vectors...")
            with open(cfg.KNOWLEDGE_BASE_PATH) as f:
                kb = json.load(f)
            self.indexer.index_all_code(kb)

        # querier
        chroma_client = chromadb.PersistentClient(path=cfg.CHROMA_PATH)
        self.querier = HybridQuerier(
            graph_store=self.store,
            chroma_client=chroma_client,
            collection_name=cfg.CHROMA_COLLECTION_NAME,
        )

        self._ready = True
        print("CodeGuardian ready.")
        return self

    def analyze(self, code: str, top_k: int = 5) -> dict:
        """Analyze a code snippet and return enriched vulnerability context."""
        if not self._ready:
            raise RuntimeError("Call initialize() first.")
        return self.querier.search_and_format(code, top_k=top_k)

    def graph_stats(self) -> dict:
        if not self.store:
            return {}
        labels = ["CodeExample", "VulnerabilityType", "Function",
                  "CWE", "OWASPDoc", "CVE", "FixPattern"]
        stats = {label: self.store.count(label) for label in labels}
        stats["relationships"] = self.store.count_rels()
        return stats

    def vector_stats(self) -> dict:
        if not self.indexer:
            return {}
        return self.indexer.get_collection_stats()
