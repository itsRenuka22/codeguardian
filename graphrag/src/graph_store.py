"""
Dual-backend graph store.
- Neo4jGraphStore  : uses a running Neo4j server (bolt)
- LocalGraphStore  : NetworkX + JSON, works without any server
GraphStore factory picks whichever is available.
"""
import json
import os
import networkx as nx


class Neo4jGraphStore:
    def __init__(self, uri, user, password):
        from neo4j import GraphDatabase
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.driver.verify_connectivity()

    def run(self, cypher, **params):
        with self.driver.session() as session:
            return list(session.run(cypher, **params))

    def run_write(self, cypher, **params):
        with self.driver.session() as session:
            session.run(cypher, **params)

    def close(self):
        self.driver.close()

    def count(self, label):
        result = self.run(f"MATCH (n:{label}) RETURN count(n) as c")
        return result[0]["c"] if result else 0

    def count_rels(self):
        result = self.run("MATCH ()-[r]->() RETURN count(r) as c")
        return result[0]["c"] if result else 0

    def clear(self):
        self.run_write("MATCH (n) DETACH DELETE n")

    def backend(self):
        return "neo4j"


class LocalGraphStore:
    """NetworkX-backed graph stored as JSON on disk."""

    def __init__(self, path: str):
        self.path = path
        self.graph_path = os.path.join(path, "graph.json")
        os.makedirs(path, exist_ok=True)
        if os.path.exists(self.graph_path):
            self._load()
        else:
            self.G = nx.MultiDiGraph()

    # ── persistence ──────────────────────────────────────────────────────────

    def _save(self):
        data = nx.node_link_data(self.G)
        with open(self.graph_path, "w") as f:
            json.dump(data, f)

    def _load(self):
        with open(self.graph_path) as f:
            data = json.load(f)
        self.G = nx.node_link_graph(data, directed=True, multigraph=True)

    # ── write helpers ─────────────────────────────────────────────────────────

    def merge_node(self, node_id: str, label: str, props: dict):
        if not self.G.has_node(node_id):
            self.G.add_node(node_id, label=label, **props)
        else:
            self.G.nodes[node_id].update(props)

    def merge_edge(self, src: str, dst: str, rel_type: str):
        for _, _, data in self.G.edges(src, data=True):
            if data.get("type") == rel_type and _ == src:
                return
        # check properly
        for u, v, data in self.G.edges(data=True):
            if u == src and v == dst and data.get("type") == rel_type:
                return
        self.G.add_edge(src, dst, type=rel_type)

    def save(self):
        self._save()

    def clear(self):
        self.G = nx.MultiDiGraph()
        self._save()

    # ── query helpers ─────────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> dict:
        if self.G.has_node(node_id):
            return dict(self.G.nodes[node_id])
        return {}

    def get_neighbors(self, node_id: str, rel_type: str = None) -> list:
        results = []
        for u, v, data in self.G.edges(node_id, data=True):
            if rel_type is None or data.get("type") == rel_type:
                results.append((v, dict(self.G.nodes[v])))
        return results

    def nodes_by_label(self, label: str) -> list:
        return [
            (n, dict(d)) for n, d in self.G.nodes(data=True)
            if d.get("label") == label
        ]

    def count(self, label: str) -> int:
        return sum(1 for _, d in self.G.nodes(data=True) if d.get("label") == label)

    def count_rels(self) -> int:
        return self.G.number_of_edges()

    def backend(self):
        return "local"

    def close(self):
        pass


def make_graph_store(neo4j_uri=None, neo4j_user=None, neo4j_password=None,
                     local_path=None):
    """Return Neo4jGraphStore if reachable, else LocalGraphStore."""
    if neo4j_uri:
        try:
            store = Neo4jGraphStore(neo4j_uri, neo4j_user, neo4j_password)
            print(f"Connected to Neo4j at {neo4j_uri}")
            return store
        except Exception as e:
            print(f"Neo4j unavailable ({e}). Using local graph store.")
    store = LocalGraphStore(local_path)
    print(f"Using local graph store at {local_path}")
    return store
