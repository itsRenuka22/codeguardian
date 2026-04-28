"""
HybridQuerier: the core GraphRAG engine.

Query flow:
  1. Vector search ChromaDB  → top-k similar code IDs
  2. Graph traversal          → enrich each result with relationships
  3. Return combined, ranked results ready for the agent
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))


class HybridQuerier:
    def __init__(self, graph_store, chroma_client, collection_name: str = "code_embeddings"):
        self.store = graph_store
        self.chroma = chroma_client
        self.collection_name = collection_name
        self._collection = None

    def _collection_obj(self):
        if self._collection is None:
            try:
                self._collection = self.chroma.get_collection(self.collection_name)
            except Exception:
                self._collection = None
        return self._collection

    # ── vector search ─────────────────────────────────────────────────────────

    def vector_search(self, query_code: str, top_k: int = 5) -> list:
        """Return list of code_ids most similar to query_code."""
        col = self._collection_obj()
        if col is None or col.count() == 0:
            return []
        n = min(top_k, col.count())
        results = col.query(query_texts=[query_code], n_results=n)
        ids = results.get("ids", [[]])[0]
        distances = results.get("distances", [[]])[0]
        return [
            {"id": id_, "distance": dist}
            for id_, dist in zip(ids, distances)
        ]

    # ── graph traversal ───────────────────────────────────────────────────────

    def graph_traverse(self, code_id: str) -> dict:
        """Get all graph-enriched info for a single code node."""
        node = self.store.get_node(code_id)
        if not node:
            return {}

        result = {
            "code_id":           code_id,
            "language":          node.get("language", ""),
            "severity":          node.get("severity", ""),
            "vulnerability_types": [],
            "functions":         [],
            "cwes":              [],
            "owasp_docs":        [],
            "cves":              [],
            "fix_patterns":      [],
        }

        # vulnerability types
        for vt_id, vt_data in self.store.get_neighbors(code_id, "HAS_VULN"):
            vt_name = vt_data.get("name", vt_id)
            result["vulnerability_types"].append(vt_name)

            # CWE mappings — use the graph node key as id (NetworkX strips the id attr)
            for cwe_node_key, cwe_data in self.store.get_neighbors(vt_id, "MAPS_TO"):
                cwe_info = {
                    "id":   cwe_data.get("id", "") or cwe_node_key,
                    "name": cwe_data.get("name", ""),
                }
                if cwe_info not in result["cwes"]:
                    result["cwes"].append(cwe_info)

            # OWASP docs
            for owasp_node_key, owasp_data in self.store.get_neighbors(vt_id, "DOCUMENTED_IN"):
                owasp_info = {
                    "title":   owasp_data.get("title", ""),
                    "url":     owasp_data.get("url", ""),
                    "summary": owasp_data.get("summary", "")[:200],
                }
                if owasp_info not in result["owasp_docs"]:
                    result["owasp_docs"].append(owasp_info)

            # CVE examples
            for cve_node_key, cve_data in self.store.get_neighbors(vt_id, "EXAMPLE_CVE"):
                cve_info = {
                    "id":          cve_data.get("id", "") or cve_node_key,
                    "severity":    cve_data.get("severity", ""),
                    "description": cve_data.get("description", "")[:150],
                }
                if cve_info not in result["cves"]:
                    result["cves"].append(cve_info)

            # fix patterns
            for fix_node_key, fix_data in self.store.get_neighbors(vt_id, "FIXED_BY"):
                fix_info = {
                    "vuln_type":   fix_data.get("vuln_type", ""),
                    "description": fix_data.get("description", ""),
                }
                if fix_info not in result["fix_patterns"]:
                    result["fix_patterns"].append(fix_info)

        # functions used
        for fn_id, fn_data in self.store.get_neighbors(code_id, "USES_FUNCTION"):
            fn_name = fn_data.get("name", fn_id)
            if fn_name not in result["functions"]:
                result["functions"].append(fn_name)

        return result

    # ── hybrid search ─────────────────────────────────────────────────────────

    def hybrid_search(self, query_code: str, top_k: int = 5) -> list:
        """Main entry: vector search + graph enrichment."""
        vector_results = self.vector_search(query_code, top_k=top_k)
        enriched = []
        for vr in vector_results:
            graph_data = self.graph_traverse(vr["id"])
            if graph_data:
                graph_data["similarity_distance"] = vr["distance"]
                enriched.append(graph_data)
        return enriched

    # ── formatting ────────────────────────────────────────────────────────────

    def format_results(self, results: list) -> dict:
        """Format enriched results for agent consumption."""
        if not results:
            return {"found": 0, "results": [], "summary": "No similar examples found."}

        summary_parts = []
        for r in results:
            vts = ", ".join(r.get("vulnerability_types", [])) or "unknown"
            cwes = ", ".join(c["id"] for c in r.get("cwes", [])) or "none"
            summary_parts.append(
                f"{r['code_id']} ({r['language']}, {r['severity']}): "
                f"vulns={vts}, CWEs={cwes}"
            )

        all_fix_descriptions = []
        for r in results:
            for fp in r.get("fix_patterns", []):
                desc = fp.get("description", "")
                if desc and desc not in all_fix_descriptions:
                    all_fix_descriptions.append(desc)

        return {
            "found":          len(results),
            "results":        results,
            "summary":        "\n".join(summary_parts),
            "fix_guidance":   all_fix_descriptions[:5],
        }

    # ── convenience ──────────────────────────────────────────────────────────

    def search_and_format(self, query_code: str, top_k: int = 5) -> dict:
        results = self.hybrid_search(query_code, top_k=top_k)
        return self.format_results(results)
