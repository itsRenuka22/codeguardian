"""
GraphBuilder: populates a graph store with all node/relationship types from
the CodeGuardian dataset.

Nodes:
  CodeExample, VulnerabilityType, Function, CWE, OWASPDoc, CVE, FixPattern

Relationships:
  HAS_VULN, USES_FUNCTION, MAPS_TO, DOCUMENTED_IN, EXAMPLE_CVE,
  FIXED_BY, VULNERABLE_TO
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from entity_extractor import EntityExtractor


class GraphBuilder:
    def __init__(self, store):
        self.store = store
        self.extractor = EntityExtractor()

    # ── node creators ─────────────────────────────────────────────────────────

    def create_code_nodes(self, knowledge_base: dict):
        items = knowledge_base.get("items", [])
        for item in items:
            self.store.merge_node(
                item["item_id"], "CodeExample",
                {
                    "id":       item["item_id"],
                    "code":     item.get("code", "")[:2000],
                    "language": item.get("language", ""),
                    "severity": item.get("severity", ""),
                    "source":   item.get("source", ""),
                },
            )

    def create_vulnerability_nodes(self, citation_map: dict):
        for vt_name, vt_data in citation_map.get("vulnerability_types", {}).items():
            self.store.merge_node(
                f"vuln_{vt_name}", "VulnerabilityType",
                {"id": f"vuln_{vt_name}", "name": vt_name,
                 "severity": vt_data.get("severity", "")},
            )

    def create_cwe_nodes(self, citation_map: dict):
        seen = set()
        for vt_data in citation_map.get("vulnerability_types", {}).values():
            cwe = vt_data.get("cwe", {})
            cwe_id = cwe.get("id", "")
            if cwe_id and cwe_id not in seen:
                seen.add(cwe_id)
                self.store.merge_node(
                    cwe_id, "CWE",
                    {"id": cwe_id, "name": cwe.get("name", ""),
                     "url": cwe.get("url", "")},
                )

    def create_owasp_nodes(self, citation_map: dict):
        seen = set()
        for vt_name, vt_data in citation_map.get("vulnerability_types", {}).items():
            owasp = vt_data.get("owasp", {})
            owasp_id = f"owasp_{vt_name}"
            if owasp_id not in seen:
                seen.add(owasp_id)
                self.store.merge_node(
                    owasp_id, "OWASPDoc",
                    {
                        "id":      owasp_id,
                        "title":   owasp.get("category", ""),
                        "url":     owasp.get("url", ""),
                        "summary": owasp.get("summary", "")[:500],
                    },
                )

    def create_cve_nodes(self, citation_map: dict):
        seen = set()
        for vt_data in citation_map.get("vulnerability_types", {}).values():
            for cve in vt_data.get("example_cves", []):
                cve_id = cve.get("id", "")
                if cve_id and cve_id not in seen:
                    seen.add(cve_id)
                    self.store.merge_node(
                        cve_id, "CVE",
                        {
                            "id":          cve_id,
                            "description": cve.get("description", "")[:400],
                            "severity":    cve.get("severity", ""),
                            "cvss_score":  cve.get("cvss_score", 0.0),
                        },
                    )

    def create_fix_nodes(self, citation_map: dict):
        for vt_name, vt_data in citation_map.get("vulnerability_types", {}).items():
            key_points = vt_data.get("owasp", {}).get("key_points", [])
            fix_id = f"fix_{vt_name}"
            self.store.merge_node(
                fix_id, "FixPattern",
                {
                    "id":          fix_id,
                    "vuln_type":   vt_name,
                    "description": "; ".join(key_points[:3]),
                    "example_code": "",
                },
            )

    def create_function_nodes(self, extracted_entities: list):
        seen = set()
        for entity in extracted_entities:
            lang = entity.get("language", "")
            for fn in entity.get("functions", []):
                fn_id = f"fn_{lang}_{fn}".replace(".", "_")
                if fn_id not in seen:
                    seen.add(fn_id)
                    self.store.merge_node(
                        fn_id, "Function",
                        {"id": fn_id, "name": fn, "language": lang},
                    )

    # ── relationship creators ──────────────────────────────────────────────────

    def create_relationships(self, knowledge_base: dict, extracted_entities: list):
        citation_map = self._citation_map
        vuln_types = citation_map.get("vulnerability_types", {})
        entity_by_id = {e["code_id"]: e for e in extracted_entities}

        for item in knowledge_base.get("items", []):
            code_id = item["item_id"]
            lang = item.get("language", "")

            # CodeExample -[HAS_VULN]-> VulnerabilityType
            for vt in item.get("vulnerability_types", []):
                vt_node = f"vuln_{vt}"
                if self.store.get_node(vt_node):
                    self.store.merge_edge(code_id, vt_node, "HAS_VULN")

            # CodeExample -[USES_FUNCTION]-> Function
            entity = entity_by_id.get(code_id, {})
            for fn in entity.get("functions", []):
                fn_id = f"fn_{lang}_{fn}".replace(".", "_")
                if self.store.get_node(fn_id):
                    self.store.merge_edge(code_id, fn_id, "USES_FUNCTION")

        # VulnerabilityType -[MAPS_TO]-> CWE
        # VulnerabilityType -[DOCUMENTED_IN]-> OWASPDoc
        # VulnerabilityType -[EXAMPLE_CVE]-> CVE
        # VulnerabilityType -[FIXED_BY]-> FixPattern
        for vt_name, vt_data in vuln_types.items():
            vt_node = f"vuln_{vt_name}"
            cwe_id = vt_data.get("cwe", {}).get("id", "")
            if cwe_id and self.store.get_node(cwe_id):
                self.store.merge_edge(vt_node, cwe_id, "MAPS_TO")

            owasp_id = f"owasp_{vt_name}"
            if self.store.get_node(owasp_id):
                self.store.merge_edge(vt_node, owasp_id, "DOCUMENTED_IN")

            for cve in vt_data.get("example_cves", []):
                cve_id = cve.get("id", "")
                if cve_id and self.store.get_node(cve_id):
                    self.store.merge_edge(vt_node, cve_id, "EXAMPLE_CVE")

            fix_id = f"fix_{vt_name}"
            if self.store.get_node(fix_id):
                self.store.merge_edge(vt_node, fix_id, "FIXED_BY")

        # Function -[VULNERABLE_TO]-> VulnerabilityType
        for entity in extracted_entities:
            lang = entity.get("language", "")
            code_id = entity.get("code_id", "")
            item_vuln_types = []
            for item in knowledge_base.get("items", []):
                if item["item_id"] == code_id:
                    item_vuln_types = item.get("vulnerability_types", [])
                    break
            for fn in entity.get("functions", []):
                fn_id = f"fn_{lang}_{fn}".replace(".", "_")
                for vt in item_vuln_types:
                    vt_node = f"vuln_{vt}"
                    if self.store.get_node(fn_id) and self.store.get_node(vt_node):
                        self.store.merge_edge(fn_id, vt_node, "VULNERABLE_TO")

    # ── orchestration ─────────────────────────────────────────────────────────

    def build_complete_graph(self, knowledge_base: dict, citation_map: dict):
        self._citation_map = citation_map
        print("Extracting entities from all code examples...")
        items = knowledge_base.get("items", [])
        extracted = [self.extractor.extract_entities(item) for item in items]

        print(f"Creating nodes...")
        self.create_code_nodes(knowledge_base)
        self.create_vulnerability_nodes(citation_map)
        self.create_cwe_nodes(citation_map)
        self.create_owasp_nodes(citation_map)
        self.create_cve_nodes(citation_map)
        self.create_fix_nodes(citation_map)
        self.create_function_nodes(extracted)

        print("Creating relationships...")
        self.create_relationships(knowledge_base, extracted)

        if hasattr(self.store, "save"):
            self.store.save()

        return extracted

    def get_statistics(self) -> dict:
        labels = ["CodeExample", "VulnerabilityType", "Function",
                  "CWE", "OWASPDoc", "CVE", "FixPattern"]
        stats = {label: self.store.count(label) for label in labels}
        stats["relationships"] = self.store.count_rels()
        stats["total_nodes"] = sum(v for k, v in stats.items()
                                   if k != "relationships")
        return stats
