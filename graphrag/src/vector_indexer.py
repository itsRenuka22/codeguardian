"""
VectorIndexer: embeds all code examples locally using all-MiniLM-L6-v2
and stores them in ChromaDB for similarity search. No API key required.
"""
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction  # type: ignore[import-untyped]


class VectorIndexer:
    def __init__(self, chroma_path: str, model_name: str = "all-MiniLM-L6-v2"):
        self.client = chromadb.PersistentClient(path=chroma_path)
        self.ef = SentenceTransformerEmbeddingFunction(model_name=model_name)
        self.collection = None

    def _get_or_create_collection(self, force: bool = False):
        name = "code_embeddings"
        if force:
            try:
                self.client.delete_collection(name)
            except Exception:
                pass
        try:
            self.collection = self.client.get_or_create_collection(
                name=name,
                embedding_function=self.ef,
                metadata={"hnsw:space": "cosine"},
            )
        except ValueError as e:
            if "embedding function conflict" in str(e).lower():
                # persisted collection used a different embedding function; reset it
                print("Embedding function conflict detected — resetting collection.")
                self.client.delete_collection(name)
                self.collection = self.client.get_or_create_collection(
                    name=name,
                    embedding_function=self.ef,
                    metadata={"hnsw:space": "cosine"},
                )
            else:
                raise
        return self.collection

    def generate_embedding(self, text: str) -> list:
        return self.ef([text])[0]

    def index_all_code(self, knowledge_base: dict, force: bool = False):
        """Index all code examples. Skips if already fully indexed unless force=True."""
        self._get_or_create_collection(force=force)
        items = knowledge_base.get("items", [])

        if self.collection.count() == len(items) and not force:
            print(f"Already indexed {len(items)} items. Use --force to re-index.")
            return

        print(f"Indexing {len(items)} code examples with {self.ef.model_name}...")
        batch_size = 50
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            ids, docs, metas = [], [], []
            for item in batch:
                lang = item.get("language", "")
                vuln_types = item.get("vulnerability_types", [])
                doc = (
                    f"Language: {lang}\n"
                    f"Vulnerability: {', '.join(vuln_types)}\n"
                    f"Code:\n{item.get('code', '')}"
                )
                ids.append(item["item_id"])
                docs.append(doc)
                metas.append({
                    "language":            lang,
                    "severity":            item.get("severity", ""),
                    "vulnerability_types": ",".join(vuln_types),
                    "source":              item.get("source", ""),
                })
            self.collection.upsert(ids=ids, documents=docs, metadatas=metas)
            print(f"  [{min(i + batch_size, len(items))}/{len(items)}] indexed")

        print(f"Done. Total indexed: {self.collection.count()}")

    def index_code_example(self, item: dict):
        if self.collection is None:
            self._get_or_create_collection()
        lang = item.get("language", "")
        vuln_types = item.get("vulnerability_types", [])
        doc = (
            f"Language: {lang}\n"
            f"Vulnerability: {', '.join(vuln_types)}\n"
            f"Code:\n{item.get('code', '')}"
        )
        self.collection.upsert(
            ids=[item["item_id"]],
            documents=[doc],
            metadatas=[{
                "language":            lang,
                "severity":            item.get("severity", ""),
                "vulnerability_types": ",".join(vuln_types),
                "source":              item.get("source", ""),
            }],
        )

    def get_collection_stats(self) -> dict:
        if self.collection is None:
            self._get_or_create_collection()
        count = self.collection.count()
        sample_ids = []
        if count > 0:
            peeked = self.collection.peek(limit=3)
            sample_ids = peeked.get("ids", [])
        return {"count": count, "sample_ids": sample_ids}

    def verify_indexing(self) -> bool:
        if self.collection is None:
            self._get_or_create_collection()
        if self.collection.count() == 0:
            return False
        try:
            first_id = self.collection.peek(limit=1)["ids"][0]
            result = self.collection.get(ids=[first_id])
            return bool(result and result.get("ids"))
        except Exception:
            return False

    def similarity_search(self, query_text: str, n_results: int = 5) -> list:
        if self.collection is None:
            self._get_or_create_collection()
        n = min(n_results, self.collection.count())
        if n == 0:
            return []
        results = self.collection.query(query_texts=[query_text], n_results=n)
        ids       = results.get("ids", [[]])[0]
        distances = results.get("distances", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        return [
            {"id": id_, "distance": dist, "metadata": meta}
            for id_, dist, meta in zip(ids, distances, metadatas)
        ]
