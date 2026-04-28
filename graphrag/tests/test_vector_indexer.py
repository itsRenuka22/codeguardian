import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config


@pytest.fixture(scope="module")
def indexer(tmp_path_factory):
    from vector_indexer import VectorIndexer
    path = str(tmp_path_factory.mktemp("chroma"))
    return VectorIndexer(chroma_path=path, model_name=config.EMBEDDING_MODEL)


@pytest.fixture(scope="module")
def plain_col(tmp_path_factory):
    import chromadb
    path = str(tmp_path_factory.mktemp("plain_chroma"))
    client = chromadb.PersistentClient(path=path)
    col = client.get_or_create_collection("plain_test")
    col.upsert(
        ids=["code_test_001"],
        documents=["SELECT * FROM users WHERE id = ?"],
        metadatas=[{"language": "java", "severity": "high",
                    "vulnerability_types": "sql_injection", "source": "test"}],
    )
    return col


def test_vector_indexer_import():
    from vector_indexer import VectorIndexer
    assert VectorIndexer is not None


def test_collection_created(indexer):
    col = indexer._get_or_create_collection()
    assert col is not None


def test_chromadb_storage(plain_col):
    assert plain_col.count() >= 1


def test_retrieve_by_id(plain_col):
    result = plain_col.get(ids=["code_test_001"])
    assert result["ids"] == ["code_test_001"]


def test_metadata_stored(plain_col):
    result = plain_col.get(ids=["code_test_001"], include=["metadatas"])
    assert result["metadatas"][0]["language"] == "java"
    assert result["metadatas"][0]["severity"] == "high"


def test_similarity_search_local(indexer):
    """Similarity search using local model — no API key needed."""
    col = indexer._get_or_create_collection()
    col.upsert(
        ids=["s1", "s2"],
        documents=[
            "SQL injection: SELECT * FROM users WHERE id = $_GET['id']",
            "XSS: echo $_GET['name'] without escaping",
        ],
        metadatas=[
            {"language": "php", "severity": "critical", "vulnerability_types": "sql_injection", "source": "test"},
            {"language": "php", "severity": "high",     "vulnerability_types": "xss",           "source": "test"},
        ],
    )
    results = indexer.similarity_search("sql injection vulnerability", n_results=2)
    assert isinstance(results, list)
    assert len(results) == 2
    assert "id" in results[0]
