import os
import sys
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)


def test_directories_exist():
    for d in ["data", "src", "tests", "data/vector_db"]:
        assert os.path.isdir(os.path.join(BASE_DIR, d)), f"Missing: {d}/"


def test_config_loads():
    import config
    assert hasattr(config, "NEO4J_URI")
    assert hasattr(config, "CHROMA_PATH")
    assert hasattr(config, "DATA_PATH")
    assert hasattr(config, "EMBEDDING_MODEL")


def test_chromadb_import():
    import chromadb
    client = chromadb.PersistentClient(path=os.path.join(BASE_DIR, "data", "vector_db"))
    assert client is not None


def test_data_files_exist():
    from config import KNOWLEDGE_BASE_PATH, CITATION_MAP_PATH
    assert os.path.exists(KNOWLEDGE_BASE_PATH), f"Missing: {KNOWLEDGE_BASE_PATH}"
    assert os.path.exists(CITATION_MAP_PATH), f"Missing: {CITATION_MAP_PATH}"


def test_data_files_readable():
    import json
    from config import KNOWLEDGE_BASE_PATH, CITATION_MAP_PATH
    with open(KNOWLEDGE_BASE_PATH) as f:
        kb = json.load(f)
    assert "items" in kb or isinstance(kb, list)
    with open(CITATION_MAP_PATH) as f:
        cm = json.load(f)
    assert cm is not None
