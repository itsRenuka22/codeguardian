import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def check():
    errors = []

    # Directories
    for d in ["data", "src", "tests", "data/vector_db"]:
        path = os.path.join(BASE_DIR, d)
        if os.path.isdir(path):
            print(f"  OK  {d}/")
        else:
            errors.append(f"Missing directory: {d}/")
            print(f"  MISSING  {d}/")

    # Config
    try:
        sys.path.insert(0, BASE_DIR)
        import config
        for attr in ["NEO4J_URI", "CHROMA_PATH", "DATA_PATH"]:
            if hasattr(config, attr):
                print(f"  OK  config.{attr}")
            else:
                errors.append(f"config missing: {attr}")
    except Exception as e:
        errors.append(f"config load failed: {e}")

    # Dependencies
    for dep in ["chromadb", "openai", "dotenv"]:
        try:
            __import__(dep)
            print(f"  OK  import {dep}")
        except ImportError:
            errors.append(f"missing package: {dep}")
            print(f"  MISSING  {dep}")

    # Data files
    try:
        from config import KNOWLEDGE_BASE_PATH, CITATION_MAP_PATH
        for path in [KNOWLEDGE_BASE_PATH, CITATION_MAP_PATH]:
            if os.path.exists(path):
                print(f"  OK  {os.path.basename(path)}")
            else:
                errors.append(f"data file missing: {path}")
                print(f"  MISSING  {path}")
    except Exception as e:
        errors.append(f"data check failed: {e}")

    if errors:
        print(f"\nSetup FAILED — {len(errors)} issue(s):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\nSetup OK")

if __name__ == "__main__":
    check()
