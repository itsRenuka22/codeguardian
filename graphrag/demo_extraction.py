import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.dirname(__file__))

from entity_extractor import EntityExtractor
from config import KNOWLEDGE_BASE_PATH

def main():
    with open(KNOWLEDGE_BASE_PATH) as f:
        kb = json.load(f)

    items = kb["items"][:10]
    extractor = EntityExtractor()

    stats = {"total": len(items), "with_functions": 0, "with_sources": 0}

    for item in items:
        result = extractor.extract_entities(item)
        has_funcs = len(result["functions"]) > 0
        has_sources = len(result["sources"]) > 0
        if has_funcs:
            stats["with_functions"] += 1
        if has_sources:
            stats["with_sources"] += 1
        print(f"{result['code_id']} ({result['language']}) "
              f"funcs={result['functions']} sources={result['sources']}")

    print(f"\nStats over {stats['total']} items:")
    print(f"  Functions found: {stats['with_functions']}/{stats['total']} "
          f"({stats['with_functions']/stats['total']*100:.0f}%)")
    print(f"  Sources found:   {stats['with_sources']}/{stats['total']} "
          f"({stats['with_sources']/stats['total']*100:.0f}%)")

if __name__ == "__main__":
    main()
