"""
Memory: persistent JSON cache keyed by SHA-256 of the input code.
Survives restarts; safe to read/write concurrently within a single process.
"""
import json
import hashlib
import os
from datetime import datetime
from typing import Optional


class Memory:
    def __init__(self, cache_path: str):
        self.cache_path = cache_path
        self._cache: dict = {}
        self._load()

    # ── public API ────────────────────────────────────────────────────────────

    def get(self, code: str) -> Optional[dict]:
        key = self._key(code)
        return self._cache.get(key)

    def store(self, code: str, result: dict):
        key = self._key(code)
        self._cache[key] = {
            **result,
            "_cached_at": datetime.utcnow().isoformat(),
        }
        self._save()

    def clear(self):
        self._cache = {}
        self._save()

    def stats(self) -> dict:
        size_bytes = 0
        if os.path.exists(self.cache_path):
            size_bytes = os.path.getsize(self.cache_path)

        return {
            "entries": len(self._cache),
            "path": self.cache_path,
            "size_bytes": size_bytes,
            "size_kb": round(size_bytes / 1024, 2),
        }

    # ── private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _key(code: str) -> str:
        return hashlib.sha256(code.encode()).hexdigest()[:16]

    def _load(self):
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path) as f:
                    self._cache = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._cache = {}

    def _save(self):
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        with open(self.cache_path, "w") as f:
            json.dump(self._cache, f, indent=2)
