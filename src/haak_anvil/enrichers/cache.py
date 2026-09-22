"""Tiny JSON file cache with TTL, used by enrichers to avoid re-hitting APIs.

One JSON file per key under ``~/.haak-anvil/cache/<namespace>/``. Values are
stored with a timestamp and considered fresh for ``ttl_seconds``. The cache is
best-effort: any read/write error degrades to a miss rather than raising, so a
corrupt cache never breaks a report run.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


class JsonCache:
    """Namespaced, TTL'd JSON cache on the local filesystem."""

    def __init__(
        self,
        namespace: str,
        *,
        root: Path | None = None,
        ttl_seconds: int = 7 * 24 * 3600,
    ) -> None:
        base = root if root is not None else Path.home() / ".haak-anvil" / "cache"
        self.dir = Path(base) / namespace
        self.ttl_seconds = ttl_seconds

    def _path_for(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return self.dir / f"{digest}.json"

    def get(self, key: str) -> Any | None:
        """Return the cached value for ``key`` if present and not expired."""
        path = self._path_for(key)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        stored_at = raw.get("_cached_at", 0)
        if (time.time() - stored_at) > self.ttl_seconds:
            return None
        return raw.get("value")

    def set(self, key: str, value: Any) -> None:
        """Persist ``value`` under ``key``. Silently no-ops on I/O errors."""
        path = self._path_for(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"_cached_at": time.time(), "key": key, "value": value}),
                encoding="utf-8",
            )
        except OSError:
            pass
