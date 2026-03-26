import time
import threading
from collections import OrderedDict


class ReplayGuard:
    """In-memory LRU nonce cache with timestamp window. Thread-safe."""

    def __init__(self, max_age_seconds: int = 300, max_cache_size: int = 100_000):
        self._max_age = max_age_seconds
        self._max_size = max_cache_size
        self._cache: OrderedDict[str, int] = OrderedDict()  # nonce -> timestamp
        self._lock = threading.Lock()

    def check(self, nonce: str, timestamp: int) -> bool:
        """Returns True if fresh (not a replay), False if replay detected.

        Checks:
        1. Is timestamp within [now - max_age, now + 60]? If not, return False.
        2. Is nonce already in cache? If yes, return False (replay).
        3. Add nonce to cache. If cache exceeds max_size, evict oldest entries.
        4. Return True.
        """
        now = int(time.time())

        # 1. Check timestamp window
        if timestamp < now - self._max_age or timestamp > now + 60:
            return False

        with self._lock:
            # 2. Check for replay
            if nonce in self._cache:
                return False

            # 3. Add nonce, evict oldest if needed
            self._cache[nonce] = timestamp
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

        # 4. Fresh message
        return True

    def clear(self) -> None:
        """Clear all cached nonces. For testing."""
        with self._lock:
            self._cache.clear()
