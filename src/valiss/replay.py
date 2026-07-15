# pyright: strict
"""Replay suppression: record request nonces and report duplicates within a
retention window, so a captured signed request cannot be replayed for the same
operation before its signature ages out.

The :class:`ReplayCache` protocol is the pluggable seam a :class:`~valiss.
verifier.Verifier` calls; :class:`MemoryReplayCache` is a process-local default.
For exactly-once across multiple server instances, implement the protocol over
shared storage (Redis, a database) instead.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


@runtime_checkable
class ReplayCache(Protocol):
    """Records request nonces and reports duplicates within a retention window.
    Implementations must be safe for concurrent use."""

    def seen_before(self, nonce: str, expiry: datetime) -> bool:
        """Record ``nonce`` with the given ``expiry`` and report whether a
        still-valid entry was already present. ``expiry`` is when the entry may
        be discarded."""
        ...


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MemoryReplayCache:
    """In-memory :class:`ReplayCache` that retains each nonce until its expiry
    and prunes lazily. Process-local and safe for concurrent use.

    ``clock`` overrides the time source (inject a fixed clock in tests); it must
    return timezone-aware datetimes consistent with the verifier's own clock.
    """

    def __init__(self, *, clock: Callable[[], datetime] | None = None):
        self._now = clock or _utcnow
        self._seen: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def seen_before(self, nonce: str, expiry: datetime) -> bool:
        now = self._now()
        with self._lock:
            expired = [key for key, exp in self._seen.items() if exp <= now]
            for key in expired:
                del self._seen[key]
            seen = self._seen.get(nonce)
            if seen is not None and seen > now:
                return True
            self._seen[nonce] = expiry
            return False
