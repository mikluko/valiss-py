# pyright: strict
"""ChainCache: verified provenance chains keyed by the emitter's user public
key, serving the receiving side of message-token chain negotiation. An emitter
sends chainless message tokens; the receiver caches the chain from the one
retransmit that carried it, and every later message verifies against the cached
copy.

Store only chains that survived a full ``verify_message``, so the cache never
holds material an attacker could plant. Used by the httpsig/grpcsig transports.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Protocol, runtime_checkable

# Bounds MemoryChainCache; when full, the least-recently-used entry is evicted
# (the emitter just re-negotiates its chain). Eviction is process-local and
# never observable on the wire, so the policy is a free hit-rate choice: LRU
# keeps actively-sending emitters warm and sheds idle ones.
_MEMORY_CHAIN_CACHE_CAP = 1024


@runtime_checkable
class ChainCache(Protocol):
    """Stores ``(account_token, user_token)`` chains by emitter user public key.
    Implementations must be safe for concurrent use."""

    def get(self, user_pub_key: str) -> tuple[str, str] | None: ...

    def put(self, user_pub_key: str, account_token: str, user_token: str) -> None: ...

    def delete(self, user_pub_key: str) -> None: ...


class MemoryChainCache:
    """A process-local :class:`ChainCache` with LRU eviction, bounded at
    :data:`_MEMORY_CHAIN_CACHE_CAP` entries. Both a hit (``get``) and a store
    (``put``) count as a use, so the entries evicted under pressure are the ones
    no emitter has touched in longest. For fewer warmup round-trips across
    multiple receiver instances, back the protocol with shared storage."""

    def __init__(self):
        # Ordered most- to least-recently-used: the front is the eviction
        # candidate, the back the freshest.
        self._entries: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, user_pub_key: str) -> tuple[str, str] | None:
        with self._lock:
            entry = self._entries.get(user_pub_key)
            if entry is not None:
                self._entries.move_to_end(user_pub_key)  # mark as recently used
            return entry

    def put(self, user_pub_key: str, account_token: str, user_token: str) -> None:
        with self._lock:
            if user_pub_key in self._entries:
                self._entries.move_to_end(user_pub_key)
            elif len(self._entries) >= _MEMORY_CHAIN_CACHE_CAP:
                self._entries.popitem(last=False)  # evict the least-recently-used
            self._entries[user_pub_key] = (account_token, user_token)

    def delete(self, user_pub_key: str) -> None:
        with self._lock:
            self._entries.pop(user_pub_key, None)
