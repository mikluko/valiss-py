# pyright: strict
"""Server-side allowlist: which issued account tokens (by ``jti``) are still
accepted. Only tokens the issuer explicitly deposited server-side pass, so a
token can be revoked by removing its id even before it expires — the allowlist
is the scheme's revocation mechanism.

Membership is tested with ``in`` (``account.id in allowlist``). File-compatible
with the Go ``valiss`` allowlist file (newline-delimited ids, ``#`` comments).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

from .errors import ValissError


@runtime_checkable
class Allowlist(Protocol):
    """Decides whether an issued token (by ``jti``) is still accepted. Tested
    with the ``in`` operator, so any container of ids — a ``set``, a DB-backed
    wrapper — satisfies it structurally."""

    def __contains__(self, jti: str) -> bool: ...


class StaticAllowlist:
    """In-memory set of accepted token ids. Set-like: build it from ids,
    ``add``/``discard`` individually, ``replace`` the whole set (e.g. after
    reloading a file), iterate, and take ``len``. Concurrent reads alongside an
    occasional ``replace``/``add`` are safe under CPython's atomic set ops."""

    def __init__(self, *jtis: str):
        self._ids: set[str] = set(jtis)

    def __contains__(self, jti: str) -> bool:
        return jti in self._ids

    def add(self, jti: str) -> None:
        self._ids.add(jti)

    def discard(self, jti: str) -> None:
        self._ids.discard(jti)

    def replace(self, jtis: Iterable[str]) -> None:
        """Swap in a new accepted set atomically."""
        self._ids = set(jtis)

    def __iter__(self) -> Iterator[str]:
        return iter(self._ids)

    def __len__(self) -> int:
        return len(self._ids)

    @classmethod
    def from_file(cls, path: str | Path) -> StaticAllowlist:
        """Read a newline-delimited allowlist file of token ids. Blank lines and
        lines beginning with ``#`` are ignored."""
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ValissError(f"valiss: open allowlist: {exc}") from exc
        ids = [
            line
            for line in (raw_line.strip() for raw_line in raw.splitlines())
            if line and not line.startswith("#")
        ]
        return cls(*ids)


class _AllowAll:
    """Accepts every token id; for local development where no allowlist is
    configured. Signature and expiry still gate access."""

    def __contains__(self, jti: str) -> bool:
        return True

    def __repr__(self) -> str:
        return "valiss.ALLOW_ALL"


# Development-only allowlist that accepts everything (the Go AllowAll).
ALLOW_ALL: Allowlist = _AllowAll()
