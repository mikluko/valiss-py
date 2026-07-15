# pyright: strict
"""Keyring: the set of trusted operators a multi-producer consumer verifies
against. Every entry is a full self-signed operator token — never a bare public
key — so each trust domain carries a name, an epoch, and a validity window, and
per-domain policy is enforced on every verification.

Entries are selected by issuer, not by trial: an incoming chain names its
operator (the account token's issuer) and its epoch, and verification runs
against exactly the entry registered under that ``(key, epoch)`` pair. One
operator key may hold entries at several epochs — a rotation grace period. A
keyring is immutable after construction and safe for concurrent use.
"""

from __future__ import annotations

from collections.abc import Iterator

from . import token
from .errors import ValissError


class Keyring:
    """A set of trusted operators built from their self-signed operator tokens.

    Identical tokens (same ``jti``) collapse into one entry. Construction fails
    on a different token for an already-occupied ``(operator key, epoch)`` pair,
    two operator keys sharing a name, or one operator key naming itself
    differently across entries. Unnamed operators are represented by their
    public key. Look entries up with :meth:`get` or ``keyring[(key, epoch)]``.
    """

    def __init__(self, *operator_tokens: str):
        entries: dict[tuple[str, int], token.OperatorClaims] = {}
        names: dict[str, str] = {}
        jtis: set[str] = set()
        for index, tok in enumerate(operator_tokens):
            try:
                claims = token.verify_operator(tok, token.issuer_of(tok))
            except ValissError as exc:
                raise ValissError(
                    f"valiss: keyring: operator token {index}: {exc}", reason=exc.reason
                ) from exc
            if claims.id in jtis:
                continue
            key = (claims.subject, claims.epoch)
            if key in entries:
                raise ValissError(
                    f"valiss: keyring: duplicate entry for operator {claims.subject} "
                    f"epoch {claims.epoch}"
                )
            owner = names.get(claims.name)
            if owner is not None and owner != claims.subject:
                raise ValissError(
                    f"valiss: keyring: operator name {claims.name!r} already names a "
                    "different operator"
                )
            for (existing_key, _epoch), existing in entries.items():
                if existing_key == claims.subject and existing.name != claims.name:
                    raise ValissError(
                        f"valiss: keyring: operator {claims.subject} entries disagree on "
                        f"name ({existing.name!r} vs {claims.name!r})"
                    )
            entries[key] = claims
            names[claims.name] = claims.subject
            jtis.add(claims.id)
        if not entries:
            raise ValissError("valiss: keyring: no operator tokens")
        self._entries = entries

    def get(self, operator_pub_key: str, epoch: int) -> token.OperatorClaims | None:
        """The operator entry registered for a key at an epoch, or None."""
        return self._entries.get((operator_pub_key, epoch))

    def __getitem__(self, key: tuple[str, int]) -> token.OperatorClaims:
        return self._entries[key]

    def __iter__(self) -> Iterator[token.OperatorClaims]:
        return iter(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)
