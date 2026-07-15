# pyright: strict
"""The gRPC transport extension claim (``Ext``), its fail-closed authorization,
and the canonical method-context bytes shared by client and server.

Pure logic — no grpc dependency — so it is importable with only ``cryptography``.
The client credentials and the server interceptor build on it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Self

from .. import token
from ..errors import Reason, ValissError
from ..verifier import Identity


@dataclass
class Ext:
    """gRPC transport extension claim: binds a token to specific methods. Mint
    it with ``token.issue_*(..., extensions=[Ext(...)])``.

    Enforcement is fail-closed: every token in the chain must carry the
    extension (unless the interceptor allows missing ones), an empty methods
    list grants nothing, and allow-all is the explicit wildcard
    ``Ext(methods=["*"])``. Extensions on both chain levels are enforced (AND),
    so an account-level extension bounds all of the account's users on top of
    their own. Unlike ``httpauth.Ext`` there is a single dimension, so an empty
    ``Ext`` denies rather than leaving a dimension open.
    """

    # methods allowed, as gRPC full method names, e.g.
    # "/example.v1.WidgetService/CreateWidget". A trailing "*" is a prefix
    # wildcard: "/example.v1.WidgetService/*" covers the whole service and "*"
    # covers everything. Empty grants nothing.
    methods: list[str] = field(default_factory=list[str])

    def extension_name(self) -> str:
        return "grpc"

    def extension_payload(self) -> Mapping[str, Any]:
        return {"methods": self.methods} if self.methods else {}

    @classmethod
    def decode(cls, payload: Mapping[str, Any]) -> Self:
        # ext_of has already guaranteed payload is an object.
        return cls(methods=[str(m) for m in payload.get("methods") or ()])

    def authorizes(self, full_method: str) -> bool:
        """Whether the extension permits the full method. An empty methods list
        permits nothing; a trailing ``*`` is a prefix wildcard."""
        return token.covered(self.methods, full_method)


def method_context(full_method: str, nonce: str = "") -> bytes:
    """Canonical request-context bytes for a gRPC full method (e.g.
    ``/example.v1.WidgetService/CreateWidget``) and per-request nonce (empty when
    replay suppression is not in use). Binding the signature to the full method
    stops a captured signature from authorizing a different RPC; client and
    server reconstruct identical bytes."""
    return f"grpc\n{full_method}\n{nonce}".encode()


def authorize_ext(identity: Identity, full_method: str, *, allow_missing: bool = False) -> None:
    """Enforce the gRPC extensions a verified request's tokens carry (account,
    then user — AND, so an account extension clamps its users). Every token must
    carry the extension and permit the method; with ``allow_missing`` a token
    without the extension imposes no constraint. Raises :class:`ValissError` (the
    interceptor maps it to ``PERMISSION_DENIED``)."""
    exts = [identity.account.ext]
    if identity.user is not None:
        exts.append(identity.user.ext)
    for ext in exts:
        decoded = token.ext_of(ext, Ext)  # raises extension_invalid on a malformed payload
        if decoded is None:
            if allow_missing:
                continue
            raise ValissError(
                "valiss: token carries no grpc extension", reason=Reason.EXTENSION_INVALID
            )
        if not decoded.authorizes(full_method):
            raise ValissError(
                f"valiss: token does not permit {full_method}", reason=Reason.EXTENSION_INVALID
            )
