"""gRPC server interceptor for the valiss scheme.

:class:`Authenticator` is a ``grpc.ServerInterceptor`` that verifies the
per-request credential against a :class:`~valiss.verifier.Verifier` and enforces
the tokens' gRPC extension, fail-closed, across all four RPC cardinalities.
A failure aborts the RPC — ``UNAUTHENTICATED`` for an authentication failure,
``PERMISSION_DENIED`` for an extension denial — before the handler runs; on
success the verified :class:`~valiss.verifier.Identity` is exposed to the handler
via :func:`identity_from_context`.

    server = grpc.server(
        executor, interceptors=[Authenticator(Verifier(op_pub, allowlist))]
    )

    def GetWidget(self, request, context):
        identity = grpcauth.identity_from_context()  # the verified tenant

Requires the ``grpc`` extra (grpcio).
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator
from typing import Any, Callable

import grpc

from .. import token
from ..errors import ValissError
from ..verifier import Identity, Request, Verifier
from .extension import authorize_ext, method_context

# The verified identity for the RPC currently on this thread. The interceptor
# sets it around the handler; a handler reads it with identity_from_context().
# A ContextVar (not the grpc context, which cannot carry values) is the Python
# analog of Go's IdentityFromContext.
_IDENTITY: contextvars.ContextVar[Identity] = contextvars.ContextVar("valiss_identity")


def identity_from_context() -> Identity | None:
    """The verified identity of the RPC being handled on this thread, or
    ``None`` outside an authenticated handler. Call it from a servicer method
    running behind an :class:`Authenticator`."""
    return _IDENTITY.get(None)


def _incoming(metadata: Any) -> dict[str, str]:
    """First-wins view of the incoming metadata, mirroring Go's first()."""
    out: dict[str, str] = {}
    for key, value in metadata:
        if key not in out:
            out[key] = value
    return out


class Authenticator(grpc.ServerInterceptor):
    """Server interceptor that authenticates every RPC against the verifier and
    enforces the tokens' gRPC extensions, fail-closed: tokens without the
    extension are denied unless ``allow_missing_extension`` is set. Pass it in
    the ``interceptors=`` list of ``grpc.server(...)``."""

    def __init__(self, verifier: Verifier, *, allow_missing_extension: bool = False):
        self._verifier = verifier
        self._allow_missing = allow_missing_extension

    def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler | None],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler | None:
        handler = continuation(handler_call_details)
        if handler is None:
            return None
        full_method: str = handler_call_details.method  # type: ignore[attr-defined]
        return self._wrap(handler, full_method)

    def _authenticate(self, context: grpc.ServicerContext, full_method: str) -> Identity:
        """Verify the credential and authorize the method, returning the
        identity. Aborts the RPC (raising) on any failure."""
        md = _incoming(context.invocation_metadata())
        account_token = md.get(token.HEADER_ACCOUNT_TOKEN, "")
        user_token = md.get(token.HEADER_USER_TOKEN, "")
        nonce = md.get(token.HEADER_NONCE, "")
        if not account_token and not user_token:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "valiss: missing credentials")
        request = Request(
            account_token=account_token,
            user_token=user_token,
            timestamp=md.get(token.HEADER_TIMESTAMP, ""),
            signature=md.get(token.HEADER_SIGNATURE, ""),
            context=method_context(full_method, nonce),
            nonce=nonce,
        )
        try:
            identity = self._verifier.verify(request)
        except ValissError as exc:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, str(exc))
        try:
            authorize_ext(identity, full_method, allow_missing=self._allow_missing)
        except ValissError as exc:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, str(exc))
        return identity

    def _wrap(self, handler: grpc.RpcMethodHandler, full_method: str) -> grpc.RpcMethodHandler:
        """Rewrap the handler so it authenticates first and runs under the
        verified identity, preserving the RPC's cardinality and codecs. Unary
        responses reset the identity once the response is produced; streaming
        responses keep it set for the life of the response iterator by wrapping
        it in a generator (the identity must outlive each yielded message)."""
        authenticate = self._authenticate

        if not handler.response_streaming:

            def unary_response(behavior: Callable[..., Any]) -> Callable[..., Any]:
                def invoke(request_or_iterator: Any, context: grpc.ServicerContext) -> Any:
                    reset = _IDENTITY.set(authenticate(context, full_method))
                    try:
                        return behavior(request_or_iterator, context)
                    finally:
                        _IDENTITY.reset(reset)

                return invoke

            if handler.request_streaming:
                return grpc.stream_unary_rpc_method_handler(
                    unary_response(handler.stream_unary),
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )
            return grpc.unary_unary_rpc_method_handler(
                unary_response(handler.unary_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        def streaming_response(behavior: Callable[..., Any]) -> Callable[..., Iterator[Any]]:
            def invoke(request_or_iterator: Any, context: grpc.ServicerContext) -> Iterator[Any]:
                reset = _IDENTITY.set(authenticate(context, full_method))
                try:
                    yield from behavior(request_or_iterator, context)
                finally:
                    _IDENTITY.reset(reset)

            return invoke

        if handler.request_streaming:
            return grpc.stream_stream_rpc_method_handler(
                streaming_response(handler.stream_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return grpc.unary_stream_rpc_method_handler(
            streaming_response(handler.unary_stream),
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )
