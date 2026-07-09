"""gRPC wiring for the tenant authentication scheme: client call credentials
that attach the per-request credential, and a server interceptor that
verifies it. Handlers read the authenticated tenant with current_tenant().

Requires the ``grpc`` extra (grpcio).
"""

from __future__ import annotations

import contextvars
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any

import grpc

from . import creds, token
from .errors import ValissError


def scope_for_method(full_method: str) -> str:
    """Per-call scope a tenant must hold under method-scope enforcement:
    ``call:`` joined with the gRPC full method, e.g.
    ``call:/example.v1.WidgetService/CreateWidget``."""
    return "call:" + full_method


class _CredentialsPlugin(grpc.AuthMetadataPlugin):
    """Attaches the credential bundle's tokens and, when the bundle holds a
    seed, a fresh per-call signature."""

    def __init__(self, bundle: creds.Bundle, now: Callable[[], datetime] | None):
        self._token = bundle.token
        self._user_token = bundle.user_token
        self._signer = bundle.signer()
        self._now = now

    def __call__(
        self,
        context: grpc.AuthMetadataContext,
        callback: grpc.AuthMetadataPluginCallback,
    ) -> None:
        try:
            md = [(token.HEADER_TOKEN, self._token)]
            if self._user_token:
                md.append((token.HEADER_USER_TOKEN, self._user_token))
            if self._signer is not None:
                ts = self._now() if self._now is not None else datetime.now().astimezone()
                timestamp, signature = token.sign_request(self._signer, ts)
                md.append((token.HEADER_TIMESTAMP, timestamp))
                md.append((token.HEADER_SIGNATURE, signature))
        except ValissError as exc:
            callback((), exc)
            return
        callback(tuple(md), None)


def call_credentials(
    bundle: creds.Bundle, *, now: Callable[[], datetime] | None = None
) -> grpc.CallCredentials:
    """Client call credentials from a creds bundle: the tenant token, the
    optional user token, and per-call signatures from the seed (absent for
    bearer bundles).

    gRPC sends call credentials only over secure channels; for local
    plaintext-equivalent transports compose with
    ``grpc.local_channel_credentials()``:

        channel_creds = grpc.composite_channel_credentials(
            grpc.ssl_channel_credentials(), call_credentials(bundle))
        channel = grpc.secure_channel(addr, channel_creds)
    """
    bundle.signer()  # fail fast on a malformed seed
    return grpc.metadata_call_credentials(_CredentialsPlugin(bundle, now), name="valiss")


_current_tenant: contextvars.ContextVar[token.Claims | None] = contextvars.ContextVar(
    "valiss_tenant", default=None
)


def current_tenant() -> token.Claims | None:
    """Authenticated claims of the request being handled; the Python
    counterpart of Go's token.TenantFromContext. Set by Authenticator for
    the duration of each handler call."""
    return _current_tenant.get()


class Authenticator(grpc.ServerInterceptor):
    """Server interceptor that verifies the per-request tenant credential
    and, optionally, per-method authorization.

    With method_scope=True the tenant must hold scope_for_method(method) for
    every call; without the scope the request is denied (PERMISSION_DENIED).
    scope_mapper substitutes a custom per-method scope.
    """

    def __init__(
        self,
        verifier: token.Verifier,
        *,
        method_scope: bool = False,
        scope_mapper: Callable[[str], str] | None = None,
    ):
        self._verifier = verifier
        if scope_mapper is not None:
            self._scope_for_method = scope_mapper
        elif method_scope:
            self._scope_for_method = scope_for_method
        else:
            self._scope_for_method = None

    def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler | None],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler | None:
        handler = continuation(handler_call_details)
        if handler is None:
            return None
        md = _first_values(handler_call_details.invocation_metadata)
        cred = token.Credential(
            token=md.get(token.HEADER_TOKEN, ""),
            user_token=md.get(token.HEADER_USER_TOKEN, ""),
            timestamp=md.get(token.HEADER_TIMESTAMP, ""),
            signature=md.get(token.HEADER_SIGNATURE, ""),
        )
        if not cred.token:
            return _aborting(handler, grpc.StatusCode.UNAUTHENTICATED, "missing tenant credential")
        try:
            claims = self._verifier.verify_credential(cred)
        except ValissError as exc:
            return _aborting(handler, grpc.StatusCode.UNAUTHENTICATED, str(exc))
        if self._scope_for_method is not None:
            scope = self._scope_for_method(handler_call_details.method)
            if not claims.authorizes(scope):
                return _aborting(
                    handler, grpc.StatusCode.PERMISSION_DENIED, f'tenant lacks scope "{scope}"'
                )
        return _with_tenant(handler, claims)


def _first_values(metadata: Sequence[tuple[str, str]] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in metadata or ():
        out.setdefault(key, value if isinstance(value, str) else "")
    return out


def _rebuild(handler: grpc.RpcMethodHandler, behavior: Any) -> grpc.RpcMethodHandler:
    factories = {
        (False, False): grpc.unary_unary_rpc_method_handler,
        (False, True): grpc.unary_stream_rpc_method_handler,
        (True, False): grpc.stream_unary_rpc_method_handler,
        (True, True): grpc.stream_stream_rpc_method_handler,
    }
    factory = factories[(handler.request_streaming, handler.response_streaming)]
    return factory(
        behavior,
        request_deserializer=handler.request_deserializer,
        response_serializer=handler.response_serializer,
    )


def _behavior(handler: grpc.RpcMethodHandler) -> Any:
    if handler.request_streaming and handler.response_streaming:
        return handler.stream_stream
    if handler.request_streaming:
        return handler.stream_unary
    if handler.response_streaming:
        return handler.unary_stream
    return handler.unary_unary


def _with_tenant(handler: grpc.RpcMethodHandler, claims: token.Claims) -> grpc.RpcMethodHandler:
    inner = _behavior(handler)
    if handler.response_streaming:

        def behavior(request_or_iterator: Any, context: grpc.ServicerContext) -> Any:
            reset = _current_tenant.set(claims)
            try:
                yield from inner(request_or_iterator, context)
            finally:
                _current_tenant.reset(reset)

    else:

        def behavior(request_or_iterator: Any, context: grpc.ServicerContext) -> Any:
            reset = _current_tenant.set(claims)
            try:
                return inner(request_or_iterator, context)
            finally:
                _current_tenant.reset(reset)

    return _rebuild(handler, behavior)


def _aborting(
    handler: grpc.RpcMethodHandler, code: grpc.StatusCode, details: str
) -> grpc.RpcMethodHandler:
    if handler.response_streaming:

        def behavior(request_or_iterator: Any, context: grpc.ServicerContext) -> Any:
            context.abort(code, details)
            yield  # unreachable; makes the behavior a generator

    else:

        def behavior(request_or_iterator: Any, context: grpc.ServicerContext) -> Any:
            context.abort(code, details)

    return _rebuild(handler, behavior)
