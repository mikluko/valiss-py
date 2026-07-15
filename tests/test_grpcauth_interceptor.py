"""Port of valiss-go contrib/grpcauth/grpcauth_test.go: the server interceptor.

Runs a real in-process grpc server behind the Authenticator with a generic echo
handler, so the whole path is exercised — metadata extraction, verification,
fail-closed extension enforcement, abort→status-code mapping, and the identity
handoff a servicer reads with identity_from_context(). A streaming case proves
the identity survives the whole response iterator (the generator wrapper). Each
negative case asserts the grpc StatusCode the failure maps to. Time is injected
via clock=/at=, never slept.
"""

from __future__ import annotations

from concurrent import futures
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import grpc
import pytest

from valiss import nkeys, token
from valiss.allowlist import ALLOW_ALL, StaticAllowlist
from valiss.grpcauth import Authenticator, Ext, identity_from_context, method_context
from valiss.replay import MemoryReplayCache
from valiss.verifier import Verifier

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


def clock(at=NOW):
    return lambda: at


# --- in-process server harness -------------------------------------------------


def _who() -> str:
    """The verified identity as the handler sees it via the ContextVar."""
    idn = identity_from_context()
    if idn is None:
        return ""
    return idn.account.name + (f"/{idn.user.name}" if idn.user is not None else "")


class _EchoHandler(grpc.GenericRpcHandler):
    """Answers any method, echoing the authenticated identity as raw bytes."""

    def __init__(self, streaming: bool):
        self._streaming = streaming

    def service(self, handler_call_details):
        if self._streaming:
            return grpc.unary_stream_rpc_method_handler(self._stream)
        return grpc.unary_unary_rpc_method_handler(self._unary)

    def _unary(self, request, context):
        return _who().encode()

    def _stream(self, request, context):
        # Two messages: the second proves the identity is still set late in the
        # response stream, i.e. the generator wrapper keeps it live.
        yield _who().encode()
        yield _who().encode()


@contextmanager
def serve(verifier, *, allow_missing=False, streaming=False):
    auth = Authenticator(verifier, allow_missing_extension=allow_missing)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4), interceptors=[auth])
    server.add_generic_rpc_handlers([_EchoHandler(streaming)])
    port = server.add_insecure_port("localhost:0")
    server.start()
    try:
        yield f"localhost:{port}"
    finally:
        server.stop(None)


def signed_md(kp, method, *, account_token="", user_token="", nonce="", at=NOW):
    md: list[tuple[str, str]] = []
    if account_token:
        md.append((token.HEADER_ACCOUNT_TOKEN, account_token))
    if user_token:
        md.append((token.HEADER_USER_TOKEN, user_token))
    if nonce:
        md.append((token.HEADER_NONCE, nonce))
    timestamp, signature = token.sign_request(kp, method_context(method, nonce), at)
    md.append((token.HEADER_TIMESTAMP, timestamp))
    md.append((token.HEADER_SIGNATURE, signature))
    return md


def token_only_md(*, account_token="", user_token=""):
    md: list[tuple[str, str]] = []
    if account_token:
        md.append((token.HEADER_ACCOUNT_TOKEN, account_token))
    if user_token:
        md.append((token.HEADER_USER_TOKEN, user_token))
    return md


def unary(target, method, metadata):
    """Invoke method; return (StatusCode.OK, body) or (code, details)."""
    with grpc.insecure_channel(target) as channel:
        try:
            body = channel.unary_unary(method)(b"", metadata=metadata)
            return grpc.StatusCode.OK, body.decode()
        except grpc.RpcError as exc:
            return exc.code(), exc.details()


def stream(target, method, metadata):
    with grpc.insecure_channel(target) as channel:
        try:
            return grpc.StatusCode.OK, [m.decode() for m in channel.unary_stream(method)(b"", metadata=metadata)]
        except grpc.RpcError as exc:
            return exc.code(), exc.details()


@pytest.fixture
def operator():
    return nkeys.create_operator()


@pytest.fixture
def account():
    return nkeys.create_account()


@pytest.fixture
def user():
    return nkeys.create_user()


# --- TestExtEnforcement --------------------------------------------------------

SVC = "/example.v1.WidgetService"


def test_method_inside_extension_allowed(operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=[f"{SVC}/*"])]
    )
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock())) as target:
        code, body = unary(target, f"{SVC}/CreateWidget", signed_md(account, f"{SVC}/CreateWidget", account_token=tok))
    assert code == grpc.StatusCode.OK
    assert body == "acme"


def test_method_outside_extension_denied(operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=[f"{SVC}/*"])]
    )
    method = "/example.v1.GadgetService/CreateGadget"
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock())) as target:
        code, _ = unary(target, method, signed_md(account, method, account_token=tok))
    assert code == grpc.StatusCode.PERMISSION_DENIED


def test_missing_extension_denied_by_default(operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock())) as target:
        code, details = unary(target, "/anything/Method", signed_md(account, "/anything/Method", account_token=tok))
    assert code == grpc.StatusCode.PERMISSION_DENIED
    assert "no grpc extension" in details


def test_missing_extension_passes_with_allow_missing(operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True) as target:
        code, _ = unary(target, "/anything/Method", signed_md(account, "/anything/Method", account_token=tok))
    assert code == grpc.StatusCode.OK


def test_empty_methods_grants_nothing(operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext()])
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock())) as target:
        code, _ = unary(target, "/anything/Method", signed_md(account, "/anything/Method", account_token=tok))
    assert code == grpc.StatusCode.PERMISSION_DENIED


def test_wildcard_grants_everything(operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=["*"])]
    )
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock())) as target:
        code, _ = unary(target, "/anything/Method", signed_md(account, "/anything/Method", account_token=tok))
    assert code == grpc.StatusCode.OK


# --- TestAuthenticate ----------------------------------------------------------


def test_authenticated_request_injects_identity(operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    verifier = Verifier(operator.public_key, ALLOW_ALL, clock=clock())
    with serve(verifier, allow_missing=True) as target:
        code, body = unary(target, "/svc/M", signed_md(account, "/svc/M", account_token=tok))
    assert code == grpc.StatusCode.OK
    assert body == "acme"  # account-level: no user segment


def test_missing_credential(operator):
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True) as target:
        code, _ = unary(target, "/svc/M", [])
    assert code == grpc.StatusCode.UNAUTHENTICATED


def test_token_not_in_allowlist(operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    verifier = Verifier(operator.public_key, StaticAllowlist("other"), clock=clock())
    with serve(verifier, allow_missing=True) as target:
        code, details = unary(target, "/svc/M", signed_md(account, "/svc/M", account_token=tok))
    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "not recognized" in details


def test_stale_request_signature(operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True) as target:
        code, _ = unary(target, "/svc/M", signed_md(account, "/svc/M", account_token=tok, at=NOW - HOUR))
    assert code == grpc.StatusCode.UNAUTHENTICATED


def test_signature_bound_to_other_method_rejected(operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True) as target:
        # Signed for /svc/Other but invoked as /svc/M.
        code, details = unary(target, "/svc/M", signed_md(account, "/svc/Other", account_token=tok))
    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "signature verification failed" in details


# --- TestBearerCredentials -----------------------------------------------------


def test_bearer_allows_token_only(operator, account, user):
    acct_tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    bearer = token.issue_user(account, "carol", user.public_key, bearer=True, ttl=HOUR, now=NOW)
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True) as target:
        code, body = unary(target, "/svc/M", token_only_md(account_token=acct_tok, user_token=bearer))
    assert code == grpc.StatusCode.OK
    assert body == "acme/carol"


def test_plain_token_denies_token_only(operator, account, user):
    acct_tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    plain = token.issue_user(account, "carol", user.public_key, ttl=HOUR, now=NOW)
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True) as target:
        code, details = unary(target, "/svc/M", token_only_md(account_token=acct_tok, user_token=plain))
    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "not a bearer token" in details


# --- TestUserChain -------------------------------------------------------------


def test_user_chain_delegated_identity(operator, account, user):
    acct_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=["/svc/*"])]
    )
    user_tok = token.issue_user(
        account, "alice", user.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=["/svc/M"])]
    )
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock())) as target:
        code, body = unary(
            target, "/svc/M", signed_md(user, "/svc/M", account_token=acct_tok, user_token=user_tok)
        )
    assert code == grpc.StatusCode.OK
    assert body == "acme/alice"


def test_user_chain_beyond_user_extension_denied(operator, account, user):
    acct_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=["/svc/*"])]
    )
    user_tok = token.issue_user(
        account, "alice", user.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=["/svc/M"])]
    )
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock())) as target:
        # /svc/Other is inside the account extension but outside the user's.
        code, _ = unary(
            target, "/svc/Other", signed_md(user, "/svc/Other", account_token=acct_tok, user_token=user_tok)
        )
    assert code == grpc.StatusCode.PERMISSION_DENIED


def test_account_extension_clamps_user(operator, account, user):
    acct_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=["/svc/*"])]
    )
    wide = token.issue_user(
        account, "mallory", user.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=["/other/*"])]
    )
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock())) as target:
        code, _ = unary(
            target, "/other/Method", signed_md(user, "/other/Method", account_token=acct_tok, user_token=wide)
        )
    assert code == grpc.StatusCode.PERMISSION_DENIED  # user cannot escape the account extension


# --- streaming + replay (new coverage the transport enables) -------------------


def test_streaming_response_keeps_identity(operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True, streaming=True) as target:
        code, messages = stream(target, "/svc/Feed", signed_md(account, "/svc/Feed", account_token=tok))
    assert code == grpc.StatusCode.OK
    assert messages == ["acme", "acme"]  # identity live for both yields


def test_streaming_denied_before_any_message(operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext()])
    with serve(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), streaming=True) as target:
        code, _ = stream(target, "/svc/Feed", signed_md(account, "/svc/Feed", account_token=tok))
    assert code == grpc.StatusCode.PERMISSION_DENIED


def test_nonce_replay_rejected(operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=["*"])]
    )
    verifier = Verifier(
        operator.public_key, ALLOW_ALL, clock=clock(), replay_cache=MemoryReplayCache(clock=clock())
    )
    md = signed_md(account, "/svc/M", account_token=tok, nonce=token.new_nonce())
    with serve(verifier) as target:
        first, _ = unary(target, "/svc/M", md)
        second, _ = unary(target, "/svc/M", md)
    assert first == grpc.StatusCode.OK
    assert second == grpc.StatusCode.UNAUTHENTICATED


def test_missing_nonce_rejected_by_cache(operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(methods=["*"])]
    )
    verifier = Verifier(
        operator.public_key, ALLOW_ALL, clock=clock(), replay_cache=MemoryReplayCache(clock=clock())
    )
    with serve(verifier) as target:
        code, details = unary(target, "/svc/M", signed_md(account, "/svc/M", account_token=tok))
    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "nonce required" in details
