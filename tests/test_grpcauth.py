from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import grpc
import pytest
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from valiss import creds, grpcauth, nkeys, token

TTL = timedelta(hours=1)
CHECK = "/grpc.health.v1.Health/Check"
WATCH = "/grpc.health.v1.Health/Watch"


class _TenantCapture(grpc.ServerInterceptor):
    """Records grpcauth.current_tenant() as seen from inside the handler."""

    def __init__(self):
        self.claims = []

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None or handler.request_streaming or handler.response_streaming:
            return handler
        inner = handler.unary_unary

        def behavior(request, context):
            self.claims.append(grpcauth.current_tenant())
            return inner(request, context)

        return grpc.unary_unary_rpc_method_handler(
            behavior,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


@pytest.fixture
def env():
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    tok = token.issue(
        operator,
        "acme",
        account.public_key,
        [grpcauth.scope_for_method(CHECK), grpcauth.scope_for_method(WATCH)],
        TTL,
    )
    issued = token.verify(tok, operator.public_key)

    capture = _TenantCapture()
    auth = grpcauth.Authenticator(
        token.Verifier(operator.public_key, token.StaticAllowlist(issued.id)),
        method_scope=True,
    )
    server = grpc.server(
        thread_pool=ThreadPoolExecutor(max_workers=4), interceptors=[auth, capture]
    )
    health_pb2_grpc.add_HealthServicer_to_server(health.HealthServicer(), server)
    port = server.add_secure_port("127.0.0.1:0", grpc.local_server_credentials())
    server.start()
    yield {
        "port": port,
        "token": tok,
        "account": account,
        "capture": capture,
    }
    server.stop(grace=None)


def _channel(port, bundle=None):
    if bundle is None:
        return grpc.secure_channel(f"127.0.0.1:{port}", grpc.local_channel_credentials())
    channel_creds = grpc.composite_channel_credentials(
        grpc.local_channel_credentials(), grpcauth.call_credentials(bundle)
    )
    return grpc.secure_channel(f"127.0.0.1:{port}", channel_creds)


def test_account_call(env):
    with _channel(env["port"], creds.Bundle(token=env["token"], seed=env["account"].seed)) as ch:
        resp = health_pb2_grpc.HealthStub(ch).Check(health_pb2.HealthCheckRequest())
    assert resp.status == health_pb2.HealthCheckResponse.SERVING
    claims = env["capture"].claims[-1]
    assert claims is not None
    assert claims.tenant_id == "acme"
    assert claims.user_id == ""


def test_user_chain_and_scope_denial(env):
    user = nkeys.create_user()
    user_tok = token.issue_user(
        env["account"], "alice", user.public_key, [grpcauth.scope_for_method(CHECK)], TTL
    )
    bundle = creds.Bundle(token=env["token"], user_token=user_tok, seed=user.seed)
    with _channel(env["port"], bundle) as ch:
        stub = health_pb2_grpc.HealthStub(ch)
        resp = stub.Check(health_pb2.HealthCheckRequest())
        assert resp.status == health_pb2.HealthCheckResponse.SERVING
        claims = env["capture"].claims[-1]
        assert claims.tenant_id == "acme"
        assert claims.user_id == "alice"

        # Watch is delegated to the account, not to alice.
        with pytest.raises(grpc.RpcError) as excinfo:
            next(stub.Watch(health_pb2.HealthCheckRequest()))
        assert excinfo.value.code() == grpc.StatusCode.PERMISSION_DENIED


def test_missing_credential(env):
    with _channel(env["port"]) as ch:
        with pytest.raises(grpc.RpcError) as excinfo:
            health_pb2_grpc.HealthStub(ch).Check(health_pb2.HealthCheckRequest())
    assert excinfo.value.code() == grpc.StatusCode.UNAUTHENTICATED
    assert "missing tenant credential" in excinfo.value.details()


def test_wrong_signer_rejected(env):
    imposter = nkeys.create_account()
    with _channel(env["port"], creds.Bundle(token=env["token"], seed=imposter.seed)) as ch:
        with pytest.raises(grpc.RpcError) as excinfo:
            health_pb2_grpc.HealthStub(ch).Check(health_pb2.HealthCheckRequest())
    assert excinfo.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_bearer_bundle_without_bearer_scope_rejected(env):
    with _channel(env["port"], creds.Bundle(token=env["token"])) as ch:
        with pytest.raises(grpc.RpcError) as excinfo:
            health_pb2_grpc.HealthStub(ch).Check(health_pb2.HealthCheckRequest())
    assert excinfo.value.code() == grpc.StatusCode.UNAUTHENTICATED
    assert "bearer" in excinfo.value.details()
