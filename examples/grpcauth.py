"""Full tenant-auth wiring for gRPC: an operator issues a scoped account
token, the server installs the auth interceptor, and the client attaches the
credential to every call. Then the user level: the account delegates a
narrower scope to an end user, who calls with the token chain. Runs
self-contained over a localhost listener.

    uv run --group dev examples/grpcauth.py
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from valiss import creds, grpcauth, nkeys, token


def main() -> None:
    # Operator side: mint the trust anchor, a tenant account key, and a
    # scoped account token. In production the valiss CLI does this and hands
    # the client a creds bundle (see valiss.creds).
    operator = nkeys.create_operator()
    account = nkeys.create_account()

    check_scope = grpcauth.scope_for_method("/grpc.health.v1.Health/Check")
    watch_scope = grpcauth.scope_for_method("/grpc.health.v1.Health/Watch")
    tok = token.issue(
        operator, "acme", account.public_key, [check_scope, watch_scope], timedelta(hours=1)
    )
    claims = token.verify(tok, operator.public_key)

    # Server side: the operator public key and the allowlist are all the
    # server needs; it never sees any seeds.
    auth = grpcauth.Authenticator(
        token.Verifier(operator.public_key, token.StaticAllowlist(claims.id)),
        method_scope=True,
    )
    server = grpc.server(
        thread_pool=ThreadPoolExecutor(max_workers=4),
        interceptors=[auth, _TenantLogger()],
    )
    health_pb2_grpc.add_HealthServicer_to_server(health.HealthServicer(), server)
    port = server.add_secure_port("127.0.0.1:0", grpc.local_server_credentials())
    server.start()

    try:
        # Client side, account level: call credentials sign every call with
        # the account seed. local_channel_credentials only because the demo
        # runs over localhost without TLS.
        channel = _dial(port, creds.Bundle(token=tok, seed=account.seed))
        stub = health_pb2_grpc.HealthStub(channel)
        resp = stub.Check(health_pb2.HealthCheckRequest())
        print("account call allowed as expected, health status:", resp.status)

        # User level: the account delegates only the Check method to alice.
        # Her credential carries the token chain and her own fresh key.
        user = nkeys.create_user()
        user_tok = token.issue_user(
            account, "alice", user.public_key, [check_scope], timedelta(hours=1)
        )
        user_channel = _dial(
            port, creds.Bundle(token=tok, user_token=user_tok, seed=user.seed)
        )
        user_stub = health_pb2_grpc.HealthStub(user_channel)
        resp = user_stub.Check(health_pb2.HealthCheckRequest())
        print("user call within delegated scope allowed, health status:", resp.status)

        # A call outside the user's delegated scope is denied, although the
        # account itself holds it.
        try:
            next(user_stub.Watch(health_pb2.HealthCheckRequest()))
        except grpc.RpcError as err:
            assert err.code() == grpc.StatusCode.PERMISSION_DENIED, err
            print(
                f"out-of-scope user call denied as expected: {err.code().name} ({err.details()})"
            )
        else:
            raise AssertionError("expected PermissionDenied for the out-of-scope user call")

        user_channel.close()
        channel.close()
    finally:
        server.stop(grace=None)


def _dial(port: int, bundle: creds.Bundle) -> grpc.Channel:
    channel_creds = grpc.composite_channel_credentials(
        grpc.local_channel_credentials(), grpcauth.call_credentials(bundle)
    )
    return grpc.secure_channel(f"127.0.0.1:{port}", channel_creds)


class _TenantLogger(grpc.ServerInterceptor):
    """Shows how handler-side code reads the authenticated identity for
    data segmentation: grpcauth.current_tenant() inside the handler."""

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None or handler.request_streaming or handler.response_streaming:
            return handler
        inner = handler.unary_unary

        def behavior(request, context):
            claims = grpcauth.current_tenant()
            if claims is not None:
                who = f'tenant "{claims.tenant_id}"'
                if claims.user_id:
                    who += f' user "{claims.user_id}"'
                print(f"server: {who} calls {handler_call_details.method}")
            return inner(request, context)

        return grpc.unary_unary_rpc_method_handler(
            behavior,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


if __name__ == "__main__":
    main()
