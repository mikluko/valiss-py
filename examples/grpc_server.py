"""Server-side gRPC interceptor: authenticate every RPC at the transport.

The Authenticator verifies the per-call credential and enforces the grpc
extension before the servicer runs, aborting UNAUTHENTICATED / PERMISSION_DENIED
otherwise; the handler reads the verified tenant with
grpcauth.identity_from_context(). The matching client attaches its credential
with grpcauth.call_credentials.

Runs in-process over grpc's local credentials (call credentials ride only a
secure transport), with a generic echo handler so no .proto compilation is
needed.

    uv run --group dev examples/grpc_server.py
"""

from concurrent import futures
from datetime import timedelta

import grpc

from valiss import ALLOW_ALL, Verifier, creds, grpcauth, nkeys, token


class EchoHandler(grpc.GenericRpcHandler):
    """Answers any method, echoing the authenticated tenant back to the caller."""

    def service(self, handler_call_details):
        def handle(request, context):
            identity = grpcauth.identity_from_context()
            return f"{identity.account.name}/{identity.user.name}".encode()

        return grpc.unary_unary_rpc_method_handler(handle)


def main() -> None:
    # --- issuer setup: the user token is bound to a grpc extension the server
    # enforces; the account carries it too for a fully-bound chain. ---
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    user = nkeys.create_user()
    ext = [grpcauth.Ext(methods=["/example.v1.WidgetService/*"])]
    account_token = token.issue_account(
        operator, "acme", account.public_key, ttl=timedelta(hours=1), extensions=ext
    )
    user_token = token.issue_user(
        account, "alice", user.public_key, ttl=timedelta(minutes=15), extensions=ext
    )

    # --- server: the interceptor authenticates and authorizes; the handler
    # trusts identity_from_context(). ---
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        interceptors=[grpcauth.Authenticator(Verifier(operator.public_key, ALLOW_ALL))],
    )
    server.add_generic_rpc_handlers([EchoHandler()])
    port = server.add_secure_port(
        "localhost:0", grpc.local_server_credentials(grpc.LocalConnectionType.LOCAL_TCP)
    )
    server.start()

    # --- client: call_credentials attaches the tokens and a per-call signature
    # bound to the invoked method. ---
    client_creds = creds.Creds(
        account_token=account_token, user_token=user_token, seed=user.seed
    )
    channel_creds = grpc.composite_channel_credentials(
        grpc.local_channel_credentials(grpc.LocalConnectionType.LOCAL_TCP),
        grpcauth.call_credentials(client_creds),
    )
    with grpc.secure_channel(f"localhost:{port}", channel_creds) as channel:
        allowed = channel.unary_unary("/example.v1.WidgetService/CreateWidget")(b"")
        print(f"in-scope  CreateWidget -> {allowed.decode()}")

        # A method outside the extension is aborted PERMISSION_DENIED before the
        # servicer runs.
        try:
            channel.unary_unary("/example.v1.GadgetService/CreateGadget")(b"")
        except grpc.RpcError as exc:
            print(f"out-of-scope CreateGadget -> {exc.code().name}: {exc.details()}")

    server.stop(None)


if __name__ == "__main__":
    main()
