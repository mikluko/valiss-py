"""gRPC transport for the valiss scheme: client call credentials, the ``grpc``
extension claim, and a server interceptor that verifies the per-request
credential and enforces the extension.

Client:

    from valiss import creds, grpcauth
    c = creds.load("alice.creds")
    channel_creds = grpc.composite_channel_credentials(
        grpc.ssl_channel_credentials(), grpcauth.call_credentials(c))
    channel = grpc.secure_channel(addr, channel_creds)

Server:

    from valiss import Verifier, grpcauth
    server = grpc.server(
        executor, interceptors=[grpcauth.Authenticator(Verifier(op_pub, allowlist))])
    # in a servicer method:
    identity = grpcauth.identity_from_context()

Requires the ``grpc`` extra (grpcio). The ``Ext`` claim and ``method_context``
are pure and also importable from ``valiss.grpcauth.extension`` without grpcio.
"""

from ._client import call_credentials
from .extension import Ext, authorize_ext, method_context
from .interceptor import Authenticator, identity_from_context

__all__ = [
    "Authenticator",
    "Ext",
    "authorize_ext",
    "call_credentials",
    "identity_from_context",
    "method_context",
]
