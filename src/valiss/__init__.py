"""valiss: tenant authentication for gRPC and HTTP clients and services,
wire-compatible with github.com/mikluko/valiss.

Client quick start:

    from valiss import creds, httpauth
    bundle = creds.load("alice.creds")
    client = httpx.Client(auth=httpauth.Auth(bundle))

    from valiss import grpcauth
    channel_creds = grpc.composite_channel_credentials(
        grpc.ssl_channel_credentials(), grpcauth.call_credentials(bundle))
    channel = grpc.secure_channel(addr, channel_creds)

Submodules mirror the Go package layout: token (issue/verify, request
signing, Verifier, allowlist), creds (bundle file), nkeys (Ed25519 nkeys),
httpauth and grpcauth (transport adapters). grpcauth requires the ``grpc``
extra; httpauth.Auth requires the ``httpx`` extra.
"""

from .errors import ValissError

__all__ = ["ValissError"]
