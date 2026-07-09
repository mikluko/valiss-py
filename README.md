# valiss-py

Python port of [valiss](https://github.com/mikluko/valiss) (**VAL**idator-**ISS**uer):
tenant authentication for gRPC and HTTP services, modeled on NATS
operator/account/user credentials. Wire-compatible with the Go
implementation: creds files, tokens, and request signatures interchange
freely between the two.

- An **operator** holds an Ed25519 nkey; its public key is the trust anchor.
- The operator signs each **account** (tenant) a scoped, time-limited JWT
  that binds the account's own nkey public key. Issued token ids go in a
  server-side allowlist.
- An account may delegate: it signs **user** tokens with its account seed,
  granting end users a subset of its scopes. Servers verify the chain up to
  the pinned operator key; nothing else needs distribution.
- The client **signs every request** with its nkey over a timestamp. The
  server verifies the token (chain) against the operator key, the signature
  against the bound key within a skew window, and the account token id
  against the allowlist, then hands the tenant (and user) identity to the
  handler for data segmentation.

Credential bundles come from the valiss CLI (`valiss creds ACCOUNT[/USER]`);
see the Go repository for key generation and the `valiss.yaml` manifest.

## Install

```sh
uv add valiss              # core: creds parsing, tokens, request signing
uv add 'valiss[httpx]'     # + httpx auth hook
uv add 'valiss[grpc]'      # + gRPC call credentials and server interceptor
```

## Client (HTTP)

```python
import httpx
from valiss import creds, httpauth

bundle = creds.load("alice.creds")
client = httpx.Client(auth=httpauth.Auth(bundle))
client.get("https://api.example.com/v1/whoami")
```

Any other HTTP client works through `httpauth.credential_headers(bundle)`;
build a fresh header set per request.

## Client (gRPC)

```python
import grpc
from valiss import creds, grpcauth

bundle = creds.load("alice.creds")
channel_creds = grpc.composite_channel_credentials(
    grpc.ssl_channel_credentials(), grpcauth.call_credentials(bundle))
channel = grpc.secure_channel("api.example.com:443", channel_creds)
```

gRPC sends call credentials only over secure channels; for local plaintext
development compose with `grpc.local_channel_credentials()` instead.

## Server (HTTP)

```python
from valiss import httpauth, token

verifier = token.Verifier(operator_pub_key, token.StaticAllowlist(jti, ...))

# in a request handler, with any framework:
cred = httpauth.extract_credential(request.headers)
claims = verifier.verify_credential(cred)   # raises ValissError -> 401
claims.authorizes(httpauth.scope_for_path(request.path))  # False -> 403
claims.tenant_id                            # segments data; claims.user_id
```

## Server (gRPC)

```python
import grpc
from valiss import grpcauth, token

auth = grpcauth.Authenticator(
    token.Verifier(operator_pub_key, token.StaticAllowlist(jti, ...)),
    method_scope=True,
)
server = grpc.server(thread_pool, interceptors=[auth])
# in a handler:
claims = grpcauth.current_tenant()
```

## Examples

Runnable end-to-end demos, mirroring the Go `examples/`:

```sh
uv run examples/httpauth.py
uv run examples/grpcauth.py
```

## Layout

- `valiss.token` — token issue/verify (account and user level), request
  sign/verify, allowlist, the credential `Verifier`
- `valiss.creds` — client credential bundle file (tokens + seed)
- `valiss.nkeys` — minimal Ed25519 nkeys (operator/account/user)
- `valiss.grpcauth` — gRPC call credentials and server interceptor
- `valiss.httpauth` — HTTP header building/extraction and httpx auth hook

Tests include a cross-language interop suite (`tests/test_interop.py`) that
round-trips credentials against the Go library; it needs the Go toolchain
and a `../valiss` checkout, and skips otherwise.
