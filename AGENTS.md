# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

valiss-py is the Python port of [valiss](https://github.com/mikluko/valiss)
(expected as a sibling checkout at `../valiss`): tenant authentication for
gRPC and HTTP services rooted in Ed25519 nkeys. It must stay wire-compatible
with the Go implementation — creds files, tokens, request signatures, and
header names interchange freely. The Go repository's AGENTS.md describes the
scheme; this port mirrors its `pkg/` layout module for module.

## Commands

```sh
uv sync --all-extras            # set up the venv (dev group installs grpc/httpx)
uv run pytest                   # full suite, including Go interop
uv run pytest tests/test_token.py -k verifier   # single file / match
uv run examples/httpauth.py     # end-to-end demo (also examples/grpcauth.py)
```

The interop tests (`tests/test_interop.py`) drive `go run` in
`tests/interop/`, which `replace`s the Go module to `../../../valiss`; they
skip when the Go toolchain or the sibling checkout is missing. Run them
after any change to token encoding, nkeys, creds format, or request signing.

## Architecture

Module map (Go package → Python module):

- `pkg/token` → `valiss.token` — issue/verify (account and user level),
  `sign_request`/`verify_request`, `Allowlist`, `Verifier`. Claims carry
  `tenant_id` and, on chain requests, `user_id`. `verify` deliberately does
  NOT check expiry or allowlist; `Verifier` layers those.
- `pkg/creds` → `valiss.creds` — bundle file, byte-compatible markers.
- nkeys (vendored subset) → `valiss.nkeys` — base32 + CRC16 encode/decode,
  operator/account/user key pairs over `cryptography` Ed25519.
- `pkg/grpcauth` → `valiss.grpcauth` — `call_credentials` (client),
  `Authenticator` server interceptor, `current_tenant()` (contextvar, the
  `TenantFromContext` counterpart).
- `pkg/httpauth` → `valiss.httpauth` — `credential_headers` /
  `extract_credential` (framework-neutral), `Auth` (httpx hook).

There is no CLI here; credential minting for production stays with the Go
`valiss` CLI. `token.issue`/`issue_user` exist for servers, tests, and
self-contained examples.

## Wire-compatibility invariants

Do not change without changing the Go side in lockstep:

- Headers: `valiss-tenant-token`, `valiss-user-token`,
  `valiss-tenant-timestamp`, `valiss-tenant-signature` (gRPC metadata keys
  and HTTP headers alike).
- Request signature: Ed25519 over the raw RFC3339Nano timestamp string,
  base64 (standard, padded). Verification binds the raw string as received;
  Python cannot re-render Go's nanosecond precision.
- Tokens: NATS-style JWT, header `{"typ":"JWT","alg":"ed25519-nkey"}`,
  base64url unpadded, custom claims `tenant_key` and `scopes` under `nats`,
  jti = base32 SHA-512/256 of the standard claims with jti empty.
- Creds file markers, including the asymmetric `-----BEGIN` / `------END`
  dashes.

## Conventions

- Error messages are prefixed `valiss:`; everything raises `ValissError`.
- Key levels are strict: operator signs account tokens, account signs user
  tokens, never the reverse; accounts always bind a key, only user tokens
  may be keyless `bearer` ones.
- Tests inject time via the `now=` parameters; prefer that over sleeping.
- grpcio and httpx are optional extras; `valiss.token`, `valiss.creds`, and
  `valiss.nkeys` must stay importable with only `cryptography` installed.
