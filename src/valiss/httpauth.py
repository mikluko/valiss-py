"""HTTP client side of the tenant authentication scheme.

``credential_headers`` builds the per-request header set for any HTTP
client; ``Auth`` wraps it as an httpx auth hook. Server-side extraction is
``extract_credential``; pass the result to token.Verifier.verify_credential.

Requires the ``httpx`` extra only for the Auth class; ``credential_headers``
and ``extract_credential`` are dependency-free.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from datetime import datetime

from . import creds, token
from .errors import ValissError


def credential_headers(
    bundle: creds.Bundle, *, now: Callable[[], datetime] | None = None
) -> dict[str, str]:
    """Headers a client attaches to one request: the bundle's tokens and,
    when the bundle holds a seed, a fresh signature. Bundles without a seed
    are bearer credentials: the server accepts them only when the effective
    token grants token.SCOPE_BEARER.

    Signatures are single-use by freshness: build a new header set per
    request.
    """
    headers = {token.HEADER_TOKEN: bundle.token}
    if bundle.user_token:
        headers[token.HEADER_USER_TOKEN] = bundle.user_token
    signer = bundle.signer()
    if signer is not None:
        ts = now() if now is not None else datetime.now().astimezone()
        timestamp, signature = token.sign_request(signer, ts)
        headers[token.HEADER_TIMESTAMP] = timestamp
        headers[token.HEADER_SIGNATURE] = signature
    return headers


def extract_credential(headers: Mapping[str, str]) -> token.Credential:
    """Build the per-request credential from a case-insensitive-get header
    mapping (http.server, WSGI-adapted, starlette, etc.)."""
    return token.Credential(
        token=headers.get(token.HEADER_TOKEN, ""),
        user_token=headers.get(token.HEADER_USER_TOKEN, ""),
        timestamp=headers.get(token.HEADER_TIMESTAMP, ""),
        signature=headers.get(token.HEADER_SIGNATURE, ""),
    )


def scope_for_path(path: str) -> str:
    """Per-call scope a tenant must hold under path-scope enforcement:
    ``call:`` joined with the request path, e.g. ``call:/v1/widgets``."""
    return "call:" + path


try:
    import httpx
except ImportError:  # httpx is an optional extra; Auth needs it, the rest does not.
    httpx = None  # type: ignore[assignment]


if httpx is not None:

    class Auth(httpx.Auth):
        """httpx auth hook that attaches the credential bundle's tokens
        and, when the bundle holds a seed, a fresh per-request signature.

        Pass as ``httpx.Client(auth=Auth(bundle))``.
        """

        def __init__(self, bundle: creds.Bundle, *, now: Callable[[], datetime] | None = None):
            bundle.signer()  # fail fast on a malformed seed
            self._bundle = bundle
            self._now = now

        def auth_flow(self, request: httpx.Request) -> Iterator[httpx.Request]:
            request.headers.update(credential_headers(self._bundle, now=self._now))
            yield request

else:

    class Auth:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object):
            raise ValissError(
                "valiss: httpauth.Auth requires httpx; install the valiss[httpx] extra"
            )
