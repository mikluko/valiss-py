"""Core of the valiss tenant authentication scheme.

Wire-compatible Python port of github.com/mikluko/valiss/pkg/token:

- An operator holds an Ed25519 nkey; its public key is the trust anchor
  servers pin.
- The operator signs each account (tenant) a scoped, time-limited JWT that
  binds the account's own nkey public key. Issued token ids go in a
  server-side allowlist.
- An account may delegate: it signs user tokens with its account seed,
  granting end users a subset of its scopes.
- The client signs every request with its nkey over an RFC3339Nano
  timestamp; servers verify the token chain against the operator key, the
  signature against the bound key within a skew window, and the account
  token id against the allowlist.

Tokens are NATS-style JWTs (``ed25519-nkey`` algorithm) carrying the custom
claims ``tenant_key`` and ``scopes`` under the ``nats`` payload field.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from . import nkeys
from .errors import ValissError

# Header field names carrying the tenant credential on each request. Used as
# gRPC metadata keys and HTTP header names alike.
HEADER_TOKEN = "valiss-tenant-token"
HEADER_USER_TOKEN = "valiss-user-token"
HEADER_TIMESTAMP = "valiss-tenant-timestamp"
HEADER_SIGNATURE = "valiss-tenant-signature"

# Scope a token must carry for its holder to make bearer requests: the token
# alone, without the per-request signature. Bearer tokens are replayable
# until they expire or leave the allowlist, so grant this only to holders
# that cannot sign (no seed distribution) and pair it with TLS and short
# TTLs.
SCOPE_BEARER = "bearer"

# Bounds request-timestamp drift and token-expiry slack.
DEFAULT_SKEW = timedelta(minutes=2)

_SCOPES_CLAIM = "scopes"
_PUBKEY_CLAIM = "tenant_key"

_JWT_HEADER = '{"typ":"JWT","alg":"ed25519-nkey"}'
_JWT_ALGORITHMS = ("ed25519-nkey", "ed25519")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    pad = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + pad)
    except (binascii.Error, ValueError) as exc:
        raise ValissError(f"valiss: bad token encoding: {exc}") from exc


def _rfc3339nano(ts: datetime) -> str:
    """Render like Go's time.RFC3339Nano: fraction trimmed of trailing zeros."""
    ts = ts.astimezone(timezone.utc)
    out = ts.strftime("%Y-%m-%dT%H:%M:%S")
    frac = f"{ts.microsecond:06d}".rstrip("0")
    if frac:
        out += f".{frac}"
    return out + "Z"


@dataclass
class Claims:
    """Verified content of a tenant token."""

    # tenant_id identifies the tenant; it segments all stored data.
    tenant_id: str
    # pub_key is the nkey public key that must sign requests.
    pub_key: str
    # Scopes granted to the tenant.
    scopes: list[str] = field(default_factory=list)
    # id is the token's unique identifier (jti), the allowlist key.
    id: str = ""
    # issuer is the public key that signed the token.
    issuer: str = ""
    # expires_at is the token expiry; None when the token never expires.
    expires_at: datetime | None = None
    # user_id identifies the end user on chain-verified requests, where an
    # account-signed user token accompanies the tenant token. Empty when the
    # tenant itself made the request.
    user_id: str = ""

    def expired(self, now: datetime, skew: timedelta) -> bool:
        """Whether the token has passed its expiry (with skew slack)."""
        return self.expires_at is not None and now > self.expires_at + skew

    def has_scope(self, scope: str) -> bool:
        """Whether the tenant holds an exact scope grant."""
        return scope in self.scopes

    def authorizes(self, required: str) -> bool:
        """Whether any granted scope covers the required scope.

        A grant ending in ``*`` is a prefix wildcard, so ``call:/svc/*``
        covers every method of that service and ``call:*`` covers every call.
        """
        return covered(self.scopes, required)


def covered(granted: Iterable[str], required: str) -> bool:
    """Whether any granted scope covers the required scope, honoring
    trailing-``*`` prefix wildcards."""
    return any(_scope_match(g, required) for g in granted)


def _scope_match(granted: str, required: str) -> bool:
    if granted.endswith("*"):
        return required.startswith(granted[:-1])
    return granted == required


def _encode_generic(
    signer: nkeys.KeyPair, subject: str, data: dict, ttl: timedelta, now: datetime
) -> str:
    """Encode a NATS-style generic-claims JWT, matching nats-io/jwt/v2.

    The jti is the base32 SHA-512/256 of the standard claims serialized with
    an empty jti, exactly as the Go library computes it.
    """
    issued_at = int(now.timestamp())
    expires = int((now + ttl).timestamp())
    standard = {
        "exp": expires,
        "iat": issued_at,
        "iss": signer.public_key,
        "sub": subject,
    }
    # sha512_256 is a distinct truncation with its own IV, not a sliced sha512.
    digest = hashlib.new("sha512_256", json.dumps(standard, separators=(",", ":")).encode())
    jti = base64.b32encode(digest.digest()).decode("ascii").rstrip("=")
    payload = {
        "exp": expires,
        "jti": jti,
        "iat": issued_at,
        "iss": signer.public_key,
        "sub": subject,
        "nats": {**data, "version": 2},
    }
    header_b64 = _b64url(_JWT_HEADER.encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    to_sign = f"{header_b64}.{payload_b64}"
    signature = _b64url(signer.sign(to_sign.encode()))
    return f"{to_sign}.{signature}"


def issue(
    operator: nkeys.KeyPair,
    tenant_id: str,
    tenant_pub_key: str,
    scopes: list[str],
    ttl: timedelta,
    *,
    now: datetime | None = None,
) -> str:
    """Mint a tenant token signed by the operator key.

    tenant_pub_key is the tenant's nkey public key; the tenant signs
    requests with the matching seed.
    """
    if not nkeys.is_valid_public_operator_key(operator.public_key):
        raise ValissError(
            "valiss: tenant tokens must be signed by an operator-type nkey (expected an SO... seed)"
        )
    if not nkeys.is_valid_public_user_key(tenant_pub_key) and not nkeys.is_valid_public_account_key(
        tenant_pub_key
    ):
        raise ValissError("valiss: invalid tenant public key")
    if ttl <= timedelta(0):
        raise ValissError("valiss: ttl must be positive")
    data = {_PUBKEY_CLAIM: tenant_pub_key, _SCOPES_CLAIM: scopes}
    return _encode_generic(operator, tenant_id, data, ttl, now or _now())


def issue_user(
    account: nkeys.KeyPair,
    user_id: str,
    user_pub_key: str,
    scopes: list[str],
    ttl: timedelta,
    *,
    now: datetime | None = None,
) -> str:
    """Mint a user token signed by a tenant's account key, delegating a
    subset of the tenant's access to an end user.

    user_pub_key may be empty only when scopes grant SCOPE_BEARER, producing
    a token-only credential for users that cannot sign requests.
    """
    if not nkeys.is_valid_public_account_key(account.public_key):
        raise ValissError(
            "valiss: user tokens must be signed by an account-type nkey (expected an SA... seed)"
        )
    if not user_pub_key:
        if SCOPE_BEARER not in scopes:
            raise ValissError(
                f'valiss: user token without a key requires the "{SCOPE_BEARER}" scope'
            )
    elif not nkeys.is_valid_public_user_key(user_pub_key) and not nkeys.is_valid_public_account_key(
        user_pub_key
    ):
        raise ValissError("valiss: invalid user public key")
    if ttl <= timedelta(0):
        raise ValissError("valiss: ttl must be positive")
    data: dict = {_SCOPES_CLAIM: scopes}
    if user_pub_key:
        data[_PUBKEY_CLAIM] = user_pub_key
    return _encode_generic(account, user_id, data, ttl, now or _now())


def verify(token: str, issuer_pub_key: str) -> Claims:
    """Decode a token, check its signature and issuer, and return the claims.

    The claims' tenant_id carries the token subject, whichever level the
    token is for. Does NOT check expiry or the allowlist; the Verifier
    layers those so callers get precise errors. A token may omit the bound
    key only when its scopes grant SCOPE_BEARER.
    """
    chunks = token.split(".")
    if len(chunks) != 3:
        raise ValissError("valiss: expected 3 chunks")
    try:
        header = json.loads(_b64url_decode(chunks[0]))
        payload = json.loads(_b64url_decode(chunks[1]))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValissError(f"valiss: bad token: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValissError("valiss: bad token structure")
    if str(header.get("typ", "")).upper() != "JWT":
        raise ValissError(f"valiss: not supported type {header.get('typ')!r}")
    if str(header.get("alg", "")).lower() not in _JWT_ALGORITHMS:
        raise ValissError(f"valiss: unexpected {header.get('alg')!r} algorithm")
    issuer = payload.get("iss", "")
    signature = _b64url_decode(chunks[2])
    try:
        nkeys.from_public_key(issuer).verify(f"{chunks[0]}.{chunks[1]}".encode(), signature)
    except ValissError as exc:
        raise ValissError("valiss: claim failed signature verification") from exc
    if issuer != issuer_pub_key:
        raise ValissError("valiss: token not signed by the expected issuer")
    data = payload.get("nats") or {}
    pub_key = data.get(_PUBKEY_CLAIM, "")
    if not isinstance(pub_key, str):
        pub_key = ""
    raw_scopes = data.get(_SCOPES_CLAIM)
    scopes = [s for s in raw_scopes if isinstance(s, str)] if isinstance(raw_scopes, list) else []
    if not pub_key and SCOPE_BEARER not in scopes:
        raise ValissError("valiss: token missing tenant key")
    expires_at = None
    if payload.get("exp"):
        expires_at = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)
    return Claims(
        tenant_id=payload.get("sub", ""),
        pub_key=pub_key,
        scopes=scopes,
        id=payload.get("jti", ""),
        issuer=issuer,
        expires_at=expires_at,
    )


def sign_request(subject: nkeys.KeyPair, now: datetime) -> tuple[str, str]:
    """Produce the timestamp and base64 signature a tenant attaches to a
    request, signing with its nkey seed.

    The signed payload is just the timestamp: the token binds the tenant
    key, the allowlist bounds validity, and the skew window bounds replay.
    """
    timestamp = _rfc3339nano(now)
    signature = base64.b64encode(subject.sign(timestamp.encode())).decode("ascii")
    return timestamp, signature


def verify_request(
    tenant_pub_key: str,
    timestamp: str,
    signature: str,
    now: datetime,
    skew: timedelta,
) -> None:
    """Check a request signature against the tenant public key and bound the
    timestamp to a symmetric skew window around now."""
    try:
        ts = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValissError(f"valiss: bad request timestamp: {exc}") from exc
    if ts.tzinfo is None:
        raise ValissError("valiss: bad request timestamp: missing timezone offset")
    drift = now - ts
    if drift > skew or drift < -skew:
        raise ValissError(f"valiss: request timestamp outside the {skew} skew window")
    try:
        raw_sig = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValissError(f"valiss: bad request signature encoding: {exc}") from exc
    try:
        pub = nkeys.from_public_key(tenant_pub_key)
    except ValissError as exc:
        raise ValissError(f"valiss: bad tenant public key: {exc}") from exc
    # Verified over the raw timestamp string: canonical RFC3339Nano
    # round-trips exactly, and Python cannot re-render Go's nanosecond
    # precision.
    try:
        pub.verify(timestamp.encode(), raw_sig)
    except ValissError as exc:
        raise ValissError("valiss: request signature verification failed") from exc


@dataclass
class Credential:
    """Per-request material a transport extracts from headers."""

    # token is the operator-signed tenant token.
    token: str = ""
    # user_token is the account-signed user token on chain credentials;
    # empty when the tenant itself makes the request.
    user_token: str = ""
    # timestamp and signature are the per-request signing proof; both empty
    # on bearer requests.
    timestamp: str = ""
    signature: str = ""


class Allowlist(Protocol):
    """Decides whether an issued token (by jti) is still accepted. Only
    tokens the issuer explicitly deposited server-side pass, so a token can
    be revoked by removing it even before expiry."""

    def allowed(self, jti: str) -> bool: ...


class StaticAllowlist:
    """In-memory set of accepted token IDs."""

    def __init__(self, *ids: str):
        self._ids = frozenset(ids)

    def allowed(self, jti: str) -> bool:
        return jti in self._ids

    def set(self, ids: Iterable[str]) -> None:
        """Replace the accepted set, e.g. after reloading the file."""
        self._ids = frozenset(ids)


def load_allowlist_file(path: str) -> StaticAllowlist:
    """Read a newline-delimited allowlist file of token IDs. Blank lines and
    lines beginning with ``#`` are ignored."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as exc:
        raise ValissError(f"valiss: open allowlist: {exc}") from exc
    ids = [line.strip() for line in lines]
    return StaticAllowlist(*[line for line in ids if line and not line.startswith("#")])


class AllowAll:
    """Accepts every token; for local development where no allowlist is
    configured. The token signature and expiry still gate access."""

    def allowed(self, jti: str) -> bool:
        return True


# Custom validation logic injected into the Verifier. Runs after the token
# chain is verified and the effective claims are assembled, and before the
# request signature check. Raising ValissError rejects the request as
# unauthenticated.
ClaimsValidator = Callable[[Credential, Claims], None]


class Verifier:
    """Checks the full per-request credential: tenant token signature
    against the pinned operator key, expiry, allowlist membership, the
    optional user-token chain, and the request signature within the skew
    window. Requests without a signature pass only when the effective token
    grants SCOPE_BEARER."""

    def __init__(
        self,
        operator_pub_key: str,
        allowlist: Allowlist,
        *,
        skew: timedelta = DEFAULT_SKEW,
        now: Callable[[], datetime] = _now,
        validators: Iterable[ClaimsValidator] = (),
    ):
        self._operator_pub_key = operator_pub_key
        self._allowlist = allowlist
        self._skew = skew
        self._now = now
        self._validators = list(validators)

    def verify_credential(self, cred: Credential) -> Claims:
        """Authenticate a request credential and return the effective
        claims. Any ValissError means the request must be rejected as
        unauthenticated.

        A credential with a user token is verified as a chain: the tenant
        token against the operator key and the allowlist, then the user
        token against the tenant token's bound account key. The effective
        scopes are the user's scopes clamped to those the tenant holds, so
        a tenant can never delegate more than it has; SCOPE_BEARER passes
        through unclamped because it selects an authentication mode, not an
        authorization grant.

        An empty timestamp and signature is a bearer request, accepted only
        when the effective token grants SCOPE_BEARER.
        """
        claims = verify(cred.token, self._operator_pub_key)
        now = self._now()
        if claims.expired(now, self._skew):
            raise ValissError("valiss: tenant token expired")
        if not self._allowlist.allowed(claims.id):
            raise ValissError("valiss: tenant token not recognized")
        if cred.user_token:
            user = verify(cred.user_token, claims.pub_key)
            if user.expired(now, self._skew):
                raise ValissError("valiss: user token expired")
            scopes = [
                s for s in user.scopes if s == SCOPE_BEARER or covered(claims.scopes, s)
            ]
            claims = Claims(
                tenant_id=claims.tenant_id,
                user_id=user.tenant_id,
                pub_key=user.pub_key,
                scopes=scopes,
                id=claims.id,
                issuer=claims.issuer,
                expires_at=_min_expiry(claims.expires_at, user.expires_at),
            )
        for validate in self._validators:
            validate(cred, claims)
        if not cred.timestamp and not cred.signature:
            if not claims.has_scope(SCOPE_BEARER):
                raise ValissError(
                    "valiss: request signature required: token does not grant the bearer scope"
                )
            return claims
        if not claims.pub_key:
            raise ValissError("valiss: request signature present but token binds no key")
        verify_request(claims.pub_key, cred.timestamp, cred.signature, now, self._skew)
        return claims


def _min_expiry(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)
