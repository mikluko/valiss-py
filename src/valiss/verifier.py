# pyright: strict
"""The integrated per-request Verifier: the server side of the valiss scheme.

A :class:`Verifier` turns the credential a transport pulled off a request — an
account token, an optional user token, a timestamp+signature (or a bearer
waiver), and an optional nonce — into a verified :class:`Identity`, or raises
:class:`~valiss.errors.ValissError`. It composes the already wire-verified
per-token primitives (``verify_account``/``verify_user``/``verify_signature``)
into one chain check: account token against the pinned operator key, expiry and
activation, allowlist membership (revocation), the optional user-token chain,
registered extension types, custom validators, and the request signature within
the skew window. A request without a signature passes only when the effective
token is a bearer user token.

The API is Pythonic where Go uses functional options: construct a ``Verifier``,
register custom checks with the :meth:`Verifier.validator` and
:meth:`Verifier.extension` decorators (or pass them at construction), and call
:meth:`Verifier.verify` (or the verifier itself). Transport layers (the
``httpauth`` middleware, the ``grpcauth`` interceptor) wrap it with header
extraction and status-code mapping.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from . import token
from .allowlist import Allowlist
from .errors import Reason, ValissError
from .keyring import Keyring
from .replay import ReplayCache

# A resolver supplies the operator-signed account token for an account public
# key, serving requests that carry only a user token. It raises ValissError
# when it has none.
AccountTokenResolver = Callable[[str], str]

# A custom check that runs after the chain is verified and possession proven;
# it raises ValissError (or any exception) to reject the request.
ClaimsValidator = Callable[["Request", "Identity"], None]

# A typed extension handler: receives the extension decoded from the account and
# user tokens (a zero value when a token omits it).
ExtensionHandler = Callable[["Request", "Identity", Any, Any], None]


@dataclass(frozen=True, slots=True)
class Request:
    """The per-request material a transport extracts from headers/metadata."""

    # account_token is the operator-signed account token.
    account_token: str = ""
    # user_token is the account-signed user token on chain credentials; empty
    # when the tenant itself makes the request.
    user_token: str = ""
    # timestamp and signature are the per-request signing proof; both empty on
    # bearer requests.
    timestamp: str = ""
    signature: str = ""
    # context is the transport's canonical description of the request that the
    # signature is bound to; empty binds nothing beyond the timestamp.
    context: bytes = b""
    # nonce is a per-request unique value folded into context by the transport;
    # a verifier with a replay cache requires it and rejects a repeat.
    nonce: str = ""


@dataclass(frozen=True, slots=True)
class Identity:
    """The verified result of a request."""

    # account is the tenant the request acts under; always present.
    account: token.AccountClaims
    # user is the delegated end user; None for account-level requests.
    user: token.UserClaims | None = None
    # operator is the trust domain the request verified under (the configured
    # operator token, else None); consumers trusting several domains segment by
    # operator.name.
    operator: token.OperatorClaims | None = None


def static_account_tokens(*tokens: str) -> AccountTokenResolver:
    """Build a resolver over a fixed token set, e.g. from server configuration.
    Tokens are indexed by their subject account key; their signatures are
    checked here, their trust is established per request."""
    by_key: dict[str, str] = {}
    for tok in tokens:
        claims = token.verify_account(tok, token.issuer_of(tok))
        by_key[claims.subject] = tok

    def resolve(account_pub_key: str) -> str:
        try:
            return by_key[account_pub_key]
        except KeyError:
            raise ValissError(
                "valiss: no account token configured for the user token's account"
            ) from None

    return resolve


def _as_resolver(
    resolver: AccountTokenResolver | Mapping[str, str] | None,
) -> AccountTokenResolver | None:
    """Normalize a resolver into a callable: a ``{account_pub: token}`` mapping
    becomes a lookup that raises when a key is absent."""
    if resolver is None or callable(resolver):
        return resolver
    mapping = dict(resolver)

    def resolve(account_pub_key: str) -> str:
        try:
            return mapping[account_pub_key]
        except KeyError:
            raise ValissError(
                "valiss: no account token configured for the user token's account"
            ) from None

    return resolve


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Verifier:
    """Verifies a full per-request credential against a pinned operator key.

    Construct with the operator public key and an :class:`~valiss.allowlist.
    Allowlist`; the keyword options mirror the Go ``VerifierOption`` set:
    ``skew``, ``clock`` (a ``() -> datetime`` for tests), ``resolver`` (a
    callable or ``{account_pub: token}`` mapping for user-only requests),
    ``replay_cache``, and ``operator_token`` (enforces the trust domain's epoch
    and validity window; a token not self-signed by the pinned key poisons the
    verifier so every request fails). Register custom checks with the
    :meth:`validator` / :meth:`extension` decorators or the ``validators`` /
    ``extension_types`` arguments.
    """

    def __init__(
        self,
        operator_pub_key: str,
        allowlist: Allowlist,
        *,
        skew: timedelta = token.DEFAULT_SKEW,
        clock: Callable[[], datetime] | None = None,
        resolver: AccountTokenResolver | Mapping[str, str] | None = None,
        replay_cache: ReplayCache | None = None,
        operator_token: str | None = None,
        validators: Iterable[ClaimsValidator] = (),
        extension_types: Iterable[type[token.DecodableExtension]] = (),
    ):
        self._configure(allowlist, skew, clock, resolver, replay_cache, validators, extension_types)
        self._operator_pub_key = operator_pub_key
        self._keyring: Keyring | None = None
        self._operator: token.OperatorClaims | None = None
        self._operator_err: ValissError | None = None
        if operator_token is not None:
            try:
                self._operator = token.verify_operator(operator_token, operator_pub_key)
            except ValissError as exc:
                self._operator_err = exc

    @classmethod
    def with_keyring(
        cls,
        keyring: Keyring,
        allowlist: Allowlist,
        *,
        skew: timedelta = token.DEFAULT_SKEW,
        clock: Callable[[], datetime] | None = None,
        resolver: AccountTokenResolver | Mapping[str, str] | None = None,
        replay_cache: ReplayCache | None = None,
        validators: Iterable[ClaimsValidator] = (),
        extension_types: Iterable[type[token.DecodableExtension]] = (),
    ) -> Verifier:
        """A verifier for a server trusting several operators (see
        :class:`~valiss.keyring.Keyring`). The credential names its trust domain
        — the account token's issuer and epoch select exactly one keyring entry
        — and the request verifies under that entry's always-enforced policy
        (its validity window and exact epoch). An unknown ``(issuer, epoch)``
        pair is rejected. There is no ``operator_token`` option: entries carry
        the policy."""
        self = cls.__new__(cls)
        self._configure(allowlist, skew, clock, resolver, replay_cache, validators, extension_types)
        self._operator_pub_key = ""
        self._keyring = keyring
        self._operator = None
        self._operator_err = None
        return self

    def _configure(
        self,
        allowlist: Allowlist,
        skew: timedelta,
        clock: Callable[[], datetime] | None,
        resolver: AccountTokenResolver | Mapping[str, str] | None,
        replay_cache: ReplayCache | None,
        validators: Iterable[ClaimsValidator],
        extension_types: Iterable[type[token.DecodableExtension]],
    ) -> None:
        self._allowlist = allowlist
        self._skew = skew
        self._now = clock or _utcnow
        self._resolver = _as_resolver(resolver)
        self._replay = replay_cache
        self._validators: list[ClaimsValidator] = list(validators)
        self._extension_types: list[type[token.DecodableExtension]] = list(extension_types)

    def validator(self, fn: ClaimsValidator) -> ClaimsValidator:
        """Register a custom check ``fn(request, identity)`` that raises to
        reject. Usable as a decorator. Validators run after possession is
        proven, in registration order; the first to raise wins."""
        self._validators.append(fn)
        return fn

    def extension(
        self, ext_type: type[token.DecodableExtension]
    ) -> Callable[[ExtensionHandler], ExtensionHandler]:
        """Decorator registering a typed extension handler
        ``fn(request, identity, account_ext, user_ext)``: the extension is
        decoded from the account and user tokens (a zero value when omitted, a
        rejection when malformed) before ``fn`` runs."""

        def register(fn: ExtensionHandler) -> ExtensionHandler:
            def validate(request: Request, identity: Identity) -> None:
                account_ext = token.ext_of(identity.account.ext, ext_type)
                if account_ext is None:
                    account_ext = ext_type()
                user_ext: Any = ext_type()
                if identity.user is not None:
                    decoded = token.ext_of(identity.user.ext, ext_type)
                    user_ext = decoded if decoded is not None else ext_type()
                fn(request, identity, account_ext, user_ext)

            self._validators.append(validate)
            return fn

        return register

    def require_extension(self, ext_type: type[token.DecodableExtension]) -> None:
        """Register an extension type for eager validation: when either token
        carries the extension it must decode into ``ext_type`` or the request is
        rejected. Reading via ``token.ext_of`` never requires registration; this
        only moves malformed-extension failures to auth time."""
        self._extension_types.append(ext_type)

    def verify(self, request: Request) -> Identity:
        """Authenticate a request credential and return the verified identity.
        Any raised :class:`ValissError` means reject the request as
        unauthenticated; its ``reason`` is the spec §7 code."""
        if self._operator_err is not None:
            raise ValissError(
                f"valiss: operator token misconfigured: {self._operator_err}",
                reason=Reason.OPERATOR_MISCONFIGURED,
            )

        account_token = request.account_token
        if not account_token:
            if not request.user_token:
                raise ValissError("valiss: missing credentials", reason=Reason.MISSING)
            if self._resolver is None:
                raise ValissError(
                    "valiss: request carries no account token and the server has no "
                    "account token resolver",
                    reason=Reason.NO_RESOLVER,
                )
            account_pub_key = token.issuer_of(request.user_token)
            account_token = self._resolver(account_pub_key)

        account, operator = self._anchor(account_token)
        now = self._now()

        if operator is not None:
            if operator.expired(now, self._skew):
                raise ValissError(
                    "valiss: operator token expired: the trust domain is closed",
                    reason=Reason.EXPIRED,
                )
            if operator.not_yet_valid(now, self._skew):
                raise ValissError("valiss: operator token not yet valid", reason=Reason.NOT_YET_VALID)
            if account.epoch != operator.epoch:
                raise ValissError(
                    f"valiss: account token epoch {account.epoch}, trust domain epoch {operator.epoch}",
                    reason=Reason.EPOCH_MISMATCH,
                )

        if account.expired(now, self._skew):
            raise ValissError("valiss: account token expired", reason=Reason.EXPIRED)
        if account.not_yet_valid(now, self._skew):
            raise ValissError("valiss: account token not yet valid", reason=Reason.NOT_YET_VALID)
        if account.id not in self._allowlist:
            raise ValissError("valiss: account token not recognized", reason=Reason.NOT_ALLOWLISTED)

        user: token.UserClaims | None = None
        if request.user_token:
            user = token.verify_user(request.user_token, account.subject)
            if operator is not None and user.epoch != operator.epoch:
                raise ValissError(
                    f"valiss: user token epoch {user.epoch}, trust domain epoch {operator.epoch}",
                    reason=Reason.EPOCH_MISMATCH,
                )
            if user.expired(now, self._skew):
                raise ValissError("valiss: user token expired", reason=Reason.EXPIRED)
            if user.not_yet_valid(now, self._skew):
                raise ValissError("valiss: user token not yet valid", reason=Reason.NOT_YET_VALID)

        identity = Identity(account=account, user=user, operator=operator)

        # Prove possession before any consumer hook runs, so extension checks
        # and validators only ever see requests whose sender holds the key (a
        # bearer user token waives the signature by design).
        subject = user.subject if user is not None else account.subject
        if not request.timestamp and not request.signature:
            if user is None or not user.bearer:
                raise ValissError(
                    "valiss: request signature required: not a bearer token",
                    reason=Reason.NOT_BEARER,
                )
        else:
            token.verify_signature(
                subject, request.timestamp, request.signature, request.context, now, self._skew
            )
            if self._replay is not None:
                if not request.nonce:
                    raise ValissError("valiss: request nonce required", reason=Reason.NONCE_REQUIRED)
                if self._replay.seen_before(request.nonce, now + 2 * self._skew):
                    raise ValissError(
                        "valiss: request nonce already seen (replay)", reason=Reason.REPLAY
                    )

        for ext_type in self._extension_types:
            token.ext_of(account.ext, ext_type)
            if user is not None:
                token.ext_of(user.ext, ext_type)

        for validate in self._validators:
            try:
                validate(request, identity)
            except ValissError:
                raise
            except Exception as exc:  # noqa: BLE001 - any validator error rejects the request
                raise ValissError(
                    f"valiss: validator rejected the request: {exc}",
                    reason=Reason.VALIDATOR_REJECTED,
                ) from exc

        return identity

    __call__ = verify

    def _anchor(
        self, account_token: str
    ) -> tuple[token.AccountClaims, token.OperatorClaims | None]:
        """Resolve the trust anchor and verify the account token against it,
        returning the account claims and the operator policy to enforce (None
        for a single-anchor verifier with no operator token). A keyring selects
        the entry the credential names — the account token's issuer and epoch —
        with no trial; an unknown pair is rejected."""
        if self._keyring is not None:
            issuer = token.issuer_of(account_token)
            account = token.verify_account(account_token, issuer)
            operator = self._keyring.get(issuer, account.epoch)
            if operator is None:
                raise ValissError(
                    f"valiss: no trusted operator {issuer} at epoch {account.epoch}",
                    reason=Reason.UNKNOWN_OPERATOR,
                )
            return account, operator
        account = token.verify_account(account_token, self._operator_pub_key)
        return account, self._operator
