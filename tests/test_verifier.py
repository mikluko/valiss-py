"""Port of valiss-go verifier_test.go: the integrated request Verifier.

Each negative case asserts the spec §7 reason code (ValissError.reason) the
failure reduces to — the executable parity oracle in the absence of a
requests.json vector set. Time is injected via clock=/now=, never slept.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from valiss import nkeys, token
from valiss.allowlist import ALLOW_ALL, StaticAllowlist
from valiss.errors import Reason, ValissError
from valiss.replay import MemoryReplayCache
from valiss.verifier import Request, Verifier, static_account_tokens

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


@pytest.fixture
def operator():
    return nkeys.create_operator()


@pytest.fixture
def account():
    return nkeys.create_account()


@pytest.fixture
def user():
    return nkeys.create_user()


def clock(at=NOW):
    return lambda: at


def sign(kp, context=b"", at=NOW):
    return token.sign_request(kp, context, at)


@dataclass
class DomainClaims:
    """A consumer-defined extension (mirrors the Go test's domainClaims)."""

    plan: str = ""
    quota: int = 0

    def extension_name(self) -> str:
        return "acme.example"

    def extension_payload(self):
        payload = {}
        if self.plan:
            payload["plan"] = self.plan
        if self.quota:
            payload["quota"] = self.quota
        return payload

    @classmethod
    def decode(cls, payload):
        if not isinstance(payload, dict):
            raise TypeError(f"expected an object, got {type(payload).__name__}")
        return cls(plan=payload.get("plan", ""), quota=payload.get("quota", 0))


# -------- bearer --------


def test_bearer(operator, account, user):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    bearer = token.issue_user(account, "carol", user.public_key, bearer=True, ttl=HOUR, now=NOW)
    plain = token.issue_user(account, "alice", user.public_key, ttl=HOUR, now=NOW)
    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock())

    idn = v.verify(Request(account_token=acct, user_token=bearer))
    assert idn.account.name == "acme" and idn.user is not None and idn.user.bearer

    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=acct, user_token=plain))
    assert exc.value.reason == Reason.NOT_BEARER

    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=acct))
    assert exc.value.reason == Reason.NOT_BEARER

    # A signature present on a bearer token is still verified: a bad one fails.
    ts, sig = sign(user)
    v.verify(Request(account_token=acct, user_token=bearer, timestamp=ts, signature=sig))
    with pytest.raises(ValissError):
        v.verify(Request(account_token=acct, user_token=bearer, timestamp=ts, signature="AAAA"))

    # A timestamp without a signature is not a bearer waiver.
    with pytest.raises(ValissError):
        v.verify(Request(account_token=acct, user_token=bearer, timestamp=ts))


# -------- custom validators --------


def test_validator_sees_identity(operator, account, user):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    usr = token.issue_user(account, "alice", user.public_key, ttl=HOUR, now=NOW)
    ts, sig = sign(user)
    seen = {}
    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock())

    @v.validator
    def capture(_req, identity):
        seen["id"] = identity

    v.verify(Request(account_token=acct, user_token=usr, timestamp=ts, signature=sig))
    assert seen["id"].account.name == "acme" and seen["id"].user.name == "alice"


def test_validator_error_rejects(operator, account):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    ts, sig = sign(account)
    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock())

    @v.validator
    def ban_acme(_req, identity):
        if identity.account.name == "acme":
            raise RuntimeError("tenant suspended")

    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=acct, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.VALIDATOR_REJECTED
    assert isinstance(exc.value.__cause__, RuntimeError)


def test_validators_run_in_order_first_wins(operator, account):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    ts, sig = sign(account)
    ran = {"second": False}

    def first(_req, _id):
        raise ValissError("valiss: first", reason=Reason.VALIDATOR_REJECTED)

    def second(_req, _id):
        ran["second"] = True

    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock(), validators=[first, second])
    with pytest.raises(ValissError):
        v.verify(Request(account_token=acct, timestamp=ts, signature=sig))
    assert ran["second"] is False


def test_validators_run_only_after_possession(operator, account):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    ts, sig = sign(account)
    ran = {"v": False}
    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock())

    @v.validator
    def mark(_req, _id):
        ran["v"] = True

    # Unsigned account request is rejected at the possession gate.
    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=acct))
    assert exc.value.reason == Reason.NOT_BEARER
    assert ran["v"] is False
    # A bad signature short-circuits before the validator too.
    with pytest.raises(ValissError):
        v.verify(Request(account_token=acct, timestamp=ts, signature="AAAA"))
    assert ran["v"] is False
    # A valid signature lets the validator run.
    v.verify(Request(account_token=acct, timestamp=ts, signature=sig))
    assert ran["v"] is True


def test_typed_extension_validator(operator, account, user):
    acct = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, extensions=[DomainClaims(plan="pro")], now=NOW
    )
    usr = token.issue_user(
        account, "alice", user.public_key, ttl=HOUR, extensions=[DomainClaims(plan="basic")], now=NOW
    )
    ts, sig = sign(user)
    got = {}
    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock())

    @v.extension(DomainClaims)
    def check(_req, _id, account_ext, user_ext):
        got["account"] = account_ext.plan
        got["user"] = user_ext.plan

    v.verify(Request(account_token=acct, user_token=usr, timestamp=ts, signature=sig))
    assert got == {"account": "pro", "user": "basic"}


# -------- extension type registration --------


def test_extension_type_registration(operator, account):
    ts, sig = sign(account)

    good = token.issue_account(
        operator, "acme", account.public_key, extensions=[DomainClaims(plan="pro")], now=NOW
    )
    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock(), extension_types=[DomainClaims])
    v.verify(Request(account_token=good, timestamp=ts, signature=sig))

    # A payload minted as a bare string under the same name cannot decode.
    bad = token.issue_account(
        operator, "acme", account.public_key,
        extensions=[token.RawExtension("acme.example", "not-a-struct")], now=NOW,
    )
    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=bad, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.EXTENSION_INVALID

    # An absent extension is not required.
    plain = token.issue_account(operator, "acme", account.public_key, now=NOW)
    v.verify(Request(account_token=plain, timestamp=ts, signature=sig))


# -------- validity windows --------


def test_token_without_expiry_never_expires(operator, account):
    acct = token.issue_account(operator, "acme", account.public_key, now=NOW)
    far = NOW + timedelta(days=365 * 100)
    ts, sig = sign(account, at=far)
    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock(far))
    v.verify(Request(account_token=acct, timestamp=ts, signature=sig))


def test_not_before_gates_the_token(operator, account):
    start = NOW + HOUR
    acct = token.issue_account(
        operator, "acme", account.public_key, ttl=2 * HOUR, not_before=start, now=NOW
    )
    ts, sig = sign(account, at=NOW)
    early = Verifier(operator.public_key, ALLOW_ALL, skew=timedelta(0), clock=clock(NOW))
    with pytest.raises(ValissError) as exc:
        early.verify(Request(account_token=acct, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.NOT_YET_VALID

    later = start + timedelta(minutes=1)
    ts, sig = sign(account, at=later)
    in_window = Verifier(operator.public_key, ALLOW_ALL, skew=timedelta(0), clock=clock(later))
    in_window.verify(Request(account_token=acct, timestamp=ts, signature=sig))


def test_user_token_not_before_gates_chain(operator, account, user):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    usr = token.issue_user(
        account, "carol", user.public_key, bearer=True, not_before=NOW + HOUR, now=NOW
    )
    v = Verifier(operator.public_key, ALLOW_ALL, skew=timedelta(0), clock=clock())
    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=acct, user_token=usr))
    assert exc.value.reason == Reason.NOT_YET_VALID


# -------- replay cache --------


def test_replay_cache(operator, account):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)

    def signed(nonce):
        ctx = b"op\n" + nonce.encode()
        ts, sig = sign(account, ctx)
        return Request(account_token=acct, timestamp=ts, signature=sig, context=ctx, nonce=nonce)

    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock(), replay_cache=MemoryReplayCache(clock=clock()))
    req = signed(token.new_nonce())
    v.verify(req)
    with pytest.raises(ValissError) as exc:
        v.verify(req)
    assert exc.value.reason == Reason.REPLAY

    v2 = Verifier(operator.public_key, ALLOW_ALL, clock=clock(), replay_cache=MemoryReplayCache(clock=clock()))
    v2.verify(signed(token.new_nonce()))
    v2.verify(signed(token.new_nonce()))

    # Missing nonce with a cache configured is rejected.
    ts, sig = sign(account)
    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=acct, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.NONCE_REQUIRED

    # Without a cache, nonces are ignored and the same request replays freely.
    lax = Verifier(operator.public_key, ALLOW_ALL, clock=clock())
    req = signed(token.new_nonce())
    lax.verify(req)
    lax.verify(req)


# -------- operator token / epoch policy --------


def test_operator_token_epoch(operator, account, user):
    op_tok = token.issue_operator(operator, epoch=2, now=NOW)
    acct = token.issue_account(operator, "acme", account.public_key, epoch=2, ttl=HOUR, now=NOW)
    usr = token.issue_user(account, "alice", user.public_key, epoch=2, ttl=HOUR, now=NOW)
    ts, sig = sign(user)
    acct_ts, acct_sig = sign(account)
    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock(), operator_token=op_tok)

    v.verify(Request(account_token=acct, user_token=usr, timestamp=ts, signature=sig))

    stale = token.issue_account(operator, "acme", account.public_key, epoch=1, ttl=HOUR, now=NOW)
    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=stale, timestamp=acct_ts, signature=acct_sig))
    assert exc.value.reason == Reason.EPOCH_MISMATCH
    assert "epoch 1, trust domain epoch 2" in str(exc.value)

    unstamped = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=unstamped, timestamp=acct_ts, signature=acct_sig))
    assert exc.value.reason == Reason.EPOCH_MISMATCH

    old_user = token.issue_user(account, "alice", user.public_key, epoch=1, ttl=HOUR, now=NOW)
    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=acct, user_token=old_user, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.EPOCH_MISMATCH
    assert "user token epoch 1" in str(exc.value)


def test_operator_token_resolved_epoch(operator, account, user):
    op_tok = token.issue_operator(operator, epoch=2, now=NOW)
    usr = token.issue_user(account, "alice", user.public_key, epoch=2, ttl=HOUR, now=NOW)
    ts, sig = sign(user)
    old = token.issue_account(operator, "acme", account.public_key, epoch=1, ttl=HOUR, now=NOW)
    v = Verifier(
        operator.public_key, ALLOW_ALL, clock=clock(),
        operator_token=op_tok, resolver=static_account_tokens(old),
    )
    with pytest.raises(ValissError) as exc:
        v.verify(Request(user_token=usr, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.EPOCH_MISMATCH


def test_without_operator_token_epochs_ignored(operator, account):
    old = token.issue_account(operator, "acme", account.public_key, epoch=1, ttl=HOUR, now=NOW)
    ts, sig = sign(account)
    lax = Verifier(operator.public_key, ALLOW_ALL, clock=clock())
    lax.verify(Request(account_token=old, timestamp=ts, signature=sig))


def test_operator_token_window(operator, account):
    acct = token.issue_account(operator, "acme", account.public_key, epoch=2, ttl=3 * HOUR, now=NOW)
    acct_ts, acct_sig = sign(account)

    short_op = token.issue_operator(operator, epoch=2, ttl=timedelta(seconds=1), now=NOW)
    closed = Verifier(
        operator.public_key, ALLOW_ALL, skew=timedelta(0),
        operator_token=short_op, clock=clock(NOW + HOUR),
    )
    with pytest.raises(ValissError) as exc:
        closed.verify(Request(account_token=acct, timestamp=acct_ts, signature=acct_sig))
    assert exc.value.reason == Reason.EXPIRED
    assert "trust domain is closed" in str(exc.value)

    future_op = token.issue_operator(operator, epoch=2, not_before=NOW + HOUR, now=NOW)
    early = Verifier(
        operator.public_key, ALLOW_ALL, skew=timedelta(0), operator_token=future_op, clock=clock(NOW)
    )
    with pytest.raises(ValissError) as exc:
        early.verify(Request(account_token=acct, timestamp=acct_ts, signature=acct_sig))
    assert exc.value.reason == Reason.NOT_YET_VALID
    # Domain opens once the operator token activates.
    active_at = NOW + 2 * HOUR
    late_ts, late_sig = sign(account, at=active_at)
    active = Verifier(
        operator.public_key, ALLOW_ALL, skew=timedelta(0),
        operator_token=future_op, clock=clock(active_at),
    )
    active.verify(Request(account_token=acct, timestamp=late_ts, signature=late_sig))


def test_operator_token_poison(operator, account):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    acct_ts, acct_sig = sign(account)

    foreign = token.issue_operator(nkeys.create_operator(), epoch=2, now=NOW)
    bad = Verifier(operator.public_key, ALLOW_ALL, clock=clock(), operator_token=foreign)
    with pytest.raises(ValissError) as exc:
        bad.verify(Request(account_token=acct, timestamp=acct_ts, signature=acct_sig))
    assert exc.value.reason == Reason.OPERATOR_MISCONFIGURED

    # An account token is not an operator token.
    bad2 = Verifier(operator.public_key, ALLOW_ALL, clock=clock(), operator_token=acct)
    with pytest.raises(ValissError) as exc:
        bad2.verify(Request(account_token=acct, timestamp=acct_ts, signature=acct_sig))
    assert exc.value.reason == Reason.OPERATOR_MISCONFIGURED


# -------- account token resolver --------


def test_account_token_resolver(operator, account, user):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    usr = token.issue_user(account, "alice", user.public_key, ttl=HOUR, now=NOW)
    ts, sig = sign(user)
    resolver = static_account_tokens(acct)

    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock(), resolver=resolver)
    idn = v.verify(Request(user_token=usr, timestamp=ts, signature=sig))
    assert idn.account.name == "acme" and idn.user.name == "alice"

    # No resolver rejects user-only credentials.
    none = Verifier(operator.public_key, ALLOW_ALL, clock=clock())
    with pytest.raises(ValissError) as exc:
        none.verify(Request(user_token=usr, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.NO_RESOLVER

    # Unknown account: the resolver has no token for it.
    other = nkeys.create_account()
    foreign_user = token.issue_user(other, "mallory", user.public_key, ttl=HOUR, now=NOW)
    with pytest.raises(ValissError, match="no account token configured"):
        v.verify(Request(user_token=foreign_user, timestamp=ts, signature=sig))

    # A resolved token still passes the allowlist.
    strict = Verifier(operator.public_key, StaticAllowlist("other"), clock=clock(), resolver=resolver)
    with pytest.raises(ValissError) as exc:
        strict.verify(Request(user_token=usr, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.NOT_ALLOWLISTED

    # An empty credential is still rejected.
    with pytest.raises(ValissError) as exc:
        v.verify(Request())
    assert exc.value.reason == Reason.MISSING

    # A tampered user token is rejected before resolution.
    with pytest.raises(ValissError):
        v.verify(Request(user_token=usr[:-2] + "xx", timestamp=ts, signature=sig))


# -------- chain --------


def test_verify_request_chain(operator, account, user):
    acct = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    usr = token.issue_user(account, "alice", user.public_key, ttl=HOUR, now=NOW)
    ts, sig = sign(user)
    v = Verifier(operator.public_key, ALLOW_ALL, clock=clock())

    idn = v.verify(Request(account_token=acct, user_token=usr, timestamp=ts, signature=sig))
    assert idn.account.subject == account.public_key
    assert idn.user.subject == user.public_key

    # An account signature does not authenticate a chain request (user subject).
    acct_ts, acct_sig = sign(account)
    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=acct, user_token=usr, timestamp=acct_ts, signature=acct_sig))
    assert exc.value.reason == Reason.BAD_REQUEST_SIGNATURE

    # A user token signed by a foreign account is rejected.
    other = nkeys.create_account()
    foreign = token.issue_user(other, "alice", user.public_key, ttl=HOUR, now=NOW)
    with pytest.raises(ValissError) as exc:
        v.verify(Request(account_token=acct, user_token=foreign, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.WRONG_ISSUER

    # An expired user token is rejected.
    short = token.issue_user(account, "alice", user.public_key, ttl=timedelta(seconds=1), now=NOW)
    late = Verifier(operator.public_key, ALLOW_ALL, skew=timedelta(0), clock=clock(NOW + timedelta(minutes=10)))
    with pytest.raises(ValissError) as exc:
        late.verify(Request(account_token=acct, user_token=short, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.EXPIRED

    # Revoking the account token (allowlist) cuts off its users.
    strict = Verifier(operator.public_key, StaticAllowlist("other"), clock=clock())
    with pytest.raises(ValissError) as exc:
        strict.verify(Request(account_token=acct, user_token=usr, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.NOT_ALLOWLISTED
