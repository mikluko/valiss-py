import base64
from datetime import datetime, timedelta, timezone

import pytest

from valiss import ValissError, nkeys, token

NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
TTL = timedelta(hours=1)


@pytest.fixture
def operator():
    return nkeys.create_operator()


@pytest.fixture
def account():
    return nkeys.create_account()


def test_issue_verify(operator, account):
    tok = token.issue(operator, "acme", account.public_key, ["call:/v1/*"], TTL, now=NOW)
    claims = token.verify(tok, operator.public_key)
    assert claims.tenant_id == "acme"
    assert claims.pub_key == account.public_key
    assert claims.scopes == ["call:/v1/*"]
    assert claims.issuer == operator.public_key
    assert claims.id
    assert claims.expires_at == NOW + TTL
    assert claims.user_id == ""


def test_issue_rejects_non_operator_signer(account):
    with pytest.raises(ValissError, match="operator-type nkey"):
        token.issue(account, "acme", account.public_key, [], TTL)


def test_issue_rejects_bad_tenant_key(operator):
    with pytest.raises(ValissError, match="invalid tenant public key"):
        token.issue(operator, "acme", operator.public_key, [], TTL)


def test_issue_rejects_non_positive_ttl(operator, account):
    with pytest.raises(ValissError, match="ttl must be positive"):
        token.issue(operator, "acme", account.public_key, [], timedelta(0))


def test_issue_user(account):
    user = nkeys.create_user()
    tok = token.issue_user(account, "alice", user.public_key, ["call:/v1/get"], TTL, now=NOW)
    claims = token.verify(tok, account.public_key)
    assert claims.tenant_id == "alice"
    assert claims.pub_key == user.public_key
    assert claims.scopes == ["call:/v1/get"]


def test_issue_user_rejects_non_account_signer(operator):
    user = nkeys.create_user()
    with pytest.raises(ValissError, match="account-type nkey"):
        token.issue_user(operator, "alice", user.public_key, [], TTL)


def test_issue_user_keyless_requires_bearer(account):
    with pytest.raises(ValissError, match="bearer"):
        token.issue_user(account, "carol", "", ["call:/v1/get"], TTL)
    tok = token.issue_user(account, "carol", "", [token.SCOPE_BEARER], TTL, now=NOW)
    claims = token.verify(tok, account.public_key)
    assert claims.pub_key == ""
    assert claims.has_scope(token.SCOPE_BEARER)


def test_verify_rejects_wrong_issuer(operator, account):
    tok = token.issue(operator, "acme", account.public_key, [], TTL, now=NOW)
    other = nkeys.create_operator()
    with pytest.raises(ValissError, match="not signed by the expected issuer"):
        token.verify(tok, other.public_key)


def test_verify_rejects_tampered_payload(operator, account):
    tok = token.issue(operator, "acme", account.public_key, [], TTL, now=NOW)
    header, payload, sig = tok.split(".")
    tampered = ".".join([header, payload[:-2] + ("aa" if payload[-2:] != "aa" else "bb"), sig])
    with pytest.raises(ValissError):
        token.verify(tampered, operator.public_key)


def test_verify_rejects_malformed(operator):
    with pytest.raises(ValissError, match="3 chunks"):
        token.verify("only.two", operator.public_key)


def test_sign_verify_request(account):
    timestamp, signature = token.sign_request(account, NOW)
    token.verify_request(account.public_key, timestamp, signature, NOW, token.DEFAULT_SKEW)


def test_verify_request_skew_window(account):
    timestamp, signature = token.sign_request(account, NOW)
    late = NOW + token.DEFAULT_SKEW + timedelta(seconds=1)
    with pytest.raises(ValissError, match="skew window"):
        token.verify_request(account.public_key, timestamp, signature, late, token.DEFAULT_SKEW)
    early = NOW - token.DEFAULT_SKEW - timedelta(seconds=1)
    with pytest.raises(ValissError, match="skew window"):
        token.verify_request(account.public_key, timestamp, signature, early, token.DEFAULT_SKEW)


def test_verify_request_rejects_wrong_key(account):
    timestamp, signature = token.sign_request(account, NOW)
    other = nkeys.create_account()
    with pytest.raises(ValissError, match="signature verification failed"):
        token.verify_request(other.public_key, timestamp, signature, NOW, token.DEFAULT_SKEW)


def test_verify_request_rejects_bad_timestamp(account):
    _, signature = token.sign_request(account, NOW)
    with pytest.raises(ValissError, match="bad request timestamp"):
        token.verify_request(account.public_key, "not-a-time", signature, NOW, token.DEFAULT_SKEW)
    with pytest.raises(ValissError, match="bad request timestamp"):
        token.verify_request(
            account.public_key, "2026-07-09T12:00:00", signature, NOW, token.DEFAULT_SKEW
        )


def test_verify_request_parses_go_nanosecond_timestamps(account):
    # Go emits up to nine fractional digits; parsing must tolerate them even
    # though datetime truncates beyond microseconds. The signature is bound
    # to the raw timestamp string, exactly as a Go client produces it.
    ts = "2026-07-09T12:00:00.123456789Z"
    sig = base64.b64encode(account.sign(ts.encode())).decode()
    token.verify_request(account.public_key, ts, sig, NOW, timedelta(hours=1))


def test_scope_coverage():
    claims = token.Claims(tenant_id="t", pub_key="", scopes=["call:/v1/*", "admin"])
    assert claims.authorizes("call:/v1/widgets")
    assert claims.authorizes("admin")
    assert not claims.authorizes("call:/v2/widgets")
    assert not claims.authorizes("admin2")
    assert token.covered(["call:*"], "call:/anything")
    assert token.covered(["*"], "anything")
    assert not token.covered([], "anything")


def test_expired():
    claims = token.Claims(tenant_id="t", pub_key="", expires_at=NOW)
    skew = timedelta(minutes=2)
    assert not claims.expired(NOW + skew, skew)
    assert claims.expired(NOW + skew + timedelta(seconds=1), skew)
    assert not token.Claims(tenant_id="t", pub_key="").expired(NOW, skew)
