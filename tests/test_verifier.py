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


def _verifier(operator, jti, **kwargs):
    return token.Verifier(
        operator.public_key, token.StaticAllowlist(jti), now=lambda: NOW, **kwargs
    )


def _account_cred(operator, account, scopes=("call:/v1/*",), now=NOW):
    tok = token.issue(operator, "acme", account.public_key, list(scopes), TTL, now=now)
    claims = token.verify(tok, operator.public_key)
    timestamp, signature = token.sign_request(account, NOW)
    cred = token.Credential(token=tok, timestamp=timestamp, signature=signature)
    return cred, claims


def test_account_credential(operator, account):
    cred, issued = _account_cred(operator, account)
    claims = _verifier(operator, issued.id).verify_credential(cred)
    assert claims.tenant_id == "acme"
    assert claims.user_id == ""
    assert claims.authorizes("call:/v1/widgets")


def test_expired_token(operator, account):
    stale = NOW - TTL - token.DEFAULT_SKEW - timedelta(seconds=1)
    cred, issued = _account_cred(operator, account, now=stale)
    with pytest.raises(ValissError, match="tenant token expired"):
        _verifier(operator, issued.id).verify_credential(cred)


def test_allowlist_rejects_unknown_jti(operator, account):
    cred, _ = _account_cred(operator, account)
    with pytest.raises(ValissError, match="not recognized"):
        _verifier(operator, "other-jti").verify_credential(cred)


def test_missing_signature_without_bearer(operator, account):
    cred, issued = _account_cred(operator, account)
    cred.timestamp = ""
    cred.signature = ""
    with pytest.raises(ValissError, match="request signature required"):
        _verifier(operator, issued.id).verify_credential(cred)


def test_bearer_token_skips_signature(operator, account):
    tok = token.issue(
        operator, "acme", account.public_key, ["call:/v1/*", token.SCOPE_BEARER], TTL, now=NOW
    )
    issued = token.verify(tok, operator.public_key)
    claims = _verifier(operator, issued.id).verify_credential(token.Credential(token=tok))
    assert claims.tenant_id == "acme"


def test_user_chain_clamps_scopes(operator, account):
    user = nkeys.create_user()
    tok = token.issue(operator, "acme", account.public_key, ["call:/v1/*"], TTL, now=NOW)
    issued = token.verify(tok, operator.public_key)
    user_tok = token.issue_user(
        account, "alice", user.public_key, ["call:/v1/get", "call:/v2/get"], TTL, now=NOW
    )
    timestamp, signature = token.sign_request(user, NOW)
    cred = token.Credential(
        token=tok, user_token=user_tok, timestamp=timestamp, signature=signature
    )
    claims = _verifier(operator, issued.id).verify_credential(cred)
    assert claims.tenant_id == "acme"
    assert claims.user_id == "alice"
    # call:/v2/get exceeds the account's grants, so the clamp drops it.
    assert claims.scopes == ["call:/v1/get"]
    assert claims.pub_key == user.public_key


def test_user_chain_rejects_foreign_account(operator, account):
    user = nkeys.create_user()
    other_account = nkeys.create_account()
    tok = token.issue(operator, "acme", account.public_key, ["call:/v1/*"], TTL, now=NOW)
    issued = token.verify(tok, operator.public_key)
    user_tok = token.issue_user(other_account, "mallory", user.public_key, [], TTL, now=NOW)
    timestamp, signature = token.sign_request(user, NOW)
    cred = token.Credential(
        token=tok, user_token=user_tok, timestamp=timestamp, signature=signature
    )
    with pytest.raises(ValissError, match="not signed by the expected issuer"):
        _verifier(operator, issued.id).verify_credential(cred)


def test_user_bearer_passes_unclamped(operator, account):
    tok = token.issue(operator, "acme", account.public_key, ["call:/v1/*"], TTL, now=NOW)
    issued = token.verify(tok, operator.public_key)
    user_tok = token.issue_user(
        account, "carol", "", [token.SCOPE_BEARER, "call:/v1/get"], TTL, now=NOW
    )
    cred = token.Credential(token=tok, user_token=user_tok)
    claims = _verifier(operator, issued.id).verify_credential(cred)
    assert claims.user_id == "carol"
    assert token.SCOPE_BEARER in claims.scopes
    assert "call:/v1/get" in claims.scopes


def test_wrong_request_signer_rejected(operator, account):
    tok = token.issue(operator, "acme", account.public_key, [], TTL, now=NOW)
    issued = token.verify(tok, operator.public_key)
    imposter = nkeys.create_account()
    timestamp, signature = token.sign_request(imposter, NOW)
    cred = token.Credential(token=tok, timestamp=timestamp, signature=signature)
    with pytest.raises(ValissError, match="signature verification failed"):
        _verifier(operator, issued.id).verify_credential(cred)


def test_claims_validators_run_in_order(operator, account):
    cred, issued = _account_cred(operator, account)
    seen = []

    def first(c, claims):
        seen.append("first")

    def second(c, claims):
        seen.append("second")
        raise ValissError("valiss: tenant suspended")

    verifier = _verifier(operator, issued.id, validators=[first, second])
    with pytest.raises(ValissError, match="tenant suspended"):
        verifier.verify_credential(cred)
    assert seen == ["first", "second"]


def test_allow_all_and_file_allowlist(tmp_path, operator, account):
    cred, issued = _account_cred(operator, account)
    token.Verifier(operator.public_key, token.AllowAll(), now=lambda: NOW).verify_credential(cred)

    path = tmp_path / "allowlist"
    path.write_text(f"# comment\n\n{issued.id}\n")
    allowlist = token.load_allowlist_file(str(path))
    assert allowlist.allowed(issued.id)
    assert not allowlist.allowed("# comment")

    allowlist.set([])
    assert not allowlist.allowed(issued.id)
