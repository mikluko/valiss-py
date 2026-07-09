from datetime import datetime, timedelta, timezone

import httpx
import pytest

from valiss import ValissError, creds, httpauth, nkeys, token

NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
TTL = timedelta(hours=1)


@pytest.fixture
def setup():
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    tok = token.issue(operator, "acme", account.public_key, ["call:/v1/*"], TTL, now=NOW)
    issued = token.verify(tok, operator.public_key)
    verifier = token.Verifier(
        operator.public_key, token.StaticAllowlist(issued.id), now=lambda: NOW
    )
    bundle = creds.Bundle(token=tok, seed=account.seed)
    return verifier, bundle


def test_credential_headers_verify(setup):
    verifier, bundle = setup
    headers = httpauth.credential_headers(bundle, now=lambda: NOW)
    claims = verifier.verify_credential(httpauth.extract_credential(headers))
    assert claims.tenant_id == "acme"


def test_bearer_bundle_has_no_signature(setup):
    _, bundle = setup
    headers = httpauth.credential_headers(creds.Bundle(token=bundle.token))
    assert token.HEADER_TIMESTAMP not in headers
    assert token.HEADER_SIGNATURE not in headers
    assert headers[token.HEADER_TOKEN] == bundle.token


def test_user_token_header(setup):
    _, bundle = setup
    bundle.user_token = "user.token.sig"
    headers = httpauth.credential_headers(bundle, now=lambda: NOW)
    assert headers[token.HEADER_USER_TOKEN] == "user.token.sig"


def test_httpx_auth_end_to_end(setup):
    verifier, bundle = setup

    def handler(request: httpx.Request) -> httpx.Response:
        cred = httpauth.extract_credential(request.headers)
        try:
            claims = verifier.verify_credential(cred)
        except ValissError as exc:
            return httpx.Response(401, text=str(exc))
        if not claims.authorizes(httpauth.scope_for_path(request.url.path)):
            return httpx.Response(403)
        return httpx.Response(200, text=claims.tenant_id)

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        auth=httpauth.Auth(bundle, now=lambda: NOW),
    )
    resp = client.get("http://server/v1/whoami")
    assert resp.status_code == 200
    assert resp.text == "acme"
    assert client.get("http://server/admin").status_code == 403

    bare = httpx.Client(transport=httpx.MockTransport(handler))
    assert bare.get("http://server/v1/whoami").status_code == 401


def test_auth_rejects_malformed_seed():
    with pytest.raises(ValissError, match="creds seed"):
        httpauth.Auth(creds.Bundle(token="t", seed="garbage"))


def test_fresh_signature_per_request(setup):
    _, bundle = setup
    clock = iter([NOW, NOW + timedelta(seconds=1)])
    first = httpauth.credential_headers(bundle, now=lambda: next(clock))
    second = httpauth.credential_headers(bundle, now=lambda: next(clock))
    assert first[token.HEADER_TIMESTAMP] != second[token.HEADER_TIMESTAMP]
    assert first[token.HEADER_SIGNATURE] != second[token.HEADER_SIGNATURE]
