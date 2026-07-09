import pytest

from valiss import ValissError, creds, nkeys


def test_roundtrip_account_bundle():
    account = nkeys.create_account()
    bundle = creds.Bundle(token="tenant.token.sig", seed=account.seed)
    parsed = creds.parse(bundle.format())
    assert parsed == bundle
    assert parsed.signer().public_key == account.public_key


def test_roundtrip_user_bundle():
    user = nkeys.create_user()
    bundle = creds.Bundle(token="tenant.token.sig", user_token="user.token.sig", seed=user.seed)
    parsed = creds.parse(bundle.format())
    assert parsed == bundle


def test_roundtrip_bearer_bundle():
    bundle = creds.Bundle(token="tenant.token.sig")
    parsed = creds.parse(bundle.format())
    assert parsed == bundle
    assert parsed.signer() is None
    assert "SEED" not in bundle.format()


def test_parse_requires_token():
    with pytest.raises(ValissError, match="not found"):
        creds.parse("no markers here")


def test_parse_rejects_empty_section():
    text = "-----BEGIN VALISS TOKEN-----\n------END VALISS TOKEN------\n"
    with pytest.raises(ValissError, match="no content"):
        creds.parse(text)


def test_parse_rejects_unclosed_empty_section():
    # Content ends the search before the closing marker is required, so only
    # an unclosed section with no content is an error (Go parity).
    text = "-----BEGIN VALISS TOKEN-----\n"
    with pytest.raises(ValissError, match="not closed"):
        creds.parse(text)
    assert creds.parse("-----BEGIN VALISS TOKEN-----\ntok\n").token == "tok"


def test_load(tmp_path):
    bundle = creds.Bundle(token="tenant.token.sig")
    path = tmp_path / "acme.creds"
    path.write_text(bundle.format())
    assert creds.load(str(path)) == bundle
    with pytest.raises(ValissError, match="read creds"):
        creds.load(str(tmp_path / "missing.creds"))


def test_signer_rejects_malformed_seed():
    bundle = creds.Bundle(token="t", seed="not-a-seed")
    with pytest.raises(ValissError, match="creds seed"):
        bundle.signer()


def test_go_fixture_parses():
    # Byte layout produced by the Go creds.Format, markers and warning block
    # included.
    account = nkeys.create_account()
    text = (
        "-----BEGIN VALISS TOKEN-----\n"
        "eyJ0.eyJz.c2ln\n"
        "------END VALISS TOKEN------\n"
        "\n"
        "-----BEGIN VALISS SEED-----\n"
        f"{account.seed}\n"
        "------END VALISS SEED------\n"
        "\n"
        "************************* IMPORTANT *************************\n"
        "Seed lets anyone sign as this identity. Keep it secret.\n"
    )
    parsed = creds.parse(text)
    assert parsed.token == "eyJ0.eyJz.c2ln"
    assert parsed.seed == account.seed
