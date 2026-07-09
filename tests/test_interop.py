"""Cross-language interop: Go-minted credentials must verify in Python and
Python-minted credentials must verify in Go. Skipped when the Go toolchain
or the sibling ../valiss checkout is unavailable."""

import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from valiss import creds, nkeys, token

INTEROP_DIR = Path(__file__).parent / "interop"
VALISS_GO = Path(__file__).parent.parent.parent / "valiss"

pytestmark = pytest.mark.skipif(
    shutil.which("go") is None or not VALISS_GO.is_dir(),
    reason="requires the Go toolchain and a ../valiss checkout",
)


def _run(*args: str, stdin: str | None = None) -> str:
    proc = subprocess.run(
        ["go", "run", ".", *args],
        cwd=INTEROP_DIR,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_go_minted_credentials_verify_in_python():
    minted = json.loads(_run("mint"))
    verifier = token.Verifier(minted["operator_pub"], token.StaticAllowlist(minted["jti"]))
    now = datetime.now(timezone.utc)

    account_bundle = creds.parse(minted["account_creds"])
    timestamp, signature = token.sign_request(account_bundle.signer(), now)
    claims = verifier.verify_credential(
        token.Credential(token=account_bundle.token, timestamp=timestamp, signature=signature)
    )
    assert claims.tenant_id == "acme"
    assert claims.scopes == ["call:/v1/*"]

    user_bundle = creds.parse(minted["user_creds"])
    timestamp, signature = token.sign_request(user_bundle.signer(), now)
    claims = verifier.verify_credential(
        token.Credential(
            token=user_bundle.token,
            user_token=user_bundle.user_token,
            timestamp=timestamp,
            signature=signature,
        )
    )
    assert claims.tenant_id == "acme"
    assert claims.user_id == "alice"
    assert claims.scopes == ["call:/v1/whoami"]


def test_python_minted_credentials_verify_in_go():
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    user = nkeys.create_user()
    ttl = timedelta(hours=1)
    now = datetime.now(timezone.utc)

    tok = token.issue(operator, "acme", account.public_key, ["call:/v1/*"], ttl, now=now)
    issued = token.verify(tok, operator.public_key)

    timestamp, signature = token.sign_request(account, now)
    out = json.loads(
        _run(
            "verify",
            stdin=json.dumps(
                {
                    "operator_pub": operator.public_key,
                    "jti": issued.id,
                    "token": tok,
                    "timestamp": timestamp,
                    "signature": signature,
                }
            ),
        )
    )
    assert out == {"tenant_id": "acme", "user_id": "", "scopes": ["call:/v1/*"]}

    user_tok = token.issue_user(account, "alice", user.public_key, ["call:/v1/whoami"], ttl, now=now)
    timestamp, signature = token.sign_request(user, now)
    out = json.loads(
        _run(
            "verify",
            stdin=json.dumps(
                {
                    "operator_pub": operator.public_key,
                    "jti": issued.id,
                    "token": tok,
                    "user_token": user_tok,
                    "timestamp": timestamp,
                    "signature": signature,
                }
            ),
        )
    )
    assert out == {"tenant_id": "acme", "user_id": "alice", "scopes": ["call:/v1/whoami"]}
