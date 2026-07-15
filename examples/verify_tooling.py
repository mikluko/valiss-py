"""Inspection tooling: per-token verification, a standalone request signature
check, and loading a creds file from disk.

These are the building blocks the Verifier composes — useful on their own for
CLIs, debugging, and tests. Unlike the Verifier they establish authenticity of
a single token (signature + type + issuer), not a full request chain.

    uv run --group dev examples/verify_tooling.py
"""

import tempfile
from datetime import timedelta
from pathlib import Path

from valiss import creds, httpauth, nkeys, token


def main() -> None:
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    user = nkeys.create_user()

    account_token = token.issue_account(
        operator, "acme", account.public_key, ttl=timedelta(hours=1)
    )
    user_token = token.issue_user(account, "alice", user.public_key, ttl=timedelta(minutes=15))

    # --- per-token verification (signature + type + issuer + subject role) ---
    acct = token.verify_account(account_token, operator.public_key)
    usr = token.verify_user(user_token, acct.subject)
    print(f"account token: name={acct.name} subject={acct.subject[:12]}… jti={acct.id[:12]}…")
    print(f"user token:    name={usr.name} bearer={usr.bearer}")

    # decode() inspects without establishing trust (checks the token's own sig).
    print(f"decode(user).issuer == account.subject: {token.decode(user_token).issuer == acct.subject}")

    # --- standalone request-signature check ---
    context = httpauth.request_context("GET", "api.example.com", "/v1/whoami")
    timestamp, signature = token.sign_request(user, context)
    token.verify_signature(user.public_key, timestamp, signature, context)
    print("request signature verifies against the subject key")

    # --- load a creds file from disk ---
    user_creds = creds.Creds(
        account_token=account_token, user_token=user_token, seed=user.seed
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "alice.creds"
        path.write_text(user_creds.format())
        loaded = creds.load(str(path))
        print(f"loaded creds from {path.name}: signer={loaded.signer().public_key[:12]}…")


if __name__ == "__main__":
    main()
