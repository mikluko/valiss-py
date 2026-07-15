"""Server-side request verification with the integrated Verifier.

A Python service turns the credential headers off an incoming request into a
verified identity itself — no round-trip to Go. This shows the whole loop:
mint an account + delegated user, sign a request on the client, and verify it
on the server, including allowlist revocation and replay suppression.

    uv run --group dev examples/verify_request.py
"""

from datetime import timedelta

from valiss import httpauth, nkeys, token
from valiss.allowlist import StaticAllowlist
from valiss.errors import ValissError
from valiss.replay import MemoryReplayCache
from valiss.verifier import Request, Verifier


def main() -> None:
    # --- issuer setup (stands in for the operator's offline key + the CLI) ---
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    account_token = token.issue_account(
        operator, "acme", account.public_key, ttl=timedelta(hours=1)
    )
    account_jti = token.verify_account(account_token, operator.public_key).id

    # A delegated signing user, bound to an HTTP extension the server enforces.
    user = nkeys.create_user()
    user_token = token.issue_user(
        account, "alice", user.public_key,
        ttl=timedelta(minutes=15), extensions=[httpauth.Ext(paths=["/v1/*"])],
    )

    # --- server: pin the operator key, allowlist the account, suppress replay ---
    allowlist = StaticAllowlist(account_jti)
    verifier = Verifier(
        operator.public_key, allowlist, replay_cache=MemoryReplayCache()
    )

    # A custom check runs only after possession is proven.
    @verifier.validator
    def tenant_is_active(_request: Request, identity: object) -> None:
        pass  # e.g. look identity.account.name up in a tenant directory

    # --- client: sign a request bound to method/host/path + a fresh nonce ---
    def make_request() -> Request:
        nonce = token.new_nonce()
        context = httpauth.request_context("GET", "api.example.com", "/v1/whoami", nonce)
        timestamp, signature = token.sign_request(user, context)
        return Request(
            account_token=account_token, user_token=user_token,
            timestamp=timestamp, signature=signature, context=context, nonce=nonce,
        )

    identity = verifier.verify(make_request())
    print(f"verified: user={identity.user.name} account={identity.account.name}")

    # Replay: the SAME request a second time is rejected by the nonce cache.
    replayed = make_request()
    verifier.verify(replayed)
    try:
        verifier.verify(replayed)
        raise SystemExit("replay should have been rejected")
    except ValissError as exc:
        print(f"replay rejected: reason={exc.reason}")

    # Revocation: drop the account id from the allowlist and every request fails.
    allowlist.discard(account_jti)
    try:
        verifier.verify(make_request())
        raise SystemExit("revoked account should have been rejected")
    except ValissError as exc:
        print(f"revoked account rejected: reason={exc.reason}")


if __name__ == "__main__":
    main()
