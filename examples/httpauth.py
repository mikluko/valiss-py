"""Full tenant-auth wiring for HTTP: an operator signs a scoped account
token, the server checks every request through the verifier, and the client
signs every request via the httpx auth hook. Runs self-contained against a
local listener.

    uv run --group dev examples/httpauth.py
"""

import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from valiss import ValissError, creds, httpauth, nkeys, token


def main() -> None:
    # Operator side: mint the trust anchor, a tenant account key, and a
    # scoped account token, bundled the same way the valiss CLI ships it to
    # a client.
    operator = nkeys.create_operator()
    account = nkeys.create_account()

    tok = token.issue(operator, "acme", account.public_key, ["call:/v1/*"], timedelta(hours=1))
    claims = token.verify(tok, operator.public_key)
    bundle_text = creds.Bundle(token=tok, seed=account.seed).format()

    # Server side: the operator public key and the allowlist are all the
    # server needs; it never sees any seeds.
    verifier = token.Verifier(operator.public_key, token.StaticAllowlist(claims.id))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            cred = httpauth.extract_credential(self.headers)
            if not cred.token:
                self.reply(401, "missing tenant credential\n")
                return
            try:
                claims = verifier.verify_credential(cred)
            except ValissError as exc:
                self.reply(401, f"{exc}\n")
                return
            scope = httpauth.scope_for_path(self.path)
            if not claims.authorizes(scope):
                self.reply(403, f"tenant lacks scope {scope}\n")
                return
            print(f'server: tenant "{claims.tenant_id}" calls {self.path}')
            self.reply(200, f'hello, tenant "{claims.tenant_id}"\n')

        def reply(self, status: int, body: str) -> None:
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    try:
        # Client side: parse the creds bundle and sign every request via the
        # auth hook.
        client_bundle = creds.parse(bundle_text)
        client = httpx.Client(auth=httpauth.Auth(client_bundle))

        resp = client.get(f"{base}/v1/whoami")
        assert resp.status_code == 200, f"expected 200 for the in-scope request, got {resp}"
        print(f"in-scope request allowed as expected: {resp.status_code} -> {resp.text}", end="")

        # A path outside the granted scope is denied.
        resp = client.get(f"{base}/admin/")
        assert resp.status_code == 403, f"expected 403 for the out-of-scope path, got {resp}"
        print("out-of-scope path denied as expected:", resp.status_code)

        # No credential at all is rejected outright.
        resp = httpx.get(f"{base}/v1/whoami")
        assert resp.status_code == 401, f"expected 401 without a credential, got {resp}"
        print("missing credential rejected as expected:", resp.status_code)
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main()
