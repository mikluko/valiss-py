"""Client credential bundle file: the tokens a client presents plus the seed
that signs its requests, modeled on the nsc creds format. A bundle is
everything a client needs. File-compatible with valiss's Go pkg/creds.

An account-level bundle holds the operator-signed tenant token and the
account seed. A user-level bundle additionally holds the account-signed user
token, and its seed is the user's. A bearer bundle carries tokens only: its
holder cannot sign requests and the server accepts it only when the token
grants the bearer scope.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import nkeys
from .errors import ValissError

_TOKEN_BEGIN = "-----BEGIN VALISS TOKEN-----"
_TOKEN_END = "------END VALISS TOKEN------"
_USER_TOKEN_BEGIN = "-----BEGIN VALISS USER TOKEN-----"
_USER_TOKEN_END = "------END VALISS USER TOKEN------"
_SEED_BEGIN = "-----BEGIN VALISS SEED-----"
_SEED_END = "------END VALISS SEED------"


@dataclass
class Bundle:
    """Parsed content of a creds file."""

    # token is the operator-signed tenant token, present in every bundle.
    token: str
    # user_token is the account-signed user token; empty in account-level
    # bundles.
    user_token: str = ""
    # seed signs requests as the bundle's subject: the account seed in an
    # account-level bundle, the user seed in a user-level one. Empty in
    # bearer bundles.
    seed: str = ""

    def signer(self) -> nkeys.KeyPair | None:
        """Key pair from the bundle seed; None for bearer bundles."""
        if not self.seed:
            return None
        try:
            return nkeys.from_seed(self.seed)
        except ValissError as exc:
            raise ValissError(f"valiss: creds seed: {exc}") from exc

    def format(self) -> str:
        """Render the creds file for the bundle."""
        out = f"{_TOKEN_BEGIN}\n{self.token.strip()}\n{_TOKEN_END}\n"
        if self.user_token:
            out += f"\n{_USER_TOKEN_BEGIN}\n{self.user_token.strip()}\n{_USER_TOKEN_END}\n"
        if self.seed:
            out += f"\n{_SEED_BEGIN}\n{self.seed.strip()}\n{_SEED_END}\n"
            out += (
                "\n************************* IMPORTANT *************************\n"
                "Seed lets anyone sign as this identity. Keep it secret.\n"
            )
        return out


def parse(contents: str) -> Bundle:
    """Extract the bundle from a creds file's contents. The tenant token is
    required; the user token and seed sections are optional."""
    token, ok = _between(contents, _TOKEN_BEGIN, _TOKEN_END, "creds token")
    if not ok:
        raise ValissError(f'valiss: creds token: marker "{_TOKEN_BEGIN}" not found')
    user_token, ok = _between(contents, _USER_TOKEN_BEGIN, _USER_TOKEN_END, "creds user token")
    seed, ok_seed = _between(contents, _SEED_BEGIN, _SEED_END, "creds seed")
    return Bundle(token=token, user_token=user_token if ok else "", seed=seed if ok_seed else "")


def load(path: str) -> Bundle:
    """Read and parse a creds file."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except OSError as exc:
        raise ValissError(f"valiss: read creds: {exc}") from exc
    return parse(raw)


def _between(contents: str, begin: str, end: str, what: str) -> tuple[str, bool]:
    """First non-empty line strictly between a begin and end marker. The
    bool is False when the begin marker is absent; a present but empty or
    unclosed section is an error."""
    inside = False
    for line in contents.splitlines():
        line = line.strip()
        if line == begin:
            inside = True
        elif inside and line == end:
            raise ValissError(f'valiss: {what}: no content before "{end}"')
        elif inside and line:
            return line, True
    if inside:
        raise ValissError(f'valiss: {what}: marker "{begin}" not closed')
    return "", False
