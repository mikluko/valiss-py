"""Port of valiss-go keyring_test.go and chain_test.go: multi-operator keyring
verification (requests and message tokens) and the chain cache.

Negative cases assert the spec §7 reason code. Two operators share the tenant
name "acme"; consumers tell them apart by Identity.operator.name — the keyring
guarantees a name maps to exactly one operator key.
"""

from datetime import datetime, timedelta, timezone

import pytest

from valiss import message, nkeys, token
from valiss.allowlist import ALLOW_ALL, StaticAllowlist
from valiss.chain import MemoryChainCache
from valiss.errors import Reason, ValissError
from valiss.keyring import Keyring
from valiss.verifier import Request, Verifier, static_account_tokens

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


class Domain:
    """A full trust domain: keys, chain tokens, and the operator token, at one epoch."""

    def __init__(self, name, epoch, *, op=None, account=None, user=None, op_ttl=None, now=NOW):
        self.op = op or nkeys.create_operator()
        self.account = account or nkeys.create_account()
        self.user = user or nkeys.create_user()
        self.name = name
        self.epoch = epoch
        self.operator_token = token.issue_operator(
            self.op, name=name, epoch=epoch, ttl=op_ttl, now=now
        )
        self.account_token = token.issue_account(
            self.op, "acme", self.account.public_key, epoch=epoch, ttl=HOUR, now=now
        )
        self.user_token = token.issue_user(
            self.account, "alice", self.user.public_key, epoch=epoch, ttl=HOUR, now=now
        )

    @property
    def op_pub(self):
        return self.op.public_key

    def reissue(self, epoch, *, name=None, op_ttl=None, now=NOW):
        return Domain(
            name or self.name, epoch, op=self.op, account=self.account, user=self.user,
            op_ttl=op_ttl, now=now,
        )

    def request(self, at=NOW):
        ts, sig = token.sign_request(self.user, b"", at)
        return Request(
            account_token=self.account_token, user_token=self.user_token,
            timestamp=ts, signature=sig,
        )

    def message(self, epoch=None, now=NOW):
        return message.issue_message(
            self.user, chain=(self.account_token, self.user_token),
            epoch=self.epoch if epoch is None else epoch, ttl=timedelta(minutes=1), now=now,
        )


# -------- Keyring construction --------


def test_keyring_selects_by_key_and_epoch():
    a4 = Domain("prod-us", 4)
    a5 = a4.reissue(5)
    b = Domain("on-prem", 0)
    k = Keyring(a4.operator_token, a5.operator_token, b.operator_token)
    assert k.get(a4.op_pub, 4).name == "prod-us"
    assert k.get(a4.op_pub, 5) is not None  # grace: same key, two epochs
    assert k.get(a4.op_pub, 6) is None  # unregistered epoch
    assert k.get(b.op_pub, 0) is not None
    assert k.get("OUNKNOWN", 0) is None


def test_keyring_identical_token_collapses():
    a = Domain("prod-us", 4)
    assert len(Keyring(a.operator_token, a.operator_token)) == 1


def test_keyring_duplicate_entry_rejected():
    a = Domain("prod-us", 4)
    reissued = token.issue_operator(a.op, name="prod-us", epoch=4, ttl=HOUR, now=NOW)
    with pytest.raises(ValissError, match="duplicate entry for operator"):
        Keyring(a.operator_token, reissued)


def test_keyring_two_operators_sharing_a_name_rejected():
    a = Domain("prod-us", 4)
    b = Domain("on-prem", 0)
    impostor = token.issue_operator(b.op, name="prod-us", now=NOW)
    with pytest.raises(ValissError, match="already names a different operator"):
        Keyring(a.operator_token, impostor)


def test_keyring_operator_disagreeing_on_name_rejected():
    a = Domain("prod-us", 4)
    renamed = token.issue_operator(a.op, name="prod-eu", epoch=5, now=NOW)
    with pytest.raises(ValissError, match="entries disagree on name"):
        Keyring(a.operator_token, renamed)


def test_keyring_unnamed_operator_represented_by_key():
    op = nkeys.create_operator()
    bare = token.issue_operator(op, now=NOW)
    k = Keyring(bare)
    assert k.get(op.public_key, 0).name == op.public_key


def test_keyring_empty_rejected():
    with pytest.raises(ValissError, match="no operator tokens"):
        Keyring()


def test_keyring_garbage_token_rejected():
    with pytest.raises(ValissError, match="operator token 0"):
        Keyring("garbage")


def test_keyring_non_operator_token_rejected():
    a = Domain("prod-us", 4)
    with pytest.raises(ValissError, match="not an operator token"):
        Keyring(a.account_token)


# -------- Message-token keyring verification --------


def test_verify_message_keyring_both_domains():
    a = Domain("prod-us", 4)
    b = Domain("on-prem", 0)
    k = Keyring(a.operator_token, b.operator_token)
    ca = message.verify_message(a.message(), keyring=k, now=NOW)
    assert ca.operator.name == "prod-us" and ca.account.name == "acme"
    cb = message.verify_message(b.message(), keyring=k, now=NOW)
    assert cb.operator.name == "on-prem" and cb.account.name == "acme"


def test_verify_message_keyring_unknown_operator():
    a = Domain("prod-us", 4)
    k = Keyring(a.operator_token)
    stranger = Domain("stranger", 0)
    with pytest.raises(ValissError) as exc:
        message.verify_message(stranger.message(), keyring=k, now=NOW)
    assert exc.value.reason == Reason.UNKNOWN_OPERATOR


def test_verify_message_keyring_unregistered_epoch():
    a = Domain("prod-us", 4)
    k = Keyring(a.operator_token)
    nxt = a.reissue(5)
    with pytest.raises(ValissError, match="at epoch 5") as exc:
        message.verify_message(nxt.message(), keyring=k, now=NOW)
    assert exc.value.reason == Reason.UNKNOWN_OPERATOR


def test_verify_message_keyring_grace_then_close():
    a = Domain("prod-us", 4)
    nxt = a.reissue(5)
    graceful = Keyring(a.operator_token, nxt.operator_token)
    message.verify_message(a.message(), keyring=graceful, now=NOW)
    message.verify_message(nxt.message(), keyring=graceful, now=NOW)

    # A short-lived old-epoch entry closes the grace window on its own.
    bounded = a.reissue(4, op_ttl=timedelta(minutes=1))
    closing = Keyring(bounded.operator_token, nxt.operator_token)
    with pytest.raises(ValissError) as exc:
        message.verify_message(a.message(), keyring=closing, now=NOW + HOUR, skew=timedelta(0))
    assert exc.value.reason == Reason.EXPIRED
    assert "trust domain is closed" in str(exc.value)


def test_verify_message_keyring_operator_policy_rejected():
    a = Domain("prod-us", 4)
    k = Keyring(a.operator_token)
    with pytest.raises(ValissError, match="keyring entries carry policy"):
        message.verify_message(a.message(), keyring=k, operator_token=a.operator_token, now=NOW)


def test_verify_message_single_anchor_operator_policy():
    a = Domain("prod-us", 4)
    with_policy = message.verify_message(
        a.message(), a.op_pub, operator_token=a.operator_token, now=NOW
    )
    assert with_policy.operator is not None and with_policy.operator.name == "prod-us"
    plain = message.verify_message(a.message(), a.op_pub, now=NOW)
    assert plain.operator is None


# -------- Keyring request Verifier --------


def test_keyring_verifier_both_domains():
    a = Domain("prod-us", 4)
    b = Domain("on-prem", 0)
    v = Verifier.with_keyring(Keyring(a.operator_token, b.operator_token), ALLOW_ALL, clock=lambda: NOW)
    ida = v.verify(a.request())
    assert ida.operator.name == "prod-us" and ida.account.name == "acme" and ida.user.name == "alice"
    idb = v.verify(b.request())
    assert idb.operator.name == "on-prem" and idb.account.name == "acme"


def test_keyring_verifier_unknown_and_epoch():
    a = Domain("prod-us", 4)
    v = Verifier.with_keyring(Keyring(a.operator_token), ALLOW_ALL, clock=lambda: NOW)
    with pytest.raises(ValissError) as exc:
        v.verify(Domain("stranger", 0).request())
    assert exc.value.reason == Reason.UNKNOWN_OPERATOR
    with pytest.raises(ValissError, match="at epoch 5") as exc:
        v.verify(a.reissue(5).request())
    assert exc.value.reason == Reason.UNKNOWN_OPERATOR


def test_keyring_verifier_grace_period():
    a = Domain("prod-us", 4)
    nxt = a.reissue(5)
    v = Verifier.with_keyring(Keyring(a.operator_token, nxt.operator_token), ALLOW_ALL, clock=lambda: NOW)
    v.verify(a.request())
    v.verify(nxt.request())


def test_keyring_verifier_entry_window_enforced():
    b = Domain("on-prem", 0)
    bounded = b.reissue(0, op_ttl=timedelta(minutes=1))
    later = NOW + HOUR
    v = Verifier.with_keyring(
        Keyring(bounded.operator_token), ALLOW_ALL, skew=timedelta(0), clock=lambda: later
    )
    with pytest.raises(ValissError) as exc:
        v.verify(b.request(at=later))
    assert exc.value.reason == Reason.EXPIRED
    assert "trust domain is closed" in str(exc.value)


def test_keyring_verifier_user_epoch_must_echo_entry():
    a = Domain("prod-us", 4)
    v = Verifier.with_keyring(Keyring(a.operator_token), ALLOW_ALL, clock=lambda: NOW)
    stale = token.issue_user(a.account, "alice", a.user.public_key, epoch=3, ttl=HOUR, now=NOW)
    ts, sig = token.sign_request(a.user, b"", NOW)
    with pytest.raises(ValissError, match="user token epoch 3, trust domain epoch 4") as exc:
        v.verify(Request(account_token=a.account_token, user_token=stale, timestamp=ts, signature=sig))
    assert exc.value.reason == Reason.EPOCH_MISMATCH


def test_keyring_verifier_allowlist_shared_across_domains():
    a = Domain("prod-us", 4)
    b = Domain("on-prem", 0)
    k = Keyring(a.operator_token, b.operator_token)
    account_a = token.verify_account(a.account_token, a.op_pub)
    strict = Verifier.with_keyring(k, StaticAllowlist(account_a.id), clock=lambda: NOW)
    strict.verify(a.request())
    with pytest.raises(ValissError) as exc:
        strict.verify(b.request())
    assert exc.value.reason == Reason.NOT_ALLOWLISTED


def test_keyring_verifier_user_only_resolves_through_keyring():
    a = Domain("prod-us", 4)
    b = Domain("on-prem", 0)
    k = Keyring(a.operator_token, b.operator_token)
    resolver = static_account_tokens(a.account_token, b.account_token)
    v = Verifier.with_keyring(k, ALLOW_ALL, clock=lambda: NOW, resolver=resolver)
    ts, sig = token.sign_request(a.user, b"", NOW)
    idn = v.verify(Request(user_token=a.user_token, timestamp=ts, signature=sig))
    assert idn.operator.name == "prod-us"


def test_single_anchor_verifier_exposes_policy_operator():
    a = Domain("prod-us", 4)
    single = Verifier(a.op_pub, ALLOW_ALL, clock=lambda: NOW, operator_token=a.operator_token)
    idn = single.verify(a.request())
    assert idn.operator is not None and idn.operator.name == "prod-us"
    plain = Verifier(a.op_pub, ALLOW_ALL, clock=lambda: NOW)
    assert plain.verify(a.request()).operator is None


# -------- Chain cache --------


def test_memory_chain_cache():
    cache = MemoryChainCache()
    assert cache.get("U1") is None
    cache.put("U1", "acct-tok", "user-tok")
    assert cache.get("U1") == ("acct-tok", "user-tok")
    cache.put("U1", "acct2", "user2")  # overwrite
    assert cache.get("U1") == ("acct2", "user2")
    cache.delete("U1")
    assert cache.get("U1") is None


def test_memory_chain_cache_lru_hit_promotes(monkeypatch):
    # A hit keeps an entry warm: under pressure the untouched one is evicted.
    monkeypatch.setattr("valiss.chain._MEMORY_CHAIN_CACHE_CAP", 2)
    cache = MemoryChainCache()
    cache.put("A", "a", "a")
    cache.put("B", "b", "b")  # full at [A, B]
    assert cache.get("A") == ("a", "a")  # promotes A to most-recently-used
    cache.put("C", "c", "c")  # evicts the least-recently-used, B
    assert cache.get("B") is None
    assert cache.get("A") == ("a", "a")  # the recently-used entry survived
    assert cache.get("C") == ("c", "c")


def test_memory_chain_cache_lru_put_refreshes(monkeypatch):
    # Re-negotiating (a repeat put) also refreshes recency.
    monkeypatch.setattr("valiss.chain._MEMORY_CHAIN_CACHE_CAP", 2)
    cache = MemoryChainCache()
    cache.put("A", "a", "a")
    cache.put("B", "b", "b")
    cache.put("A", "a2", "a2")  # refresh A -> [B, A]
    cache.put("C", "c", "c")  # evicts B
    assert cache.get("B") is None
    assert cache.get("A") == ("a2", "a2")
    assert cache.get("C") == ("c", "c")
