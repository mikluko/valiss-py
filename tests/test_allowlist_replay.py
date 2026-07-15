from datetime import datetime, timedelta, timezone

from valiss.allowlist import ALLOW_ALL, Allowlist, StaticAllowlist
from valiss.replay import MemoryReplayCache, ReplayCache

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)


def test_static_allowlist_membership_and_mutation():
    a = StaticAllowlist("a", "b")
    assert "a" in a and "z" not in a
    a.add("z")
    assert "z" in a
    a.discard("a")
    assert "a" not in a
    assert set(a) == {"b", "z"} and len(a) == 2
    a.replace(["only"])
    assert "only" in a and "b" not in a


def test_static_allowlist_from_file(tmp_path):
    p = tmp_path / "allow.txt"
    p.write_text("# a comment\nID1\n\n  ID2  \n#ID3\n")
    a = StaticAllowlist.from_file(str(p))
    assert "ID1" in a and "ID2" in a
    assert "ID3" not in a  # commented out
    assert len(a) == 2


def test_allow_all_and_protocols():
    assert "anything" in ALLOW_ALL
    assert isinstance(ALLOW_ALL, Allowlist)
    assert isinstance(StaticAllowlist(), Allowlist)
    assert isinstance(MemoryReplayCache(), ReplayCache)


def test_memory_replay_cache_records_and_prunes():
    cache = MemoryReplayCache(clock=lambda: NOW)
    # First use records the nonce with a future expiry, not seen before.
    assert cache.seen_before("n1", NOW + timedelta(minutes=4)) is False
    # Same nonce within its window is a replay.
    assert cache.seen_before("n1", NOW + timedelta(minutes=4)) is True
    # A distinct nonce is fine.
    assert cache.seen_before("n2", NOW + timedelta(minutes=4)) is False


def test_memory_replay_cache_expired_entry_is_not_a_replay():
    clock = {"t": NOW}
    cache = MemoryReplayCache(clock=lambda: clock["t"])
    assert cache.seen_before("n1", NOW + timedelta(minutes=1)) is False
    # Advance past the entry's expiry: it prunes and the nonce is fresh again.
    clock["t"] = NOW + timedelta(minutes=2)
    assert cache.seen_before("n1", clock["t"] + timedelta(minutes=1)) is False
