import pytest

from simsys_tokens.hashing import token_hash
from simsys_tokens.store import NoSuchHandle, Store, ensure_schema


@pytest.fixture()
def store(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    return Store(db, "demo")


def test_mint_returns_a_usable_token_and_stores_only_its_digest(store, tmp_path):
    raw, handle = store.mint("agent", "scout", "cli:leon@dev")
    assert raw.startswith("demo-agent-")
    assert handle == token_hash(raw)[:16]
    # The raw value must not be anywhere in the file.
    assert raw.encode() not in (tmp_path / "tokens.db").read_bytes()


def test_lookup_live_finds_it(store):
    raw, _ = store.mint("agent", "scout", "cli:leon@dev")
    assert store.lookup_live(token_hash(raw))["role"] == "agent"


def test_lookup_is_service_scoped(tmp_path):
    db = tmp_path / "shared.db"
    ensure_schema(db, create=True)
    a, b = Store(db, "alpha"), Store(db, "beta")
    raw, _ = a.mint("agent", "x", "cli:leon@dev")
    assert a.lookup_live(token_hash(raw)) is not None
    assert b.lookup_live(token_hash(raw)) is None


def test_revoke_is_immediate_and_soft(store):
    raw, handle = store.mint("agent", "scout", "cli:leon@dev")
    store.revoke(handle, "session:leon")
    assert store.lookup_live(token_hash(raw)) is None
    rows, _ = store.list_rows(include_revoked=True)
    assert len(rows) == 1 and rows[0]["revoked_by"] == "session:leon"


def test_second_revoke_does_not_rewrite_the_revoker(store):
    _, handle = store.mint("agent", "scout", "cli:leon@dev")
    _, first_changed = store.revoke(handle, "session:leon")
    _, second_changed = store.revoke(handle, "session:someone_else")
    assert first_changed is True and second_changed is False
    rows, _ = store.list_rows(include_revoked=True)
    assert rows[0]["revoked_by"] == "session:leon"


def test_list_defaults_to_live_only(store):
    _, h1 = store.mint("agent", "a", "cli:leon@dev")
    store.mint("agent", "b", "cli:leon@dev")
    store.revoke(h1, "session:leon")
    live, _ = store.list_rows()
    assert [r["label"] for r in live] == ["b"]


def test_list_reports_has_more(store):
    for i in range(5):
        store.mint("agent", f"t{i}", "cli:leon@dev")
    rows, has_more = store.list_rows(limit=3)
    assert len(rows) == 3 and has_more is True
    rows, has_more = store.list_rows(limit=50)
    assert len(rows) == 5 and has_more is False


@pytest.mark.parametrize("bad_limit", [-1, 0, -500])
def test_hostile_limits_are_clamped_not_passed_through(store, bad_limit):
    # SQLite reads a negative LIMIT as "no limit", so an unclamped -1 would dump
    # the entire roster to a caller who asked for a page.
    for i in range(5):
        store.mint("agent", f"t{i}", "cli:leon@dev")
    rows, has_more = store.list_rows(limit=bad_limit)
    assert len(rows) == 1 and has_more is True


def test_connections_do_not_leak(store, tmp_path):
    # sqlite3's context manager commits but does not close. 200 calls against a
    # default 1024-fd ulimit is a comfortable margin for detecting a leak.
    for _ in range(200):
        store.list_rows()
    import os

    assert len(os.listdir(f"/proc/{os.getpid()}/fd")) < 200


def test_unknown_handle_raises(store):
    with pytest.raises(NoSuchHandle):
        store.resolve_handle("0" * 16)


def test_touch_last_used_sets_it_once_populated(store):
    raw, handle = store.mint("agent", "scout", "cli:leon@dev")
    assert store.resolve_handle(handle)["last_used_at"] is None
    store.touch_last_used(token_hash(raw))
    assert store.resolve_handle(handle)["last_used_at"] is not None


def test_live_label_uniqueness_is_queryable(store):
    store.mint("agent", "scout", "cli:leon@dev")
    assert store.live_label_exists("scout") is True
    assert store.live_label_exists("other") is False


def test_a_revoked_label_frees_up(store):
    _, handle = store.mint("agent", "scout", "cli:leon@dev")
    store.revoke(handle, "session:leon")
    assert store.live_label_exists("scout") is False


def test_list_rows_filters_by_label(store):
    store.mint("agent", "alpha", "cli:leon@dev")
    store.mint("agent", "beta", "cli:leon@dev")
    rows, _ = store.list_rows(label="alpha")
    assert [r["label"] for r in rows] == ["alpha"]
    rows, _ = store.list_rows(label="nope")
    assert rows == []


def test_mint_with_expires_at_is_not_live(store):
    from simsys_tokens.store import is_expired

    raw, handle = store.mint("agent", "old", "cli:leon@dev", expires_at="2000-01-01T00:00:00+00:00")
    assert store.lookup_live(token_hash(raw)) is None
    row = store.find_any(token_hash(raw))
    assert row is not None and row["revoked_at"] is None
    assert is_expired(row["expires_at"]) is True


def test_a_future_expiry_still_authenticates(store):
    raw, _ = store.mint("agent", "later", "cli:leon@dev", expires_at="2999-01-01T00:00:00+00:00")
    assert store.lookup_live(token_hash(raw)) is not None


@pytest.mark.parametrize("bad", ["not a time", "", 123, "2026-13-45T00:00:00"])
def test_bad_expires_at_is_rejected(store, bad):
    with pytest.raises(ValueError):
        store.mint("agent", "x", "cli:leon@dev", expires_at=bad)


def test_expires_at_is_normalised_to_utc(store):
    raw, _ = store.mint("agent", "tz", "cli:leon@dev", expires_at="2999-01-01T00:00:00-05:00")
    assert store.find_any(token_hash(raw))["expires_at"] == "2999-01-01T05:00:00+00:00"


def test_naive_expiry_is_assumed_utc(store):
    raw, _ = store.mint("agent", "naive", "cli:leon@dev", expires_at="2999-01-01T00:00:00")
    assert store.find_any(token_hash(raw))["expires_at"] == "2999-01-01T00:00:00+00:00"


def test_touch_eviction_refreshes_recency(store):
    # A re-emitted key must move to the newest end, or it can be evicted as if
    # it were the oldest. pop-then-set in _touch_note is what fixes that.
    store.touch_map_max = 2
    store._touch_note(store.last_touch, "a", 1.0)
    store._touch_note(store.last_touch, "b", 2.0)
    store._touch_note(store.last_touch, "a", 3.0)  # refresh "a"
    store._touch_note(store.last_touch, "c", 4.0)  # must evict "b", not "a"
    assert list(store.last_touch) == ["a", "c"]


def test_max_limit_is_per_store(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    small = Store(db, "demo", max_limit=2)
    for i in range(3):
        small.mint("agent", f"t{i}", "cli:leon@dev")
    rows, has_more = small.list_rows(limit=999)
    assert len(rows) == 2 and has_more is True
