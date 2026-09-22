import dataclasses

import pytest

from simsys_tokens.core import authenticate
from simsys_tokens.store import Store, ensure_schema


@pytest.fixture()
def store(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    return Store(db, "demo")


def test_valid_bearer_resolves(store):
    raw, handle = store.mint("agent", "scout", "cli:leon@dev")
    info = authenticate(store, f"Bearer {raw}")
    assert (info.handle, info.role, info.label) == (handle, "agent", "scout")


def test_token_info_carries_no_raw_secret(store):
    raw, _ = store.mint("agent", "scout", "cli:leon@dev")
    info = authenticate(store, f"Bearer {raw}")
    values = [str(v) for v in dataclasses.asdict(info).values()]
    assert all(raw not in v for v in values), "TokenInfo leaked the raw token"


def test_revoke_takes_effect_without_restart(store):
    raw, handle = store.mint("agent", "scout", "cli:leon@dev")
    assert authenticate(store, f"Bearer {raw}") is not None
    store.revoke(handle, "session:leon")
    assert authenticate(store, f"Bearer {raw}") is None


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer nope", "bearer lowercase"])
def test_non_resolving_headers_return_none(store, header):
    assert authenticate(store, header) is None


def test_first_use_populates_last_used_at(store):
    raw, handle = store.mint("agent", "scout", "cli:leon@dev")
    assert store.resolve_handle(handle)["last_used_at"] is None
    authenticate(store, f"Bearer {raw}")
    assert store.resolve_handle(handle)["last_used_at"] is not None


def test_malformed_bearer_never_reaches_hash_or_db(store, monkeypatch):
    # A malformed shape can never resolve: it must fail closed BEFORE sha256
    # (CPU-DoS guard) and before SQLite. Patch token_hash to blow up if called.
    import simsys_tokens.core as core

    def _boom(raw):
        raise AssertionError("hash called on malformed input")

    monkeypatch.setattr(core, "token_hash", _boom)
    assert authenticate(store, "Bearer nope") is None
    assert authenticate(store, "Bearer demo-bad-role-x") is None


def test_overlong_bearer_is_rejected_without_hashing(store, monkeypatch):
    import simsys_tokens.core as core

    monkeypatch.setattr(
        core,
        "token_hash",
        lambda raw: (_ for _ in ()).throw(AssertionError("hash called on overlong input")),
    )
    assert authenticate(store, "Bearer " + "a" * 10000) is None


def test_touch_map_is_bounded(store):

    raw, _ = store.mint("agent", "scout", "cli:leon@dev")
    # Fill past the cap with junk keys, then authenticate once: the map must
    # evict oldest-first instead of growing without bound under scanner traffic.
    for i in range(6000):
        store.last_touch[f"junk{i:06d}"] = 0.0
    authenticate(store, f"Bearer {raw}")
    assert len(store.last_touch) <= 5000 + 1
