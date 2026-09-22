import pytest

from simsys_tokens.hashing import token_hash
from simsys_tokens.importer import import_entries
from simsys_tokens.store import Store, ensure_schema

RAW = "demo-agent-" + "b" * 64


@pytest.fixture()
def store(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    return Store(db, "demo")


def test_imports_a_raw_key(store):
    report = import_entries(store, [{"role": "agent", "key": RAW}])
    assert report.imported == 1
    assert store.lookup_live(token_hash(RAW))["label"] == "imported:agent"


def test_imports_a_precomputed_digest(store):
    # A config may hold no raw token at all, only its digest.
    digest = token_hash(RAW)
    assert import_entries(store, [{"role": "agent", "key_sha256": digest}]).imported == 1
    assert store.lookup_live(digest) is not None


def test_import_leaves_last_used_at_null(store):
    import_entries(store, [{"role": "agent", "key": RAW}])
    assert store.lookup_live(token_hash(RAW))["last_used_at"] is None


def test_reimport_is_idempotent_on_the_secret(store):
    import_entries(store, [{"role": "agent", "key": RAW}])
    report = import_entries(store, [{"role": "agent", "key": RAW}])
    assert report.imported == 0
    rows, _ = store.list_rows()
    assert len(rows) == 1


def test_reimport_upserts_policy_columns(store):
    import_entries(store, [{"role": "agent", "key": RAW, "priority": 5}])
    report = import_entries(store, [{"role": "agent", "key": RAW, "priority": 1}])
    assert report.updated == 1
    assert store.lookup_live(token_hash(RAW))["priority"] == 1


def test_reimport_does_not_rewrite_label_or_created_by(store):
    import_entries(store, [{"role": "agent", "key": RAW, "label": "original"}])
    import_entries(store, [{"role": "agent", "key": RAW, "label": "changed"}])
    assert store.lookup_live(token_hash(RAW))["label"] == "original"


def test_a_bad_role_is_skipped_and_reported_not_raised(store):
    report = import_entries(store, [{"role": "bad-role", "key": RAW}])
    assert report.imported == 0 and len(report.rejected) == 1
    rows, _ = store.list_rows()
    assert rows == []


def test_a_colliding_live_label_is_skipped_and_reported(store):
    store.mint("agent", "taken", "cli:leon@dev")
    other = "demo-agent-" + "c" * 64
    report = import_entries(store, [{"role": "agent", "key": other, "label": "taken"}])
    assert report.imported == 0 and len(report.rejected) == 1


def test_declaring_both_forms_is_rejected(store):
    report = import_entries(store, [{"role": "agent", "key": RAW, "key_sha256": token_hash(RAW)}])
    assert report.imported == 0 and "exactly one" in report.rejected[0][1]


@pytest.mark.parametrize("bad_digest", ["a" * 63, "a" * 65, "A" * 64, "zz" + "a" * 62, ""])
def test_malformed_key_sha256_is_rejected(store, bad_digest):
    # An unvalidated digest stores a row that can never match a real token:
    # the caller's auth then fails forever with nothing to point at.
    report = import_entries(store, [{"role": "agent", "key_sha256": bad_digest}])
    assert report.imported == 0
    assert "64 lowercase hex" in report.rejected[0][1]


@pytest.mark.parametrize("bad_key", ["", None, 123])
def test_a_malformed_key_is_rejected_not_raised(store, bad_key):
    # import_entries runs inside install_tokens() at startup. An unset env var
    # interpolated to "" must not take the host app down.
    report = import_entries(store, [{"role": "agent", "key": bad_key}])
    assert report.imported == 0 and report.rejected


def test_import_validates_policy_like_the_endpoint_does(store):
    report = import_entries(store, [{"role": "agent", "key": RAW, "priority": "high"}])
    assert report.imported == 0 and "priority" in report.rejected[0][1]


def test_concurrent_same_secret_is_idempotent_not_a_label_conflict(store, monkeypatch):
    # Multi-worker boot runs import in every worker. Loser of a same-digest
    # race (find_any saw None, INSERT hits the PK) must converge to the
    # upsert path, not to a spurious "label in use" rejection.
    from simsys_tokens.hashing import token_hash as _th

    digest = _th(RAW)
    store.insert_digest(digest, "agent", "imported:agent", "config-import", None, None)
    real_find = store.find_any
    calls = {"n": 0}

    def _lying_find(d):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # as the loser saw before the winner committed
        return real_find(d)

    monkeypatch.setattr(store, "find_any", _lying_find)
    report = import_entries(store, [{"role": "agent", "key": RAW}])
    assert report.imported == 0 and report.rejected == []
