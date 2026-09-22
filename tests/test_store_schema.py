import sqlite3

import pytest

from simsys_tokens.errors import TokenError
from simsys_tokens.store import SCHEMA_VERSION, connect, ensure_schema


def test_create_true_makes_the_file(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    assert db.exists()


def test_create_false_refuses_a_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        ensure_schema(tmp_path / "nope.db", create=False)


def test_is_idempotent(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    ensure_schema(db, create=True)
    with connect(db) as c:
        assert c.execute("SELECT COUNT(*) FROM _schema_version").fetchone()[0] == 1


def test_schema_version_table_is_single_row_by_construction(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    with connect(db) as c:
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("INSERT INTO _schema_version (id, version) VALUES (2, 99)")


def test_a_newer_store_is_a_hard_error(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    with connect(db) as c:
        c.execute("UPDATE _schema_version SET version = ?", (SCHEMA_VERSION + 1,))
        c.commit()
    with pytest.raises(TokenError, match="newer"):
        ensure_schema(db, create=False)


def test_handle_index_exists_and_rerun_heals_it(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    with connect(db) as c:
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_tokens_handle" in names
        # Simulate a pre-index store: drop it, re-run, it must come back via
        # IF NOT EXISTS (the upgrade path for already-adopted stores).
        c.execute("DROP INDEX idx_tokens_handle")
    ensure_schema(db, create=False)
    with connect(db) as c:
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_tokens_handle" in names


def test_store_is_created_0600(tmp_path):
    # The store holds digests, labels and actors — not raw secrets — but a
    # world-readable token roster is still the wrong default.
    import os
    import stat

    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    assert stat.S_IMODE(os.stat(db).st_mode) == 0o600


@pytest.mark.skipif(sqlite3.sqlite_version_info < (3, 35), reason="DROP COLUMN needs sqlite 3.35+")
def test_a_v1_store_migrates_to_v2(tmp_path):
    # Build a v2 store, then walk it back to v1 as if it predated expires_at.
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    with connect(db) as c:
        c.execute("ALTER TABLE tokens DROP COLUMN expires_at")
        c.execute("UPDATE _schema_version SET version = 1")
    ensure_schema(db, create=False)
    with connect(db) as c:
        cols = {row[1] for row in c.execute("PRAGMA table_info(tokens)")}
        version = c.execute("SELECT version FROM _schema_version").fetchone()[0]
    assert "expires_at" in cols, "the migration did not add the column"
    assert version == SCHEMA_VERSION, "the version row was not advanced"


def test_migration_converges_on_rerun(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    ensure_schema(db, create=False)
    ensure_schema(db, create=False)
    with connect(db) as c:
        assert c.execute("SELECT COUNT(*) FROM _schema_version").fetchone()[0] == 1
        assert c.execute("SELECT version FROM _schema_version").fetchone()[0] == SCHEMA_VERSION
