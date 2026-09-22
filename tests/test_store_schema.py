import sqlite3

import pytest

from simsys_tokens.store import SCHEMA_VERSION, connect, ensure_schema
from simsys_tokens.errors import TokenError


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
