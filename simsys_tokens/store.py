"""The token store: schema, migrations and row access.

ensure_schema() is the ONE creation/migration routine. install_tokens() and every
CLI subcommand call it — on a fresh install the bootstrap token is minted before
the service has ever started, so the CLI must be able to create the schema too,
and two independent creation paths would drift.
"""
from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path

from .errors import TokenError

SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS tokens (
  token_sha256 TEXT PRIMARY KEY,
  service      TEXT NOT NULL,
  label        TEXT NOT NULL,
  role         TEXT NOT NULL,
  priority     INTEGER,
  rate_limit   TEXT,
  created_at   TEXT NOT NULL,
  created_by   TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at   TEXT,
  revoked_by   TEXT
);
CREATE INDEX IF NOT EXISTS idx_tokens_live ON tokens(service, revoked_at);
-- Expression index for resolve_handle(): without it the substr() predicate
-- cannot use the PRIMARY KEY and degrades to a full scan. SQLite >= 3.9
-- supports this; Python 3.10 bundles >= 3.37. IF NOT EXISTS so existing
-- stores gain it on the next ensure_schema() run.
CREATE INDEX IF NOT EXISTS idx_tokens_handle ON tokens(service, substr(token_sha256, 1, 16));
-- Live-label uniqueness enforced by the DATABASE, not by check-then-insert.
-- Two concurrent creates can both pass a live_label_exists() check and then both
-- insert; a partial unique index makes that impossible rather than unlikely.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_live_label
  ON tokens(service, label) WHERE revoked_at IS NULL;
-- Single-row by construction: a bare (version INTEGER) table lets a double-run
-- leave two rows and makes SELECT version non-deterministic.
CREATE TABLE IF NOT EXISTS _schema_version (
  id      INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
);
"""


@contextlib.contextmanager
def connect(db_path: str | Path):
    """Transaction AND lifetime scoped.

    sqlite3's own connection context manager commits or rolls back but NEVER
    closes, so a bare `with sqlite3.connect(...)` leaks a handle per call — which
    becomes file-descriptor growth and "database is locked" under the
    multi-worker adopters this package is meant to serve. WAL and a busy timeout
    are set for the same reason: several workers share one file.
    """
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA foreign_keys = ON")
        with conn:  # commit on success, rollback on exception
            yield conn
    finally:
        conn.close()


def ensure_schema(db_path: str | Path, *, create: bool) -> None:
    path = Path(db_path)
    if not path.exists():
        if not create:
            raise FileNotFoundError(
                f"{path} does not exist. Pass --init to create it, and check the path "
                f"matches the one the app passes to install_tokens()."
            )
        path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        # Check the version BEFORE applying any DDL. Running this package's
        # schema against a store written by a newer package and *then* refusing
        # to downgrade is the wrong order: the damage is already done by the
        # time the error is raised.
        existing = conn.execute(
            "SELECT version FROM _schema_version WHERE id = 1"
        ).fetchone() if _table_exists(conn, "_schema_version") else None
        if existing is not None and existing["version"] > SCHEMA_VERSION:
            raise TokenError(
                f"store at {path} is schema v{existing['version']}, newer than this "
                f"package (v{SCHEMA_VERSION}). Refusing to downgrade — no DDL applied."
            )
        if existing is not None and existing["version"] < SCHEMA_VERSION:
            # Future migrations land here as incremental steps (v1 -> v2, ...),
            # NOT as edits to _DDL alone: CREATE ... IF NOT EXISTS never alters
            # an existing table, so a bare DDL edit silently no-ops on adopted
            # stores. v1 is the first version; there is nothing to migrate yet.
            _migrate(conn, existing["version"])
        conn.executescript(_DDL)
        # INSERT OR IGNORE, not check-then-insert: two processes racing to
        # initialise the same store would otherwise both see row is None and
        # collide on the id=1 primary key.
        conn.execute(
            "INSERT OR IGNORE INTO _schema_version (id, version) VALUES (1, ?)",
            (SCHEMA_VERSION,),
        )


def _migrate(conn, from_version: int) -> None:
    """Incremental migration stub. v1 has no predecessors; raise on unknown."""
    raise TokenError(
        f"store is schema v{from_version}, package is v{SCHEMA_VERSION}: "
        f"no migration path implemented"
    )


def _table_exists(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None
