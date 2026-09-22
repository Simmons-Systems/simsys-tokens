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


import threading
from datetime import datetime, timezone

from .hashing import handle_of, mint_token, token_hash, validate_handle, validate_role, validate_service

MAX_LIMIT = 500
# Bound for the per-process throttle maps. Thousands of tokens fleet-wide means
# a few thousand entries max in practice; 5000 with oldest-first eviction keeps
# memory flat if a scanner hammers random digests.
TOUCH_MAP_MAX = 5000


class NoSuchHandle(TokenError):
    """Raised with a sentence, not a bare handle — the CLI prints str(exc)
    directly, and `error: 0000000000000000` tells the operator nothing."""


class AmbiguousHandle(TokenError):
    pass


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    """Service-scoped row access. Every query carries `service`."""

    def __init__(self, db_path, service: str):
        validate_service(service)
        self.db_path = db_path
        self.service = service
        # Per-store, not module-global: a global throttle map keyed only on the
        # digest is shared across every service in the process and never shrinks.
        # Guarded by _touch_lock: adapters run threaded (Flask) and async workers
        # share the Store, so an unlocked dict check-then-set races.
        self.last_touch: dict[str, float] = {}
        self.last_auth_failed: dict[str, float] = {}
        self._touch_lock = threading.Lock()

    def _touch_note(self, mapping: dict[str, float], key: str, now: float) -> None:
        """Record `key` at `now`, evicting oldest-first when over TOUCH_MAP_MAX."""
        mapping[key] = now
        while len(mapping) > TOUCH_MAP_MAX:
            mapping.pop(next(iter(mapping)), None)

    def mint(self, role, label, created_by, priority=None, rate_limit=None):
        validate_role(role)
        raw = mint_token(self.service, role)
        handle = self.insert_digest(
            token_hash(raw), role, label, created_by, priority, rate_limit
        )
        return raw, handle

    def insert_digest(self, digest, role, label, created_by, priority=None, rate_limit=None):
        """Plain INSERT — raises sqlite3.IntegrityError on any conflict.

        Deliberately NOT `INSERT OR IGNORE`: that would suppress the live-label
        unique-index violation as well as the primary-key one, silently dropping
        a colliding import instead of reporting it. Import idempotence comes from
        the caller's find_any() check, not from the insert mode.
        """
        validate_role(role)
        with connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO tokens (token_sha256, service, label, role, priority,"
                " rate_limit, created_at, created_by) VALUES (?,?,?,?,?,?,?,?)",
                (digest, self.service, label, role, priority, rate_limit, _utcnow(), created_by),
            )
        return handle_of(digest)

    def lookup_live(self, digest):
        with connect(self.db_path) as conn:
            return conn.execute(
                "SELECT * FROM tokens WHERE token_sha256 = ? AND service = ?"
                " AND revoked_at IS NULL",
                (digest, self.service),
            ).fetchone()

    def find_any(self, digest):
        with connect(self.db_path) as conn:
            return conn.execute(
                "SELECT * FROM tokens WHERE token_sha256 = ? AND service = ?",
                (digest, self.service),
            ).fetchone()

    def list_rows(self, include_revoked=False, limit=MAX_LIMIT):
        # Clamp BOTH ends. A negative limit reaches SQLite as `LIMIT -1`, which
        # means "no limit" and returns every row, while `rows[:limit]` with a
        # negative slice silently drops the tail and miscomputes has_more.
        limit = max(1, min(int(limit), MAX_LIMIT))
        clause = "" if include_revoked else " AND revoked_at IS NULL"
        with connect(self.db_path) as conn:
            rows = conn.execute(
                f"SELECT * FROM tokens WHERE service = ?{clause}"
                " ORDER BY created_at, rowid LIMIT ?",
                (self.service, limit + 1),
            ).fetchall()
        return (rows[:limit], len(rows) > limit)

    def resolve_handle(self, handle):
        validate_handle(handle)
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM tokens WHERE service = ? AND substr(token_sha256,1,16) = ?",
                (self.service, handle),
            ).fetchall()
        if not rows:
            raise NoSuchHandle(
                f"no token with handle {handle!r} in service {self.service!r}"
            )
        if len(rows) > 1:
            raise AmbiguousHandle(
                f"handle {handle!r} matches {len(rows)} tokens in service "
                f"{self.service!r}; use a longer prefix from the listing"
            )
        return rows[0]

    def revoke(self, handle, revoked_by):
        """Returns (row, changed). `changed` is False when it was already revoked.

        The guard is in the UPDATE's WHERE clause, not a preceding read: a
        check-then-act pair lets two concurrent revokes both pass the check and
        the second overwrite the first's revoked_by, losing the record of who
        actually killed the token.
        """
        row = self.resolve_handle(handle)
        with connect(self.db_path) as conn:
            cur = conn.execute(
                "UPDATE tokens SET revoked_at = ?, revoked_by = ?"
                " WHERE token_sha256 = ? AND service = ? AND revoked_at IS NULL",
                (_utcnow(), revoked_by, row["token_sha256"], self.service),
            )
            changed = cur.rowcount == 1
        return self.resolve_handle(handle), changed

    def update_row(self, handle, *, label=None, priority=..., rate_limit=...):
        row = self.resolve_handle(handle)
        sets, params = [], []
        if label is not None:
            sets.append("label = ?")
            params.append(label)
        if priority is not ...:
            sets.append("priority = ?")
            params.append(priority)
        if rate_limit is not ...:
            sets.append("rate_limit = ?")
            params.append(rate_limit)
        if sets:
            # `AND service = ?` like every other query in this class. Safe
            # without it only because token_sha256 is the primary key — an
            # invariant a future schema change could break silently.
            params.extend([row["token_sha256"], self.service])
            with connect(self.db_path) as conn:
                conn.execute(
                    f"UPDATE tokens SET {', '.join(sets)}"
                    " WHERE token_sha256 = ? AND service = ?",
                    params,
                )
        return self.resolve_handle(handle)

    def update_policy(self, digest, priority, rate_limit):
        """Policy-only update, keyed on the digest. Used by the importer's
        re-import path — every row write goes through Store, so there is one
        place to audit for SQL."""
        with connect(self.db_path) as conn:
            conn.execute(
                "UPDATE tokens SET priority = ?, rate_limit = ?"
                " WHERE token_sha256 = ? AND service = ?",
                (priority, rate_limit, digest, self.service),
            )

    def touch_last_used(self, digest):
        # No explicit commit: connect() commits on clean exit, so an extra
        # conn.commit() here is redundant (and masks the context-manager contract).
        with connect(self.db_path) as conn:
            conn.execute(
                "UPDATE tokens SET last_used_at = ? WHERE token_sha256 = ? AND service = ?",
                (_utcnow(), digest, self.service),
            )

    def live_label_exists(self, label, *, excluding_digest=None):
        sql = ("SELECT 1 FROM tokens WHERE service = ? AND label = ? AND revoked_at IS NULL")
        params = [self.service, label]
        if excluding_digest:
            sql += " AND token_sha256 != ?"
            params.append(excluding_digest)
        with connect(self.db_path) as conn:
            return conn.execute(sql, params).fetchone() is not None
