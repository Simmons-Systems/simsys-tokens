/**
 * The token store: schema, migrations and row access, on node:sqlite.
 *
 * Same schema as the Python package (`tokens` + `_schema_version`), so one store
 * file is readable by both runtimes. `ensureSchema` is the ONE creation /
 * migration routine — the CLI and the Express mount both call it, and two
 * independent creation paths would drift.
 *
 * No dependency: node:sqlite ships with Node (>=22.13 without a flag).
 */
import { chmodSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { AmbiguousHandle, NoSuchHandle, TokenError } from "./errors.js";
import { handleOf, mintToken, tokenHash, validateHandle, validateRole, validateService } from "./hashing.js";

export const SCHEMA_VERSION = 2;

export const MAX_LIMIT = 500;
export const TOUCH_MAP_MAX = 5000;

const DDL = `
CREATE TABLE IF NOT EXISTS tokens (
  token_sha256 TEXT PRIMARY KEY,
  service      TEXT NOT NULL,
  label        TEXT NOT NULL,
  role         TEXT NOT NULL,
  priority     INTEGER,
  rate_limit   TEXT,
  expires_at   TEXT,
  created_at   TEXT NOT NULL,
  created_by   TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at   TEXT,
  revoked_by   TEXT
);
CREATE INDEX IF NOT EXISTS idx_tokens_live ON tokens(service, revoked_at);
CREATE INDEX IF NOT EXISTS idx_tokens_handle ON tokens(service, substr(token_sha256, 1, 16));
CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_live_label
  ON tokens(service, label) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS _schema_version (
  id      INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
);
`;

// Columns added after v1, with the migration that introduces each.
// CREATE TABLE IF NOT EXISTS never alters an existing table, so a bare edit to
// DDL silently no-ops on adopted stores — every such column needs a step here.
const COLUMN_MIGRATIONS: Record<string, string> = {
  expires_at: "ALTER TABLE tokens ADD COLUMN expires_at TEXT",
};

/** One row of `tokens`. */
export interface TokenRow {
  token_sha256: string;
  service: string;
  label: string;
  role: string;
  priority: number | null;
  rate_limit: string | null;
  expires_at: string | null;
  created_at: string;
  created_by: string;
  last_used_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
}

/**
 * Canonical timestamp: UTC, second precision, `+00:00` offset — byte-identical
 * to Python's `datetime.isoformat(timespec="seconds")`, because expiry is
 * compared as a string and a `Z`-form here vs a `+00:00`-form there would make
 * one runtime's tokens look expired to the other.
 */
export function utcNow(): string {
  return `${new Date().toISOString().slice(0, 19)}+00:00`;
}

export function normalizeExpiresAt(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error("expires_at must be an ISO-8601 timestamp or null");
  }
  const m = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$/.exec(
    value.trim(),
  );
  if (!m) throw new Error(`expires_at is not an ISO-8601 timestamp: ${JSON.stringify(value)}`);
  const at = new Date(`${m[1]}T${m[2]}${m[3] ?? "+00:00"}`);
  if (Number.isNaN(at.getTime())) {
    throw new Error(`expires_at is not a valid timestamp: ${JSON.stringify(value)}`);
  }
  return `${at.toISOString().slice(0, 19)}+00:00`;
}

/** True iff `expiresAt` is set and not in the future. String compare: every
 * stored timestamp is normalised to the same UTC format. */
export function isExpired(expiresAt: string | null, now = utcNow()): boolean {
  if (!expiresAt) return false;
  return expiresAt <= now;
}

/** Best-effort chmod 0600 on the store file. The store holds digests, labels
 * and actors — not secrets — so this is hygiene, not a boundary; a failure must
 * not stop an app from starting. */
function restrictPermissions(path: string): void {
  for (const p of [path, `${path}-wal`, `${path}-shm`]) {
    try {
      if (existsSync(p)) chmodSync(p, 0o600);
    } catch {
      /* best effort */
    }
  }
}

function withDb<T>(path: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(path);
  try {
    db.exec("PRAGMA journal_mode = WAL;");
    db.exec("PRAGMA busy_timeout = 5000;");
    db.exec("PRAGMA foreign_keys = ON;");
    return fn(db);
  } finally {
    db.close();
  }
}

function tableExists(db: DatabaseSync, name: string): boolean {
  const row = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?")
    .get(name);
  return row !== undefined;
}

function columnExists(db: DatabaseSync, table: string, column: string): boolean {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  return rows.some((r) => r.name === column);
}

export function ensureSchema(dbPath: string, { create }: { create: boolean }): void {
  if (!existsSync(dbPath)) {
    if (!create) {
      throw new TokenError(
        `${dbPath} does not exist. Pass --init to create it, and check the path ` +
          `matches the one the app passes to installTokens().`,
      );
    }
    mkdirSync(dirname(dbPath), { recursive: true });
  }
  withDb(dbPath, (db) => {
    const existing = tableExists(db, "_schema_version")
      ? (db.prepare("SELECT version FROM _schema_version WHERE id = 1").get() as
          | { version: number }
          | undefined)
      : undefined;
    if (existing && existing.version > SCHEMA_VERSION) {
      throw new TokenError(
        `store at ${dbPath} is schema v${existing.version}, newer than this package ` +
          `(v${SCHEMA_VERSION}). Refusing to downgrade — no DDL applied.`,
      );
    }
    if (existing && existing.version < SCHEMA_VERSION) {
      db.exec("BEGIN");
      try {
        if (existing.version < 2) {
          for (const [column, ddl] of Object.entries(COLUMN_MIGRATIONS)) {
            if (!columnExists(db, "tokens", column)) db.exec(ddl);
          }
        }
        db.exec("COMMIT");
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    }
    db.exec(DDL);
    // Upsert, not INSERT OR IGNORE: an upgraded store already has the id=1 row,
    // and ignoring it would leave the version stale forever.
    db.prepare(
      "INSERT INTO _schema_version (id, version) VALUES (1, ?)" +
        " ON CONFLICT(id) DO UPDATE SET version = excluded.version",
    ).run(SCHEMA_VERSION);
  });
  restrictPermissions(dbPath);
}

/** Service-scoped row access. Every statement carries `service`. */
export class Store {
  readonly dbPath: string;
  readonly service: string;
  readonly maxLimit: number;
  readonly touchMapMax: number;
  /** Monotonic ms of the last throttled touch / auth_failed emit, per key. */
  readonly lastTouch = new Map<string, number>();
  readonly lastAuthFailed = new Map<string, number>();

  constructor(dbPath: string, service: string, opts: { maxLimit?: number; touchMapMax?: number } = {}) {
    validateService(service);
    this.dbPath = dbPath;
    this.service = service;
    this.maxLimit = opts.maxLimit ?? MAX_LIMIT;
    this.touchMapMax = opts.touchMapMax ?? TOUCH_MAP_MAX;
  }

  /** Record `key` at `now`, evicting oldest-first past the bound. Delete-then-set
   * so a re-emitted key moves to the newest end instead of being evicted as the
   * oldest. */
  touchNote(map: Map<string, number>, key: string, now: number): void {
    map.delete(key);
    map.set(key, now);
    while (map.size > this.touchMapMax) {
      const oldest = map.keys().next().value;
      if (oldest === undefined) break;
      map.delete(oldest);
    }
  }

  mint(
    role: string,
    label: string,
    createdBy: string,
    extra: { priority?: number | null; rateLimit?: string | null; expiresAt?: string | null } = {},
  ): { raw: string; handle: string } {
    validateRole(role);
    const raw = mintToken(this.service, role);
    const handle = this.insertDigest(tokenHash(raw), role, label, createdBy, extra);
    return { raw, handle };
  }

  insertDigest(
    digest: string,
    role: string,
    label: string,
    createdBy: string,
    extra: { priority?: number | null; rateLimit?: string | null; expiresAt?: string | null } = {},
  ): string {
    validateRole(role);
    withDb(this.dbPath, (db) => {
      db.prepare(
        "INSERT INTO tokens (token_sha256, service, label, role, priority, rate_limit," +
          " expires_at, created_at, created_by) VALUES (?,?,?,?,?,?,?,?,?)",
      ).run(
        digest,
        this.service,
        label,
        role,
        extra.priority ?? null,
        extra.rateLimit ?? null,
        normalizeExpiresAt(extra.expiresAt ?? null),
        utcNow(),
        createdBy,
      );
    });
    return handleOf(digest);
  }

  lookupLive(digest: string, now = utcNow()): TokenRow | undefined {
    return withDb(this.dbPath, (db) =>
      db
        .prepare(
          "SELECT * FROM tokens WHERE token_sha256 = ? AND service = ?" +
            " AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
        )
        .get(digest, this.service, now),
    ) as TokenRow | undefined;
  }

  findAny(digest: string): TokenRow | undefined {
    return withDb(this.dbPath, (db) =>
      db
        .prepare("SELECT * FROM tokens WHERE token_sha256 = ? AND service = ?")
        .get(digest, this.service),
    ) as TokenRow | undefined;
  }

  listRows(opts: { includeRevoked?: boolean; limit?: number; label?: string | null } = {}): {
    rows: TokenRow[];
    hasMore: boolean;
  } {
    const requested = opts.limit ?? this.maxLimit;
    const limit = Math.max(1, Math.min(Math.trunc(requested), this.maxLimit));
    let clause = opts.includeRevoked ? "" : " AND revoked_at IS NULL";
    const params: Array<string | number> = [this.service];
    if (opts.label != null) {
      clause += " AND label = ?";
      params.push(opts.label);
    }
    const rows = withDb(this.dbPath, (db) =>
      db
        .prepare(
          `SELECT * FROM tokens WHERE service = ?${clause} ORDER BY created_at, rowid LIMIT ?`,
        )
        .all(...params, limit + 1),
    ) as unknown as TokenRow[];
    return { rows: rows.slice(0, limit), hasMore: rows.length > limit };
  }

  resolveHandle(handle: string): TokenRow {
    validateHandle(handle);
    const rows = withDb(this.dbPath, (db) =>
      db
        .prepare("SELECT * FROM tokens WHERE service = ? AND substr(token_sha256,1,16) = ?")
        .all(this.service, handle),
    ) as unknown as TokenRow[];
    if (rows.length === 0) {
      throw new NoSuchHandle(`no token with handle ${JSON.stringify(handle)} in service ${JSON.stringify(this.service)}`);
    }
    if (rows.length > 1) {
      throw new AmbiguousHandle(
        `handle ${JSON.stringify(handle)} matches ${rows.length} tokens in service ` +
          `${JSON.stringify(this.service)}; use a longer prefix from the listing`,
      );
    }
    return rows[0];
  }

  /** Returns the row and whether it changed. The already-revoked guard is in the
   * UPDATE's WHERE clause, not a preceding read — a check-then-act pair lets two
   * concurrent revokes both pass and the second overwrite the first's revoked_by. */
  revoke(handle: string, revokedBy: string): { row: TokenRow; changed: boolean } {
    const row = this.resolveHandle(handle);
    const changed = withDb(this.dbPath, (db) => {
      const res = db
        .prepare(
          "UPDATE tokens SET revoked_at = ?, revoked_by = ?" +
            " WHERE token_sha256 = ? AND service = ? AND revoked_at IS NULL",
        )
        .run(utcNow(), revokedBy, row.token_sha256, this.service);
      return Number(res.changes) === 1;
    });
    return { row: this.resolveHandle(handle), changed };
  }

  updateRow(
    handle: string,
    patch: {
      label?: string | null;
      priority?: number | null | undefined;
      rateLimit?: string | null | undefined;
      expiresAt?: string | null | undefined;
    },
  ): TokenRow {
    const row = this.resolveHandle(handle);
    const sets: string[] = [];
    const params: Array<string | number | null> = [];
    if (patch.label != null) {
      sets.push("label = ?");
      params.push(patch.label);
    }
    if (patch.priority !== undefined) {
      sets.push("priority = ?");
      params.push(patch.priority);
    }
    if (patch.rateLimit !== undefined) {
      sets.push("rate_limit = ?");
      params.push(patch.rateLimit);
    }
    if (patch.expiresAt !== undefined) {
      sets.push("expires_at = ?");
      params.push(normalizeExpiresAt(patch.expiresAt));
    }
    if (sets.length > 0) {
      withDb(this.dbPath, (db) => {
        db.prepare(
          `UPDATE tokens SET ${sets.join(", ")} WHERE token_sha256 = ? AND service = ?`,
        ).run(...params, row.token_sha256, this.service);
      });
    }
    return this.resolveHandle(handle);
  }

  updatePolicy(digest: string, priority: number | null, rateLimit: string | null): void {
    withDb(this.dbPath, (db) => {
      db.prepare(
        "UPDATE tokens SET priority = ?, rate_limit = ? WHERE token_sha256 = ? AND service = ?",
      ).run(priority, rateLimit, digest, this.service);
    });
  }

  touchLastUsed(digest: string): void {
    withDb(this.dbPath, (db) => {
      db.prepare(
        "UPDATE tokens SET last_used_at = ? WHERE token_sha256 = ? AND service = ?",
      ).run(utcNow(), digest, this.service);
    });
  }

  liveLabelExists(label: string, opts: { excludingDigest?: string } = {}): boolean {
    let sql = "SELECT 1 FROM tokens WHERE service = ? AND label = ? AND revoked_at IS NULL";
    const params: string[] = [this.service, label];
    if (opts.excludingDigest) {
      sql += " AND token_sha256 != ?";
      params.push(opts.excludingDigest);
    }
    return (
      withDb(this.dbPath, (db) => db.prepare(sql).get(...params)) !== undefined
    );
  }
}
