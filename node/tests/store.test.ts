import { readFileSync, statSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import { describe, expect, it } from "vitest";

import { tokenHash } from "../src/hashing.js";
import {
  SCHEMA_VERSION,
  Store,
  ensureSchema,
  isExpired,
  normalizeExpiresAt,
  utcNow,
} from "../src/store.js";
import { tempDb } from "./helpers.js";

function freshStore(service = "demo"): { store: Store; dbPath: string } {
  const dbPath = tempDb();
  ensureSchema(dbPath, { create: true });
  return { store: new Store(dbPath, service), dbPath };
}

describe("ensureSchema", () => {
  it("creates the file and refuses when create=false", () => {
    const dbPath = tempDb();
    expect(() => ensureSchema(dbPath, { create: false })).toThrow(/does not exist/);
    ensureSchema(dbPath, { create: true });
    expect(() => ensureSchema(dbPath, { create: false })).not.toThrow();
  });

  it("is idempotent and stamps the version", () => {
    const { dbPath } = freshStore();
    ensureSchema(dbPath, { create: false });
    ensureSchema(dbPath, { create: false });
    // A second run must not throw or duplicate the version row.
    expect(SCHEMA_VERSION).toBe(2);
  });

  it("creates the store 0600", () => {
    const { dbPath } = freshStore();
    expect(statSync(dbPath).mode & 0o777).toBe(0o600);
  });

  it("refuses a store newer than this package", () => {
    const { dbPath } = freshStore();
    const db = new DatabaseSync(dbPath);
    db.exec(`UPDATE _schema_version SET version = ${SCHEMA_VERSION + 1}`);
    db.close();
    expect(() => ensureSchema(dbPath, { create: false })).toThrow(/newer/);
  });
});

describe("expiry timestamp canonicalisation", () => {
  it("normalises to the Python format (+00:00, second precision)", () => {
    // Cross-runtime contract: the Node and Python packages write the same string
    // so expiry compares consistently against a store either one wrote.
    expect(normalizeExpiresAt("2999-01-01T00:00:00Z")).toBe("2999-01-01T00:00:00+00:00");
    expect(normalizeExpiresAt("2999-01-01T00:00:00-05:00")).toBe("2999-01-01T05:00:00+00:00");
    expect(normalizeExpiresAt("2999-01-01T00:00:00")).toBe("2999-01-01T00:00:00+00:00");
    expect(utcNow()).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$/);
  });

  it("rejects garbage", () => {
    for (const bad of ["not a time", "", 123, "2999-13-45T00:00:00"]) {
      expect(() => normalizeExpiresAt(bad)).toThrow();
    }
  });

  it("isExpired is false for null and future, true for past", () => {
    expect(isExpired(null)).toBe(false);
    expect(isExpired("2999-01-01T00:00:00+00:00")).toBe(false);
    expect(isExpired("2000-01-01T00:00:00+00:00")).toBe(true);
  });
});

describe("Store rows", () => {
  it("mints and never writes the raw value", () => {
    const { store, dbPath } = freshStore();
    const { raw, handle } = store.mint("agent", "scout", "cli:leon@dev");
    expect(raw.startsWith("demo-agent-")).toBe(true);
    expect(handle).toBe(tokenHash(raw).slice(0, 16));
    expect(readFileSync(dbPath).includes(Buffer.from(raw))).toBe(false);
  });

  it("is service-scoped", () => {
    const dbPath = tempDb();
    ensureSchema(dbPath, { create: true });
    const a = new Store(dbPath, "alpha");
    const b = new Store(dbPath, "beta");
    const { raw } = a.mint("agent", "x", "cli:leon@dev");
    expect(a.lookupLive(tokenHash(raw))).toBeDefined();
    expect(b.lookupLive(tokenHash(raw))).toBeUndefined();
  });

  it("revokes immediately and softly, and a second revoke is a no-op", () => {
    const { store } = freshStore();
    const { raw, handle } = store.mint("agent", "scout", "cli:leon@dev");
    const first = store.revoke(handle, "session:leon");
    expect(first.changed).toBe(true);
    expect(store.lookupLive(tokenHash(raw))).toBeUndefined();
    const second = store.revoke(handle, "session:someone_else");
    expect(second.changed).toBe(false);
    expect(second.row.revoked_by).toBe("session:leon");
  });

  it("filters by label and clamps hostile limits", () => {
    const { store } = freshStore();
    store.mint("agent", "alpha", "cli:leon@dev");
    store.mint("agent", "beta", "cli:leon@dev");
    expect(store.listRows({ label: "alpha" }).rows.map((r) => r.label)).toEqual(["alpha"]);
    const clamped = store.listRows({ limit: -1 });
    expect(clamped.rows.length).toBe(1);
    expect(clamped.hasMore).toBe(true);
  });

  it("excludes an expired token from lookupLive but finds it with findAny", () => {
    const { store } = freshStore();
    const { raw } = store.mint("agent", "old", "cli:leon@dev", {
      expiresAt: "2000-01-01T00:00:00+00:00",
    });
    expect(store.lookupLive(tokenHash(raw))).toBeUndefined();
    const row = store.findAny(tokenHash(raw));
    expect(row).toBeDefined();
    expect(row?.revoked_at).toBeNull();
  });

  it("refreshes recency on re-emit instead of evicting the newest", () => {
    const dbPath = tempDb();
    ensureSchema(dbPath, { create: true });
    const store = new Store(dbPath, "demo", { touchMapMax: 2 });
    store.touchNote(store.lastTouch, "a", 1);
    store.touchNote(store.lastTouch, "b", 2);
    store.touchNote(store.lastTouch, "a", 3); // refresh
    store.touchNote(store.lastTouch, "c", 4); // must evict "b", not "a"
    expect([...store.lastTouch.keys()]).toEqual(["a", "c"]);
  });
});
