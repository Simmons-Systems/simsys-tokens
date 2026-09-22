import { describe, expect, it, vi } from "vitest";

import { authenticate } from "../src/core.js";
import { Emitter, type EventSink } from "../src/events.js";
import { tokenHash } from "../src/hashing.js";
import { Store, ensureSchema } from "../src/store.js";
import { tempDb } from "./helpers.js";

function fresh(service = "demo"): Store {
  const dbPath = tempDb();
  ensureSchema(dbPath, { create: true });
  return new Store(dbPath, service);
}

describe("authenticate", () => {
  it("resolves a live bearer to a secret-free TokenInfo", () => {
    const store = fresh();
    const { raw, handle } = store.mint("agent", "scout", "cli:leon@dev");
    const info = authenticate(store, `Bearer ${raw}`);
    expect(info).not.toBeNull();
    expect([info!.handle, info!.role, info!.label]).toEqual([handle, "agent", "scout"]);
    expect(JSON.stringify(info)).not.toContain(raw);
  });

  it("revoke takes effect without a restart", () => {
    const store = fresh();
    const { raw, handle } = store.mint("agent", "scout", "cli:leon@dev");
    expect(authenticate(store, `Bearer ${raw}`)).not.toBeNull();
    store.revoke(handle, "session:leon");
    expect(authenticate(store, `Bearer ${raw}`)).toBeNull();
  });

  it("rejects an expired token and reports it as expired", () => {
    const store = fresh();
    const seen: Array<Record<string, unknown>> = [];
    const emitter = new Emitter({ sink: (e, f) => seen.push({ event: e, ...f }) });
    const { raw } = store.mint("agent", "old", "cli:leon@dev", {
      expiresAt: "2000-01-01T00:00:00+00:00",
    });
    expect(authenticate(store, `Bearer ${raw}`, { emitter })).toBeNull();
    expect(seen[0].reason).toBe("expired");
  });

  for (const header of [null, undefined, "", "Basic abc", "Bearer nope", "bearer lowercase"]) {
    it(`returns null for ${JSON.stringify(header)}`, () => {
      expect(authenticate(fresh(), header as string | null)).toBeNull();
    });
  }

  it("never reaches the store for a malformed bearer", () => {
    const store = fresh();
    const spy = vi.spyOn(store, "lookupLive");
    expect(authenticate(store, "Bearer nope")).toBeNull();
    expect(authenticate(store, `Bearer ${"a".repeat(10000)}`)).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  it("populates last_used_at on first use and emits first_use once", () => {
    const store = fresh();
    const events: string[] = [];
    const emitter = new Emitter({ sink: (e) => events.push(e) });
    const { raw, handle } = store.mint("agent", "scout", "cli:leon@dev");
    expect(store.resolveHandle(handle).last_used_at).toBeNull();
    authenticate(store, `Bearer ${raw}`, { emitter });
    expect(store.resolveHandle(handle).last_used_at).not.toBeNull();
    expect(events).toEqual(["token.first_use"]);
    events.length = 0;
    store.lastTouch.clear(); // defeat the throttle, not the flag
    authenticate(store, `Bearer ${raw}`, { emitter });
    expect(events).toEqual([]);
  });

  it("keeps the touch map bounded", () => {
    const store = fresh();
    const { raw } = store.mint("agent", "scout", "cli:leon@dev");
    for (let i = 0; i < 6000; i++) store.lastTouch.set(`junk${i}`, 0);
    authenticate(store, `Bearer ${raw}`);
    expect(store.lastTouch.size).toBeLessThanOrEqual(store.touchMapMax + 1);
  });
});
