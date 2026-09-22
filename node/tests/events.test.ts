import { describe, expect, it } from "vitest";

import { authenticate } from "../src/core.js";
import { Emitter, stdoutSink } from "../src/events.js";
import { Store, ensureSchema } from "../src/store.js";
import { tempDb } from "./helpers.js";

function setup() {
  const dbPath = tempDb();
  ensureSchema(dbPath, { create: true });
  const store = new Store(dbPath, "demo");
  const seen: Array<Record<string, unknown>> = [];
  const emitter = new Emitter({ sink: (event, fields) => seen.push({ event, ...fields }) });
  return { store, seen, emitter };
}

describe("lifecycle events", () => {
  it("fires auth_failed on a presented but unknown bearer", () => {
    const { store, seen, emitter } = setup();
    authenticate(store, `Bearer demo-agent-${"0".repeat(64)}`, { emitter });
    expect(seen.map((e) => e.event)).toEqual(["token.auth_failed"]);
    expect(seen[0].digest_prefix).toBeDefined();
    expect(seen[0].label).toBeNull();
  });

  it("does NOT fire on an anonymous request", () => {
    const { store, seen, emitter } = setup();
    authenticate(store, null, { emitter });
    authenticate(store, "", { emitter });
    expect(seen).toEqual([]);
  });

  it("names a revoked token", () => {
    const { store, seen, emitter } = setup();
    const { raw, handle } = store.mint("agent", "scout", "cli:leon@dev");
    store.revoke(handle, "session:leon");
    authenticate(store, `Bearer ${raw}`, { emitter });
    expect(seen[0].handle).toBe(handle);
    expect(seen[0].label).toBe("scout");
    expect(seen[0].reason).toBe("revoked");
  });

  it("throttles repeated malformed and unknown failures", () => {
    const { store, seen, emitter } = setup();
    authenticate(store, "Bearer nope", { emitter });
    expect(seen[0].reason).toBe("malformed");
    seen.length = 0;
    authenticate(store, "Bearer nope", { emitter });
    expect(seen).toEqual([]);

    const unknown = `Bearer demo-agent-${"1".repeat(64)}`;
    authenticate(store, unknown, { emitter });
    expect(seen.length).toBe(1);
    authenticate(store, unknown, { emitter });
    expect(seen.length).toBe(1);
  });

  it("emits on the FIRST failure of a freshly booted process", () => {
    // Date.now() is epoch-based; a `now - 0 < window` guard would swallow this.
    const { store, seen, emitter } = setup();
    authenticate(store, `Bearer demo-agent-${"0".repeat(64)}`, { emitter });
    expect(seen.length).toBe(1);
  });

  it("a second emitter does not touch the default", () => {
    const other: string[] = [];
    const custom = new Emitter({ sink: (e) => other.push(e) });
    custom.tokenCreated("demo", "h", "l", "r", "a");
    expect(other).toEqual(["token.created"]);
  });

  it("the default sink writes one JSON line with the service", () => {
    const written: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    (process.stdout.write as unknown as (s: string) => boolean) = (s: string) => {
      written.push(String(s));
      return true;
    };
    try {
      stdoutSink("token.created", { service: "demo", label: "scout" });
    } finally {
      process.stdout.write = original as typeof process.stdout.write;
    }
    expect(JSON.parse(written.join("").trim())).toMatchObject({
      event: "token.created",
      service: "demo",
      label: "scout",
    });
  });
});
