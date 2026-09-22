import { describe, expect, it } from "vitest";

import type { Limits, SessionIdentity } from "../src/core.js";
import { Endpoints, authenticate } from "../src/core.js";
import { Store, ensureSchema } from "../src/store.js";
import { tempDb } from "./helpers.js";

const SITE = "https://tokens.example.com";
const OP: SessionIdentity = { user: "leon", isOperator: true };
const MEMBER: SessionIdentity = { user: "member", isOperator: false };

function ep(limits?: Limits) {
  const dbPath = tempDb();
  ensureSchema(dbPath, { create: true });
  const store = new Store(dbPath, "demo");
  return new Endpoints(store, SITE, { limits });
}

function mint(e: Endpoints, label = "scout"): Record<string, unknown> {
  const out = e.handleCreate(OP, null, { label, role: "agent" }, SITE, null);
  expect(out.status).toBe(201);
  return out.body;
}

describe("authorization", () => {
  it("401 for anonymous", () => {
    expect(ep().handleList(null, null, {}).status).toBe(401);
  });
  it("403 for a bearer token, on every endpoint including list", () => {
    const e = ep();
    const raw = mint(e).token as string;
    expect(e.handleList(null, raw, {}).status).toBe(403);
    expect(e.handleCreate(null, raw, { label: "x", role: "agent" }, SITE, null).status).toBe(403);
    expect(e.handleDelete(null, raw, "0".repeat(16), SITE, null).status).toBe(403);
  });
  it("403 for a non-operator session, including list", () => {
    const e = ep();
    expect(e.handleList(MEMBER, null, {}).status).toBe(403);
    expect(e.handleCreate(MEMBER, null, { label: "x", role: "agent" }, SITE, null).status).toBe(403);
  });
});

describe("CSRF", () => {
  for (const [origin, referer] of [
    ["https://evil.example", null],
    [null, null],
  ] as const) {
    it(`rejects bad/absent origin (${origin}, ${referer})`, () => {
      const e = ep();
      expect(e.handleCreate(OP, null, { label: "x", role: "agent" }, origin, referer).status).toBe(403);
      const h = mint(e, "y").handle as string;
      expect(e.handlePatch(OP, null, h, { label: "z" }, origin, referer).status).toBe(403);
      expect(e.handleDelete(OP, null, h, origin, referer).status).toBe(403);
    });
  }
  it("does not CSRF-check the listing", () => {
    expect(ep().handleList(OP, null, {}).status).toBe(200);
  });
});

describe("ordering and responses", () => {
  it("checks credentials before existence", () => {
    const e = ep();
    expect(e.handleDelete(null, null, "0".repeat(16), SITE, null).status).toBe(401);
    expect(e.handleDelete(null, null, "deadbeefdeadbeef", SITE, null).status).toBe(401);
  });

  it("returns the raw token once and never exposes the digest", () => {
    const e = ep();
    const body = mint(e);
    const listed = e.handleList(OP, null, {}).body.tokens as Array<Record<string, unknown>>;
    expect(JSON.stringify(listed)).not.toContain(body.token);
    expect(String(listed[0].handle)).toHaveLength(16);
    expect(listed[0]).not.toHaveProperty("token_sha256");
  });

  it("409 on a duplicate live label", () => {
    const e = ep();
    mint(e, "dup");
    expect(e.handleCreate(OP, null, { label: "dup", role: "agent" }, SITE, null).status).toBe(409);
  });

  it("400 on bad bodies, policy and handles", () => {
    const e = ep();
    expect(e.handleCreate(OP, null, { role: "agent" }, SITE, null).status).toBe(400);
    expect(e.handleCreate(OP, null, { label: "x", role: "BAD-ROLE" }, SITE, null).status).toBe(400);
    expect(e.handleList(OP, null, { limit: "abc" }).status).toBe(400);
    expect(e.handleDelete(OP, null, "abc", SITE, null).status).toBe(400);
    for (const body of [
      { label: "x", role: "agent", priority: "high" },
      { label: "x", role: "agent", priority: true },
      { label: "x", role: "agent", rate_limit: "not json" },
      { label: "x", role: "agent", rate_limit: 10 },
      { label: "x", role: "agent", rate_limit: '"str"' },
      { label: "x", role: "agent", rate_limit: "[1,2]" },
    ]) {
      expect(e.handleCreate(OP, null, body as Record<string, unknown>, SITE, null).status).toBe(400);
    }
  });

  it("404s an unknown handle and 200s a GET", () => {
    const e = ep();
    const h = mint(e, "single").handle as string;
    expect(e.handleGet(OP, null, h).body.label).toBe("single");
    expect(e.handleGet(OP, null, "0".repeat(16)).status).toBe(404);
  });

  it("PATCH changes label/policy and is allowed on a revoked token", () => {
    const e = ep();
    const h = mint(e, "before").handle as string;
    const out = e.handlePatch(OP, null, h, { label: "after", priority: 1 }, SITE, null);
    expect(out.status).toBe(200);
    expect([out.body.label, out.body.priority]).toEqual(["after", 1]);
    expect(e.handlePatch(OP, null, h, { role: "admin" }, SITE, null).status).toBe(400);
    e.handleDelete(OP, null, h, SITE, null);
    expect(e.handlePatch(OP, null, h, { label: "old key" }, SITE, null).status).toBe(200);
  });

  it("bounds the label and honours a Limits override", () => {
    const e = ep({ maxLabelLen: 3 });
    expect(e.handleCreate(OP, null, { label: "toolong", role: "agent" }, SITE, null).status).toBe(400);
    expect(e.handleCreate(OP, null, { label: "ok", role: "agent" }, SITE, null).status).toBe(201);
  });

  it("supports expiry on create/patch and refuses an expired token", () => {
    const e = ep();
    const out = e.handleCreate(
      OP,
      null,
      { label: "tmp", role: "agent", expires_at: "2999-01-01T00:00:00+00:00" },
      SITE,
      null,
    );
    const h = out.body.handle as string;
    expect(e.handleGet(OP, null, h).body.expires_at).toBe("2999-01-01T00:00:00+00:00");
    expect(e.handlePatch(OP, null, h, { expires_at: null }, SITE, null).body.expires_at).toBeNull();
    expect(e.handlePatch(OP, null, h, { expires_at: "nope" }, SITE, null).status).toBe(400);

    const past = e.handleCreate(
      OP,
      null,
      { label: "gone", role: "agent", expires_at: "2000-01-01T00:00:00+00:00" },
      SITE,
      null,
    );
    expect(authenticate(e.store, `Bearer ${past.body.token as string}`)).toBeNull();
  });

  it("surfaces revoked_by in the listing", () => {
    const e = ep();
    const h = mint(e, "trace").handle as string;
    expect((e.handleList(OP, null, {}).body.tokens as Array<Record<string, unknown>>)[0].revoked_by).toBeNull();
    e.handleDelete(OP, null, h, SITE, null);
    const revoked = e.handleList(OP, null, { include: "revoked" }).body.tokens as Array<Record<string, unknown>>;
    expect(revoked[0].revoked_by).toBe("session:leon");
  });

  it("fails at construction for an invalid site_origin", () => {
    const dbPath = tempDb();
    ensureSchema(dbPath, { create: true });
    expect(() => new Endpoints(new Store(dbPath, "demo"), "not-an-origin")).toThrow();
  });
});
