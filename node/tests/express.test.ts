import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";

import type { SessionIdentity } from "../src/core.js";
import { installTokens } from "../src/express.js";
import { tempDb } from "./helpers.js";

const SITE = "https://tokens.example.com";

function app(opts: Partial<Parameters<typeof installTokens>[1]> = {}, identity: SessionIdentity | null = { user: "leon", isOperator: true }) {
  const a = express();
  installTokens(a, {
    service: "demo",
    dbPath: tempDb(),
    siteOrigin: SITE,
    sessionResolver: () => identity,
    ...opts,
  } as Parameters<typeof installTokens>[1]);
  return a;
}

describe("Express adapter", () => {
  it("creates then lists, and never repeats the secret", async () => {
    const a = app();
    const created = await request(a)
      .post("/api/tokens")
      .set("Origin", SITE)
      .send({ label: "scout", role: "agent" });
    expect(created.status).toBe(201);
    const listed = await request(a).get("/api/tokens");
    expect(listed.status).toBe(200);
    expect(listed.body.tokens).toHaveLength(1);
    expect(JSON.stringify(listed.body)).not.toContain(created.body.token);
  });

  it("serves the component asset", async () => {
    const res = await request(app()).get("/simsys-tokens.js");
    expect(res.status).toBe(200);
    expect(res.text).toContain("customElements.define");
    expect(res.headers["content-type"]).toContain("javascript");
  });

  it("401 for anonymous, 403 for a bearer and for a non-operator", async () => {
    expect((await request(app({}, null)).get("/api/tokens")).status).toBe(401);
    expect(
      (await request(app({}, { user: "member", isOperator: false })).get("/api/tokens")).status,
    ).toBe(403);
  });

  it("401 (not 400) for an unauthenticated caller with malformed JSON", async () => {
    // Authorization is decided before the body is decoded.
    const res = await request(app({}, null))
      .post("/api/tokens")
      .set("Origin", SITE)
      .set("Content-Type", "application/json")
      .send("{not json");
    expect(res.status).toBe(401);
  });

  it("accepts JSON with no Content-Type header", async () => {
    const res = await request(app())
      .post("/api/tokens")
      .set("Origin", SITE)
      .set("Content-Type", "")
      .send('{"label":"noct","role":"agent"}');
    expect(res.status).toBe(201);
  });

  it("rejects a foreign origin", async () => {
    const res = await request(app())
      .post("/api/tokens")
      .set("Origin", "https://evil.example")
      .send({ label: "x", role: "agent" });
    expect(res.status).toBe(403);
  });

  it("honours a custom api prefix and asset path", async () => {
    const a = app({ apiPrefix: "/internal/tokens", assetPath: "/tok.js" });
    expect((await request(a).get("/api/tokens")).status).toBe(404);
    expect((await request(a).get("/simsys-tokens.js")).status).toBe(404);
    const created = await request(a)
      .post("/internal/tokens")
      .set("Origin", SITE)
      .send({ label: "a", role: "agent" });
    expect(created.status).toBe(201);
    expect((await request(a).get("/internal/tokens")).status).toBe(200);
    expect((await request(a).get("/tok.js")).status).toBe(200);
  });

  it("reads the bearer from a custom header", async () => {
    const a = app({ authHeader: "X-Auth" });
    const res = await request(a)
      .get("/api/tokens")
      .set("X-Auth", `Bearer demo-agent-${"a".repeat(64)}`);
    expect(res.status).toBe(403);
  });

  it("treats a raising session resolver as anonymous", async () => {
    const a = express();
    installTokens(a, {
      service: "demo",
      dbPath: tempDb(),
      siteOrigin: SITE,
      sessionResolver: () => {
        throw new Error("adopter bug");
      },
    });
    expect((await request(a).get("/api/tokens")).status).toBe(401);
  });

  it("imports tokens at mount", async () => {
    const store = installTokens(express(), {
      service: "demo",
      dbPath: tempDb(),
      siteOrigin: SITE,
      sessionResolver: () => ({ user: "leon", isOperator: true }),
      importTokens: [{ role: "agent", key: `demo-agent-${"d".repeat(64)}` }],
    });
    // installTokens(app, ...) returns the Store — a smoke check on the seam.
    expect(typeof store.mint).toBe("function");
  });
});
