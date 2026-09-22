import { describe, expect, it } from "vitest";

import type { SessionIdentity } from "../src/core.js";
import { asset, collection, item, type RequestEvent, type TokenOptions } from "../src/svelte.js";
import { tempDb } from "./helpers.js";

const SITE = "https://tokens.example.com";
const OP: SessionIdentity = { user: "leon", isOperator: true };
const MEMBER: SessionIdentity = { user: "member", isOperator: false };
const BASE = "https://app.example.com/api/tokens";

/**
 * One mount per test, so the collection and item handler sets share a store —
 * mirroring the two `+server.ts` files an adopter writes, which the SQLite file
 * joins.
 */
function mount(identity: SessionIdentity | null = OP, overrides: Partial<TokenOptions> = {}) {
  const opts: TokenOptions = {
    service: "demo",
    dbPath: tempDb(),
    siteOrigin: SITE,
    sessionResolver: () => identity,
    ...overrides,
  };
  return { collection: collection(opts), item: item(opts), asset: asset() };
}

/** The subset of RequestEvent SvelteKit passes; the adapter is typed against it. */
function event(url: string, init: RequestInit = {}, params: Record<string, string> = {}): RequestEvent {
  return { request: new Request(url, init), url: new URL(url), params };
}

function post(
  url: string,
  body?: unknown,
  headers: Record<string, string> = {},
  params: Record<string, string> = {},
) {
  return event(
    url,
    {
      method: "POST",
      headers: { origin: SITE, "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    },
    params,
  );
}

function patch(url: string, body: unknown, params: Record<string, string> = {}) {
  return event(
    url,
    {
      method: "PATCH",
      headers: { origin: SITE, "content-type": "application/json" },
      body: JSON.stringify(body),
    },
    params,
  );
}

describe("SvelteKit adapter", () => {
  it("creates then lists, and never repeats the secret", async () => {
    const m = mount();
    const created = await m.collection.POST(post(BASE, { label: "scout", role: "agent" }));
    expect(created.status).toBe(201);
    const { token } = (await created.json()) as { token: string };

    const listed = await m.collection.GET(event(BASE));
    expect(listed.status).toBe(200);
    const body = (await listed.json()) as { tokens: unknown[] };
    expect(body.tokens).toHaveLength(1);
    expect(JSON.stringify(body)).not.toContain(token);
  });

  it("serves the component asset", async () => {
    const res = await mount().asset.GET(event("https://app.example.com/simsys-tokens.js"));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("javascript");
    expect(await res.text()).toContain("customElements.define");
  });

  it("401 for anonymous, 403 for a bearer and for a non-operator", async () => {
    const anon = await mount(null).collection.GET(event(BASE));
    expect(anon.status).toBe(401);
    const member = await mount(MEMBER).collection.GET(event(BASE));
    expect(member.status).toBe(403);
    const bearer = await mount(null).collection.GET(
      event(BASE, { headers: { authorization: `Bearer demo-agent-${"a".repeat(64)}` } }),
    );
    expect(bearer.status).toBe(403);
  });

  it("401 (not 400) for an unauthenticated caller with malformed JSON", async () => {
    const res = await mount(null).collection.POST(
      event(BASE, {
        method: "POST",
        headers: { origin: SITE, "content-type": "application/json" },
        body: "{not json",
      }),
    );
    expect(res.status).toBe(401);
  });

  it("accepts JSON with no Content-Type header", async () => {
    const res = await mount().collection.POST(
      event(BASE, { method: "POST", headers: { origin: SITE }, body: '{"label":"noct","role":"agent"}' }),
    );
    expect(res.status).toBe(201);
  });

  it("400 for a body that is not a JSON object", async () => {
    for (const raw of ["null", "[1,2]", '"str"']) {
      const res = await mount().collection.POST(
        event(BASE, {
          method: "POST",
          headers: { origin: SITE, "content-type": "application/json" },
          body: raw,
        }),
      );
      expect(res.status).toBe(400);
    }
  });

  it("rejects a foreign origin", async () => {
    const res = await mount().collection.POST(
      post(BASE, { label: "x", role: "agent" }, { origin: "https://evil.example" }),
    );
    expect(res.status).toBe(403);
  });

  it("409 on a duplicate live label", async () => {
    const m = mount();
    await m.collection.POST(post(BASE, { label: "dup", role: "agent" }));
    const again = await m.collection.POST(post(BASE, { label: "dup", role: "agent" }));
    expect(again.status).toBe(409);
  });

  it("item routes resolve the handle from event.params", async () => {
    const m = mount();
    const created = await m.collection.POST(post(BASE, { label: "one", role: "agent" }));
    const { handle } = (await created.json()) as { handle: string };
    const url = `${BASE}/${handle}`;

    const got = await m.item.GET(event(url, {}, { handle }));
    expect(got.status).toBe(200);
    expect(((await got.json()) as { label: string }).label).toBe("one");

    const patched = await m.item.PATCH(patch(url, { label: "two" }, { handle }));
    expect(patched.status).toBe(200);
    expect(((await patched.json()) as { label: string }).label).toBe("two");

    const deleted = await m.item.DELETE(
      event(url, { method: "DELETE", headers: { origin: SITE } }, { handle }),
    );
    expect(deleted.status).toBe(200);
    expect(((await deleted.json()) as { revoked_at: string | null }).revoked_at).not.toBeNull();
  });

  it("404 for an unknown handle", async () => {
    const res = await mount().item.GET(event(`${BASE}/${"0".repeat(16)}`, {}, { handle: "0".repeat(16) }));
    expect(res.status).toBe(404);
  });

  it("supports expiry and reports it distinctly from revoked", async () => {
    const m = mount();
    const created = await m.collection.POST(
      post(BASE, { label: "tmp", role: "agent", expires_at: "2000-01-01T00:00:00+00:00" }),
    );
    expect(created.status).toBe(201);
    const { handle } = (await created.json()) as { handle: string };
    const got = await m.item.GET(event(`${BASE}/${handle}`, {}, { handle }));
    expect(((await got.json()) as { expires_at: string }).expires_at).toBe("2000-01-01T00:00:00+00:00");
  });

  it("treats a raising session resolver as anonymous", async () => {
    const m = mount(OP, {
      sessionResolver: () => {
        throw new Error("adopter bug");
      },
    });
    expect((await m.collection.GET(event(BASE))).status).toBe(401);
  });
});
