/**
 * Express adapter. Translates requests; never decides policy.
 *
 * Two mount forms, both from one factory:
 *   app.use(installTokens.express(opts));   // a Router
 *   installTokens(app, opts);               // mounts and returns the Store
 *
 * The body is parsed INSIDE the handlers, after `authz`, so an unauthenticated
 * caller with malformed JSON gets 401 rather than 400 — the same ordering the
 * Python adapters enforce. If the adopter already ran a JSON parser, `req.body`
 * is reused as-is.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import express from "express";
import type { Express, Request, Response, Router } from "express";

import { Endpoints, type Limits, type SessionIdentity } from "./core.js";
import { DEFAULT as DEFAULT_EMITTER, Emitter, setSink, type EventSink } from "./events.js";
import { importEntries } from "./importer.js";
import { Store, ensureSchema } from "./store.js";

export interface TokenOptions {
  service: string;
  dbPath: string;
  siteOrigin: string;
  sessionResolver: (req: Request) => SessionIdentity | null;
  limits?: Limits;
  emitter?: Emitter;
  /** Reconfigures the process default sink; pass `emitter` for an isolated one. */
  eventSink?: EventSink;
  /** Existing config tokens to import at mount. */
  importTokens?: Array<Record<string, unknown>>;
  apiPrefix?: string;
  assetPath?: string;
  authHeader?: string;
}

/** Ship the component from src/ (which `files` includes), so one asset serves
 * both the repo and the published package without a copy-during-build step. */
const ASSET = fileURLToPath(new URL("../src/static/simsys-tokens.js", import.meta.url));

function normalizePath(p: string): string {
  return `/${p.replace(/^\/+|\/+$/g, "")}`;
}

async function rawBody(req: Request): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

async function readJsonBody(
  req: Request,
): Promise<{ body?: Record<string, unknown>; error?: string }> {
  const existing = (req as Request & { body?: unknown }).body;
  if (existing !== undefined && existing !== null && typeof existing === "object" && !Buffer.isBuffer(existing)) {
    return { body: existing as Record<string, unknown> };
  }
  const raw = req.readableEnded ? Buffer.alloc(0) : await rawBody(req);
  if (raw.length === 0) return { body: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    return { error: "request body is not valid JSON" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { error: "request body must be a JSON object" };
  }
  return { body: parsed as Record<string, unknown> };
}

function build(opts: TokenOptions): { router: Router; store: Store } {
  ensureSchema(opts.dbPath, { create: true });
  if (opts.eventSink) setSink(opts.eventSink);
  const api = normalizePath(opts.apiPrefix ?? "/api/tokens");
  const asset = normalizePath(opts.assetPath ?? "/simsys-tokens.js");
  const authHeader = opts.authHeader ?? "Authorization";
  const store = new Store(opts.dbPath, opts.service);
  const endpoints = new Endpoints(store, opts.siteOrigin, {
    emitter: opts.emitter,
    limits: opts.limits,
  });
  if (opts.importTokens) importEntries(store, opts.importTokens, { emitter: opts.emitter });

  const router = express.Router();

  function ctx(req: Request): {
    identity: SessionIdentity | null;
    bearer: string | null;
    origin: string | null;
    referer: string | null;
  } {
    let identity: SessionIdentity | null = null;
    try {
      identity = opts.sessionResolver(req) ?? null;
    } catch {
      // Adopter code must not turn a management endpoint into a 500; a raising
      // resolver is anonymous (401).
      identity = null;
    }
    const h = req.headers[authHeader.toLowerCase()];
    return {
      identity,
      bearer: typeof h === "string" ? h : null,
      origin: req.headers.origin ?? null,
      referer: req.headers.referer ?? null,
    };
  }

  router.get(api, (req, res) => {
    const { identity, bearer } = ctx(req);
    const out = endpoints.handleList(identity, bearer, req.query as Record<string, string>);
    res.status(out.status).json(out.body);
  });

  router.post(api, async (req, res) => {
    const { identity, bearer, origin, referer } = ctx(req);
    const refusal = endpoints.authz(identity, bearer); // BEFORE decoding the body
    if (refusal) return void res.status(refusal.status).json(refusal.body);
    const { body, error } = await readJsonBody(req);
    if (error) return void res.status(400).json({ error });
    const out = endpoints.handleCreate(identity, bearer, body!, origin, referer);
    res.status(out.status).json(out.body);
  });

  router.get(`${api}/:handle`, (req, res) => {
    const { identity, bearer } = ctx(req);
    const out = endpoints.handleGet(identity, bearer, req.params.handle);
    res.status(out.status).json(out.body);
  });

  router.patch(`${api}/:handle`, async (req, res) => {
    const { identity, bearer, origin, referer } = ctx(req);
    const refusal = endpoints.authz(identity, bearer);
    if (refusal) return void res.status(refusal.status).json(refusal.body);
    const { body, error } = await readJsonBody(req);
    if (error) return void res.status(400).json({ error });
    const out = endpoints.handlePatch(identity, bearer, req.params.handle, body!, origin, referer);
    res.status(out.status).json(out.body);
  });

  router.delete(`${api}/:handle`, (req, res) => {
    const { identity, bearer, origin, referer } = ctx(req);
    const out = endpoints.handleDelete(identity, bearer, req.params.handle, origin, referer);
    res.status(out.status).json(out.body);
  });

  // Deliberately OUTSIDE the API prefix: under file-based routing a path under
  // it collides with the :handle route.
  router.get(asset, (_req, res) => {
    res.type("application/javascript").send(readFileSync(ASSET, "utf8"));
  });

  return { router, store };
}

export interface InstallTokens {
  (app: Express, opts: TokenOptions): Store;
  express(opts: TokenOptions): Router;
}

export const installTokens: InstallTokens = Object.assign(
  (app: Express, opts: TokenOptions): Store => {
    const { router, store } = build(opts);
    app.use(router);
    return store;
  },
  { express: (opts: TokenOptions): Router => build(opts).router },
);

export { DEFAULT_EMITTER as defaultEmitter, Store, ensureSchema };
export type { EventSink, Limits, Request, Response, SessionIdentity };
