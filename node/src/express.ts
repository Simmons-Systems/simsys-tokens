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
import express from "express";
import type { Express, Request, Router } from "express";

import type { SessionIdentity } from "./core.js";
import { componentSource, readJsonIncoming } from "./http.js";
import { buildCore, type BaseTokenOptions } from "./options.js";

export interface TokenOptions extends BaseTokenOptions {
  sessionResolver: (req: Request) => SessionIdentity | null;
  apiPrefix?: string;
  assetPath?: string;
}

function normalizePath(p: string): string {
  return `/${p.replace(/^\/+|\/+$/g, "")}`;
}

function build(opts: TokenOptions): { router: Router; core: ReturnType<typeof buildCore> } {
  const api = normalizePath(opts.apiPrefix ?? "/api/tokens");
  const asset = normalizePath(opts.assetPath ?? "/simsys-tokens.js");
  const core = buildCore(opts);
  const { endpoints, authHeader } = core;

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
    const { body, error } = await readJsonIncoming(req);
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
    const { body, error } = await readJsonIncoming(req);
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
    res.type("application/javascript").send(componentSource());
  });

  return { router, core };
}

export interface InstallTokens {
  (app: Express, opts: TokenOptions): ReturnType<typeof build>["core"]["store"];
  express(opts: TokenOptions): Router;
}

export const installTokens: InstallTokens = Object.assign(
  (app: Express, opts: TokenOptions) => {
    const { router, core } = build(opts);
    app.use(router);
    return core.store;
  },
  { express: (opts: TokenOptions): Router => build(opts).router },
);
