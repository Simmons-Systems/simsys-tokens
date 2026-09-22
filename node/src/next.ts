/**
 * Next.js App Router adapter. Translates requests; never decides policy.
 *
 * File-routed, so it exports handler *sets* rather than a middleware:
 *
 *   // app/api/tokens/route.ts
 *   import { collection } from "@simsys/tokens/next";
 *   export const { GET, POST } = collection(opts);
 *
 *   // app/api/tokens/[handle]/route.ts
 *   import { item } from "@simsys/tokens/next";
 *   export const { GET, PATCH, DELETE } = item(opts);
 *
 *   // app/simsys-tokens.js/route.ts      <- outside /api/tokens/*, see below
 *   import { asset } from "@simsys/tokens/next";
 *   export const { GET } = asset();
 *
 * The asset MUST be mounted outside the API prefix: under file-based routing a
 * path under it resolves to the `[handle]` route, which exports only
 * GET/PATCH/DELETE for an item — a `GET` there is a 405 and the component never
 * loads.
 *
 * No `next` dependency: these handlers take a Web `Request` and return a Web
 * `Response`, so they type-check and test against the runtime globals alone.
 *
 * Each factory builds its own Store/Endpoints (each route file is a separate
 * module). That is safe — the store is the shared state — but `importTokens`, if
 * used, runs once per route file and relies on the importer being idempotent.
 */
import type { SessionIdentity } from "./core.js";
import { componentResponse, jsonResponse, readJsonRequest, type BodyResult } from "./http.js";
import { buildCore, type BaseTokenOptions } from "./options.js";

export interface TokenOptions extends BaseTokenOptions {
  sessionResolver: (request: Request) => SessionIdentity | null;
}

/** Next 15 passes `params` as a Promise; earlier versions pass an object. Accept
 * both without pinning the adapter to a Next major. */
export interface RouteContext {
  params?: Promise<Record<string, string>> | Record<string, string>;
}

function resolver(opts: TokenOptions, request: Request): SessionIdentity | null {
  try {
    return opts.sessionResolver(request) ?? null;
  } catch {
    // A raising resolver is anonymous (401), never a 500 — same contract as the
    // other adapters.
    return null;
  }
}

async function handleFrom(context?: RouteContext): Promise<string> {
  const raw = context?.params;
  const resolved =
    raw && typeof (raw as Promise<Record<string, string>>).then === "function"
      ? await (raw as Promise<Record<string, string>>)
      : (raw as Record<string, string> | undefined);
  return resolved?.handle ?? "";
}

export function collection(opts: TokenOptions) {
  const { endpoints, authHeader } = buildCore(opts);

  return {
    GET: async (request: Request): Promise<Response> => {
      const out = endpoints.handleList(
        resolver(opts, request),
        request.headers.get(authHeader),
        Object.fromEntries(new URL(request.url).searchParams) as Record<string, string>,
      );
      return jsonResponse(out.status, out.body);
    },

    POST: async (request: Request): Promise<Response> => {
      const identity = resolver(opts, request);
      const bearer = request.headers.get(authHeader);
      const refusal = endpoints.authz(identity, bearer); // BEFORE decoding the body
      if (refusal) return jsonResponse(refusal.status, refusal.body);
      const { body, error }: BodyResult = await readJsonRequest(request);
      if (error) return jsonResponse(400, { error });
      const out = endpoints.handleCreate(
        identity,
        bearer,
        body!,
        request.headers.get("origin"),
        request.headers.get("referer"),
      );
      return jsonResponse(out.status, out.body);
    },
  };
}

export function item(opts: TokenOptions) {
  const { endpoints, authHeader } = buildCore(opts);

  return {
    GET: async (request: Request, context?: RouteContext): Promise<Response> => {
      const out = endpoints.handleGet(
        resolver(opts, request),
        request.headers.get(authHeader),
        await handleFrom(context),
      );
      return jsonResponse(out.status, out.body);
    },

    PATCH: async (request: Request, context?: RouteContext): Promise<Response> => {
      const identity = resolver(opts, request);
      const bearer = request.headers.get(authHeader);
      const refusal = endpoints.authz(identity, bearer);
      if (refusal) return jsonResponse(refusal.status, refusal.body);
      const { body, error } = await readJsonRequest(request);
      if (error) return jsonResponse(400, { error });
      const out = endpoints.handlePatch(
        identity,
        bearer,
        await handleFrom(context),
        body!,
        request.headers.get("origin"),
        request.headers.get("referer"),
      );
      return jsonResponse(out.status, out.body);
    },

    DELETE: async (request: Request, context?: RouteContext): Promise<Response> => {
      const out = endpoints.handleDelete(
        resolver(opts, request),
        request.headers.get(authHeader),
        await handleFrom(context),
        request.headers.get("origin"),
        request.headers.get("referer"),
      );
      return jsonResponse(out.status, out.body);
    },
  };
}

/** The component asset. Needs no options — it reads nothing from the store. */
export function asset() {
  return { GET: async (_request: Request): Promise<Response> => componentResponse() };
}
