/**
 * SvelteKit adapter. Translates requests; never decides policy.
 *
 * File-routed, so it exports handler *sets* rather than a middleware:
 *
 *   // src/routes/api/tokens/+server.ts
 *   import { collection } from "@simsys/tokens/svelte";
 *   export const { GET, POST } = collection(opts);
 *
 *   // src/routes/api/tokens/[handle]/+server.ts
 *   import { item } from "@simsys/tokens/svelte";
 *   export const { GET, PATCH, DELETE } = item(opts);
 *
 *   // src/routes/simsys-tokens.js/+server.ts   <- outside /api/tokens/*, see below
 *   import { asset } from "@simsys/tokens/svelte";
 *   export const { GET } = asset();
 *
 * The asset MUST be mounted outside the API prefix: under file-based routing a
 * path under it resolves to the `[handle]` route, whose GET/DELETE handlers would
 * answer a `GET` with a 405, so the component never loads.
 *
 * No `@sveltejs/kit` dependency: the handlers are typed structurally against the
 * parts of `RequestEvent` SvelteKit actually passes (`request`, `url`, `params`),
 * so they type-check and test without the framework installed.
 *
 * Each factory builds its own Store/Endpoints (each `+server.ts` is a separate
 * module). That is safe — the store is the shared state — but `importTokens`, if
 * used, runs once per route file and relies on the importer being idempotent.
 */
import type { SessionIdentity } from "./core.js";
import { componentResponse, jsonResponse, readJsonRequest } from "./http.js";
import { buildCore, type BaseTokenOptions } from "./options.js";

export interface TokenOptions extends BaseTokenOptions {
  sessionResolver: (event: RequestEvent) => SessionIdentity | null;
}

/**
 * The subset of SvelteKit's `RequestEvent` these handlers use. Declared
 * structurally so the package needs no `@sveltejs/kit` dependency; a real
 * `RequestEvent` satisfies it.
 */
export interface RequestEvent {
  request: Request;
  url: URL;
  params: Record<string, string>;
}

function resolver(opts: TokenOptions, event: RequestEvent): SessionIdentity | null {
  try {
    return opts.sessionResolver(event) ?? null;
  } catch {
    // A raising resolver is anonymous (401), never a 500 — same contract as the
    // other adapters.
    return null;
  }
}

export function collection(opts: TokenOptions) {
  const { endpoints, authHeader } = buildCore(opts);

  return {
    GET: async (event: RequestEvent): Promise<Response> => {
      const out = endpoints.handleList(
        resolver(opts, event),
        event.request.headers.get(authHeader),
        Object.fromEntries(event.url.searchParams) as Record<string, string>,
      );
      return jsonResponse(out.status, out.body);
    },

    POST: async (event: RequestEvent): Promise<Response> => {
      const identity = resolver(opts, event);
      const bearer = event.request.headers.get(authHeader);
      const refusal = endpoints.authz(identity, bearer); // BEFORE decoding the body
      if (refusal) return jsonResponse(refusal.status, refusal.body);
      const { body, error } = await readJsonRequest(event.request);
      if (error) return jsonResponse(400, { error });
      const out = endpoints.handleCreate(
        identity,
        bearer,
        body!,
        event.request.headers.get("origin"),
        event.request.headers.get("referer"),
      );
      return jsonResponse(out.status, out.body);
    },
  };
}

export function item(opts: TokenOptions) {
  const { endpoints, authHeader } = buildCore(opts);

  return {
    GET: async (event: RequestEvent): Promise<Response> => {
      const out = endpoints.handleGet(
        resolver(opts, event),
        event.request.headers.get(authHeader),
        event.params.handle ?? "",
      );
      return jsonResponse(out.status, out.body);
    },

    PATCH: async (event: RequestEvent): Promise<Response> => {
      const identity = resolver(opts, event);
      const bearer = event.request.headers.get(authHeader);
      const refusal = endpoints.authz(identity, bearer);
      if (refusal) return jsonResponse(refusal.status, refusal.body);
      const { body, error } = await readJsonRequest(event.request);
      if (error) return jsonResponse(400, { error });
      const out = endpoints.handlePatch(
        identity,
        bearer,
        event.params.handle ?? "",
        body!,
        event.request.headers.get("origin"),
        event.request.headers.get("referer"),
      );
      return jsonResponse(out.status, out.body);
    },

    DELETE: async (event: RequestEvent): Promise<Response> => {
      const out = endpoints.handleDelete(
        resolver(opts, event),
        event.request.headers.get(authHeader),
        event.params.handle ?? "",
        event.request.headers.get("origin"),
        event.request.headers.get("referer"),
      );
      return jsonResponse(out.status, out.body);
    },
  };
}

/** The component asset. Needs no options — it reads nothing from the store. */
export function asset() {
  return { GET: async (_event: RequestEvent): Promise<Response> => componentResponse() };
}
