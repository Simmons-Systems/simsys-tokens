/**
 * @simsys/tokens — the framework-free core.
 *
 * This entry point deliberately imports NO framework. Adapters are separate
 * subpaths, each with its own peer:
 *
 *   import { installTokens } from "@simsys/tokens/express";   // Express (peer: express)
 *   import { collection } from "@simsys/tokens/next";         // Next.js App Router (no peer)
 *   import { collection } from "@simsys/tokens/svelte";       // SvelteKit (no peer)
 *
 * The Next and SvelteKit adapters take Web `Request`/`Response` (and, for
 * SvelteKit, a structurally-typed `RequestEvent`), so they need no framework
 * dependency at all. Only Express is imported at runtime, which is why its peer
 * is optional rather than required.
 */
export { Endpoints, authenticate, rowToPublic, validatePolicy } from "./core.js";
export type { Limits, Result, SessionIdentity, TokenInfo } from "./core.js";

export { Emitter, DEFAULT as defaultEmitter, setSink } from "./events.js";
export type { EventSink } from "./events.js";

export { importEntries } from "./importer.js";
export type { ImportReport } from "./importer.js";

export { Store, ensureSchema, isExpired, normalizeExpiresAt, utcNow } from "./store.js";
export type { TokenRow } from "./store.js";

export { AmbiguousHandle, NoSuchHandle, TokenError } from "./errors.js";

export {
  HANDLE_LEN,
  handleOf,
  mintToken,
  tokenHash,
  validateHandle,
  validateRole,
  validateService,
} from "./hashing.js";

export { checkOrigin, originOf } from "./csrf.js";

// Shared adapter plumbing, exported for anyone building a fourth adapter.
export { buildCore } from "./options.js";
export type { BaseTokenOptions, Core } from "./options.js";
export { componentResponse, componentSource, jsonResponse, readJsonRequest } from "./http.js";
export type { BodyResult } from "./http.js";
