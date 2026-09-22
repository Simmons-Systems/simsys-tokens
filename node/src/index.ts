/**
 * @simsys/tokens — drop-in API-token store, auth and management surface.
 *
 * Public API. The Express adapter is `.` (this module) and `./express`; a
 * framework-free core is exported for anything else.
 */
export { installTokens } from "./express.js";
export type { InstallTokens, TokenOptions } from "./express.js";

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
