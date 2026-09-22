/**
 * Shared wiring for the adapters: the options every mount accepts, and the one
 * place that creates the schema, the Store and the Endpoints.
 *
 * Keeping this here is what stops the three adapters from drifting: an adapter
 * that built its own store would take a different schema-creation path, and one
 * that built its own Endpoints could disagree about policy.
 */
import { Endpoints, type Limits, type SessionIdentity } from "./core.js";
import { Emitter, setSink, type EventSink } from "./events.js";
import { importEntries } from "./importer.js";
import { Store, ensureSchema } from "./store.js";

export interface BaseTokenOptions {
  /** Token prefix and namespace; ^[a-z0-9_]{1,32}$ (no hyphens). */
  service: string;
  dbPath: string;
  /** Exact origin for the CSRF check, e.g. https://app.example.com. */
  siteOrigin: string;
  limits?: Limits;
  /** A private emitter, for a process hosting more than one service. */
  emitter?: Emitter;
  /** Reconfigures the process default sink (pass `emitter` for isolation). */
  eventSink?: EventSink;
  /** Existing config tokens to import at mount. */
  importTokens?: Array<Record<string, unknown>>;
  /** Header carrying the bearer; default Authorization. */
  authHeader?: string;
}

export interface Core {
  store: Store;
  endpoints: Endpoints;
  authHeader: string;
}

export function buildCore(opts: BaseTokenOptions): Core {
  ensureSchema(opts.dbPath, { create: true });
  if (opts.eventSink) setSink(opts.eventSink);
  const store = new Store(opts.dbPath, opts.service);
  const endpoints = new Endpoints(store, opts.siteOrigin, {
    emitter: opts.emitter,
    limits: opts.limits,
  });
  if (opts.importTokens) importEntries(store, opts.importTokens, { emitter: opts.emitter });
  return { store, endpoints, authHeader: opts.authHeader ?? "Authorization" };
}
