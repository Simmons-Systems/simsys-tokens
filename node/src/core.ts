/**
 * Framework-agnostic policy. Adapters translate; they never decide.
 *
 * Every status code, guard and validation rule lives here, so the Express
 * adapter can never disagree with a future Next/Svelte adapter about them.
 */
import { checkOrigin } from "./csrf.js";
import { DEFAULT as DEFAULT_EMITTER, Emitter } from "./events.js";
import { tokenHash, validateHandle, validateRole } from "./hashing.js";
import type { TokenRow, Store } from "./store.js";
import { normalizeExpiresAt } from "./store.js";
import { AmbiguousHandle, NoSuchHandle } from "./errors.js";

export const LAST_USED_THROTTLE_SECONDS = 60;
export const AUTH_FAILED_THROTTLE_SECONDS = 60;
export const MAX_RAW_LEN = 256;
export const MAX_LABEL_LEN = 64;

const TOKEN_RE = /^[a-z0-9_]{1,32}-[a-z0-9_]{1,32}-[0-9a-f]{64}$/;
const PATCHABLE = new Set(["label", "priority", "rate_limit", "expires_at"]);

export interface SessionIdentity {
  user: string;
  isOperator: boolean;
}

export interface TokenInfo {
  handle: string;
  label: string;
  role: string;
  priority: number | null;
  rateLimit: string | null;
  tokenSha256: string;
  expiresAt: string | null;
}

export interface Limits {
  lastUsedThrottle?: number;
  authFailedThrottle?: number;
  maxRawLen?: number;
  maxLabelLen?: number;
}

export interface Result {
  status: number;
  body: Record<string, unknown>;
}

interface AuthCtx {
  emitter?: Emitter;
  limits?: Limits;
}

function resolvedLimits(limits?: Limits): Required<Limits> {
  return {
    lastUsedThrottle: limits?.lastUsedThrottle ?? LAST_USED_THROTTLE_SECONDS,
    authFailedThrottle: limits?.authFailedThrottle ?? AUTH_FAILED_THROTTLE_SECONDS,
    maxRawLen: limits?.maxRawLen ?? MAX_RAW_LEN,
    maxLabelLen: limits?.maxLabelLen ?? MAX_LABEL_LEN,
  };
}

function extractBearer(header: string | null | undefined): string | null {
  if (!header || !header.startsWith("Bearer ")) return null;
  return header.slice("Bearer ".length) || null;
}

function wellFormed(raw: string, maxRawLen: number): boolean {
  // Shape check BEFORE hashing: hashing arbitrary-length attacker input on the
  // hot auth path is a CPU-DoS vector, and a malformed token cannot resolve.
  return raw.length <= maxRawLen && TOKEN_RE.test(raw);
}

function emitAuthFailedOnce(
  store: Store,
  emitter: Emitter,
  limits: Required<Limits>,
  key: string,
  fields: { handle?: string | null; label?: string | null; digestPrefix?: string | null; reason: string },
): void {
  // Map-presence, not a 0 default: Date.now() counts from an arbitrary epoch and
  // is well under any throttle window on a freshly booted host, so `now - 0 <
  // window` would swallow the FIRST failure entirely.
  const now = Date.now();
  const last = store.lastAuthFailed.get(key);
  if (last !== undefined && now - last < limits.authFailedThrottle * 1000) return;
  store.touchNote(store.lastAuthFailed, key, now);
  emitter.tokenAuthFailed(store.service, fields);
}

export function authenticate(
  store: Store,
  authorizationHeader: string | null | undefined,
  ctx: AuthCtx = {},
): TokenInfo | null {
  const emitter = ctx.emitter ?? DEFAULT_EMITTER;
  const limits = resolvedLimits(ctx.limits);
  const raw = extractBearer(authorizationHeader);
  if (raw === null) return null;
  if (!wellFormed(raw, limits.maxRawLen)) {
    emitAuthFailedOnce(store, emitter, limits, `malformed:${raw.slice(0, 16)}`, {
      handle: null,
      label: null,
      digestPrefix: null,
      reason: "malformed",
    });
    return null;
  }
  const digest = tokenHash(raw);
  const row = store.lookupLive(digest);
  if (!row) {
    const any = store.findAny(digest);
    if (!any) {
      emitAuthFailedOnce(store, emitter, limits, `unknown:${digest.slice(0, 16)}`, {
        digestPrefix: digest.slice(0, 16),
        reason: "unknown",
      });
    } else if (any.revoked_at !== null) {
      emitAuthFailedOnce(store, emitter, limits, `revoked:${digest.slice(0, 16)}`, {
        handle: digest.slice(0, 16),
        label: any.label,
        reason: "revoked",
      });
    } else {
      // Present, not revoked, and lookupLive filtered it — so it expired.
      emitAuthFailedOnce(store, emitter, limits, `expired:${digest.slice(0, 16)}`, {
        handle: digest.slice(0, 16),
        label: any.label,
        reason: "expired",
      });
    }
    return null;
  }
  // Capture first-use BEFORE the throttled touch, since touch clears it.
  const firstUse = row.last_used_at === null;
  const now = Date.now();
  const claimed = firstUse && store.lastTouch.get(digest) === undefined;
  const last = store.lastTouch.get(digest) ?? 0;
  const shouldTouch = now - last >= limits.lastUsedThrottle * 1000 || claimed;
  if (shouldTouch) store.touchNote(store.lastTouch, digest, now);
  if (shouldTouch) store.touchLastUsed(digest);
  if (claimed) emitter.tokenFirstUse(store.service, digest.slice(0, 16), row.label);
  return {
    handle: digest.slice(0, 16),
    label: row.label,
    role: row.role,
    priority: row.priority,
    rateLimit: row.rate_limit,
    tokenSha256: digest,
    expiresAt: row.expires_at,
  };
}

/** Return an error string, or null. */
export function validatePolicy(body: Record<string, unknown>): string | null {
  const priority = body.priority;
  if (priority !== undefined && priority !== null) {
    if (typeof priority !== "number" || !Number.isInteger(priority)) {
      return "priority must be an integer or null";
    }
  }
  const rateLimit = body.rate_limit;
  if (rateLimit !== undefined && rateLimit !== null) {
    if (typeof rateLimit !== "string") return "rate_limit must be a JSON string or null";
    let parsed: unknown;
    try {
      parsed = JSON.parse(rateLimit);
    } catch {
      return "rate_limit must parse as JSON";
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return "rate_limit must be a JSON object";
    }
  }
  if ("expires_at" in body) {
    try {
      normalizeExpiresAt(body.expires_at);
    } catch (err) {
      return (err as Error).message;
    }
  }
  return null;
}

export function rowToPublic(row: TokenRow): Record<string, unknown> {
  return {
    handle: row.token_sha256.slice(0, 16),
    label: row.label,
    role: row.role,
    priority: row.priority,
    rate_limit: row.rate_limit,
    expires_at: row.expires_at,
    created_at: row.created_at,
    created_by: row.created_by,
    last_used_at: row.last_used_at,
    revoked_at: row.revoked_at,
    revoked_by: row.revoked_by,
  };
}

export class Endpoints {
  readonly store: Store;
  readonly siteOrigin: string;
  readonly emitter: Emitter;
  readonly limits: Required<Limits>;

  constructor(store: Store, siteOrigin: string, ctx: AuthCtx = {}) {
    // Validate at construction: a typo'd site_origin must fail at startup, not
    // raise a 500 on every mutating request.
    checkOrigin(siteOrigin, siteOrigin, null);
    this.store = store;
    this.siteOrigin = siteOrigin;
    this.emitter = ctx.emitter ?? DEFAULT_EMITTER;
    this.limits = resolvedLimits(ctx.limits);
  }

  /** Credentials first, always. Public so an adapter can refuse BEFORE decoding
   * a body — parsing unauthenticated JSON is work done on their behalf and
   * reorders 401 vs 400. */
  authz(identity: SessionIdentity | null, bearer: string | null | undefined): Result | null {
    if (bearer) return { status: 403, body: { error: "bearer tokens may not reach management endpoints" } };
    if (identity === null) return { status: 401, body: { error: "authentication required" } };
    if (!identity.isOperator) return { status: 403, body: { error: "operator privilege required" } };
    return null;
  }

  private csrf(origin: string | null | undefined, referer: string | null | undefined): Result | null {
    if (!checkOrigin(this.siteOrigin, origin, referer)) {
      return { status: 403, body: { error: "origin check failed" } };
    }
    return null;
  }

  handleList(
    identity: SessionIdentity | null,
    bearer: string | null | undefined,
    params: Record<string, string>,
  ): Result {
    const refusal = this.authz(identity, bearer);
    if (refusal) return refusal;
    const include = params.include === "revoked";
    const rawLimit = params.limit === undefined ? this.store.maxLimit : Number(params.limit);
    if (params.limit !== undefined && (!Number.isFinite(rawLimit) || !Number.isInteger(rawLimit))) {
      return { status: 400, body: { error: "limit must be an integer" } };
    }
    const label = params.label ?? null;
    const { rows, hasMore } = this.store.listRows({
      includeRevoked: include,
      limit: rawLimit,
      label,
    });
    return { status: 200, body: { tokens: rows.map(rowToPublic), has_more: hasMore } };
  }

  handleGet(identity: SessionIdentity | null, bearer: string | null | undefined, handle: string): Result {
    const refusal = this.authz(identity, bearer);
    if (refusal) return refusal;
    try {
      return { status: 200, body: rowToPublic(this.store.resolveHandle(handle)) };
    } catch (err) {
      return this.handleError(err);
    }
  }

  handleCreate(
    identity: SessionIdentity | null,
    bearer: string | null | undefined,
    body: Record<string, unknown>,
    origin: string | null | undefined,
    referer: string | null | undefined,
  ): Result {
    const refusal = this.authz(identity, bearer) ?? this.csrf(origin, referer);
    if (refusal) return refusal;
    const label = body.label;
    const role = body.role;
    if (!label || typeof label !== "string" || !role) {
      return { status: 400, body: { error: "label and role are required" } };
    }
    if (label.length > this.limits.maxLabelLen) {
      return { status: 400, body: { error: `label must be <= ${this.limits.maxLabelLen} characters` } };
    }
    try {
      validateRole(role);
    } catch (err) {
      return { status: 400, body: { error: (err as Error).message } };
    }
    const bad = validatePolicy(body);
    if (bad) return { status: 400, body: { error: bad } };
    let minted: { raw: string; handle: string };
    try {
      minted = this.store.mint(role, label, `session:${identity!.user}`, {
        priority: (body.priority as number | null | undefined) ?? null,
        rateLimit: (body.rate_limit as string | null | undefined) ?? null,
        expiresAt: (body.expires_at as string | null | undefined) ?? null,
      });
    } catch (err) {
      if (isUniqueViolation(err)) {
        return { status: 409, body: { error: `label ${JSON.stringify(label)} is already in use by a live token` } };
      }
      throw err;
    }
    this.emitter.tokenCreated(this.store.service, minted.handle, label, role, `session:${identity!.user}`);
    return { status: 201, body: { handle: minted.handle, token: minted.raw } };
  }

  handlePatch(
    identity: SessionIdentity | null,
    bearer: string | null | undefined,
    handle: string,
    body: Record<string, unknown>,
    origin: string | null | undefined,
    referer: string | null | undefined,
  ): Result {
    const refusal = this.authz(identity, bearer) ?? this.csrf(origin, referer);
    if (refusal) return refusal;
    const unknownKeys = Object.keys(body).filter((k) => !PATCHABLE.has(k));
    if (unknownKeys.length > 0) {
      return { status: 400, body: { error: `not mutable: ${JSON.stringify(unknownKeys.sort())}` } };
    }
    if ("label" in body) {
      if (typeof body.label !== "string" || body.label === "") {
        return { status: 400, body: { error: "label must be a non-empty string" } };
      }
      if (body.label.length > this.limits.maxLabelLen) {
        return { status: 400, body: { error: `label must be <= ${this.limits.maxLabelLen} characters` } };
      }
    }
    const bad = validatePolicy(body);
    if (bad) return { status: 400, body: { error: bad } };
    let row: TokenRow;
    try {
      row = this.store.resolveHandle(handle);
    } catch (err) {
      return this.handleError(err);
    }
    const newLabel = body.label as string | undefined;
    const actor = `session:${identity!.user}`;
    let updated: TokenRow;
    try {
      updated = this.store.updateRow(handle, {
        label: newLabel ?? null,
        priority: "priority" in body ? (body.priority as number | null) : undefined,
        rateLimit: "rate_limit" in body ? (body.rate_limit as string | null) : undefined,
        expiresAt: "expires_at" in body ? (body.expires_at as string | null) : undefined,
      });
    } catch (err) {
      if (isUniqueViolation(err)) {
        return { status: 409, body: { error: `label ${JSON.stringify(newLabel)} is already in use by a live token` } };
      }
      throw err;
    }
    if (newLabel && newLabel !== row.label) {
      this.emitter.tokenRelabelled(this.store.service, handle, row.label, newLabel, actor);
    }
    for (const [field, current] of [
      ["priority", row.priority],
      ["rate_limit", row.rate_limit],
      ["expires_at", row.expires_at],
    ] as const) {
      if (field in body && body[field] !== current) {
        this.emitter.tokenPolicyChanged(this.store.service, handle, field, current, body[field], actor);
      }
    }
    return { status: 200, body: rowToPublic(updated) };
  }

  handleDelete(
    identity: SessionIdentity | null,
    bearer: string | null | undefined,
    handle: string,
    origin: string | null | undefined,
    referer: string | null | undefined,
  ): Result {
    const refusal = this.authz(identity, bearer) ?? this.csrf(origin, referer);
    if (refusal) return refusal;
    let row: TokenRow;
    try {
      row = this.store.resolveHandle(handle);
    } catch (err) {
      return this.handleError(err);
    }
    const { row: updated, changed } = this.store.revoke(handle, `session:${identity!.user}`);
    if (changed) {
      // Only a real live->revoked transition emits; a repeat DELETE is a no-op.
      this.emitter.tokenRevoked(this.store.service, handle, row.label, `session:${identity!.user}`);
    }
    return { status: 200, body: rowToPublic(updated) };
  }

  private handleError(err: unknown): Result {
    if (err instanceof NoSuchHandle) return { status: 404, body: { error: "no such token" } };
    if (err instanceof AmbiguousHandle) return { status: 409, body: { error: "handle is ambiguous" } };
    if (err instanceof Error && !(err instanceof NoSuchHandle)) {
      // validateHandle raises a plain Error with a useful sentence.
      if (/^handle must be/.test(err.message)) return { status: 400, body: { error: err.message } };
    }
    throw err;
  }
}

function isUniqueViolation(err: unknown): boolean {
  const message = (err as { message?: string })?.message ?? "";
  return /UNIQUE constraint failed/i.test(message);
}
