/**
 * Token minting, hashing and slug validation.
 *
 * The preimage is the FULL token string, not its hex tail. Getting this wrong is
 * silent: a mismatched preimage yields a well-formed digest that simply never
 * matches, so every token fails auth and every ownership check says "not
 * yours". The Python package and the Node package share tests/vectors.json to
 * pin this agreement.
 */
import { createHash, randomBytes } from "node:crypto";

// Anchored, and with no `$`-before-newline quirk: JS `$` matches only at the end
// (no `m` flag), so "agent\n" is correctly rejected here. Python needs
// fullmatch for the same guarantee — see the Python hashing module.
const SLUG_RE = /^[a-z0-9_]{1,32}$/;
const HANDLE_RE = /^[0-9a-f]{16}$/;

export const HANDLE_LEN = 16;

export function tokenHash(raw: string): string {
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

function validateSlug(value: unknown, what: string): asserts value is string {
  if (typeof value !== "string" || !SLUG_RE.test(value)) {
    throw new Error(
      `${what} must match ^[a-z0-9_]{1,32}$ (no hyphens); got ${JSON.stringify(value)}`,
    );
  }
}

export function validateService(service: unknown): asserts service is string {
  validateSlug(service, "service");
}

export function validateRole(role: unknown): asserts role is string {
  validateSlug(role, "role");
}

export function validateHandle(handle: unknown): asserts handle is string {
  if (typeof handle !== "string" || !HANDLE_RE.test(handle)) {
    throw new Error(
      `handle must be exactly 16 lowercase hex chars; got ${JSON.stringify(handle)}`,
    );
  }
}

export function mintToken(service: string, role: string): string {
  validateService(service);
  validateRole(role);
  return `${service}-${role}-${randomBytes(32).toString("hex")}`;
}

export function handleOf(digest: string): string {
  return digest.slice(0, HANDLE_LEN);
}
