/**
 * Request/response helpers shared by the adapters, so the JSON-body rules and the
 * component asset live in exactly one place.
 *
 * The body rules are the Python adapters' rules, deliberately: a JSON `null` or an
 * array is 400, an empty body is `{}`, malformed JSON is 400 — and the body is
 * parsed AFTER the credential check, so an unauthenticated caller gets 401 rather
 * than 400.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const JSON_INVALID = "request body is not valid JSON";
export const JSON_NOT_OBJECT = "request body must be a JSON object";

export interface BodyResult {
  body?: Record<string, unknown>;
  error?: string;
}

/** Ship the component from src/ (which `files` includes), so one asset serves the
 * repo, the published tarball, and all three adapters without a copy step. */
const ASSET = fileURLToPath(new URL("../src/static/simsys-tokens.js", import.meta.url));

export function componentSource(): string {
  return readFileSync(ASSET, "utf8");
}

export function componentResponse(): Response {
  return new Response(componentSource(), {
    headers: { "content-type": "application/javascript; charset=utf-8" },
  });
}

export function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function validateObject(value: unknown): BodyResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { error: JSON_NOT_OBJECT };
  }
  return { body: value as Record<string, unknown> };
}

function parseText(text: string): BodyResult {
  if (!text) return { body: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { error: JSON_INVALID };
  }
  return validateObject(parsed);
}

/** Parse a JSON object body from a Web `Request` (Next.js, SvelteKit). */
export async function readJsonRequest(request: Request): Promise<BodyResult> {
  return parseText(await request.text());
}

/** Parse a JSON object body from an Express request, reusing a body an upstream
 * parser already produced rather than re-reading the stream. */
export async function readJsonIncoming(req: {
  body?: unknown;
  readableEnded?: boolean;
  [Symbol.asyncIterator]?: () => AsyncIterator<unknown>;
}): Promise<BodyResult> {
  const existing = req.body;
  if (
    existing !== undefined &&
    existing !== null &&
    typeof existing === "object" &&
    !Buffer.isBuffer(existing)
  ) {
    return validateObject(existing);
  }
  if (req.readableEnded) return { body: {} };
  const chunks: Buffer[] = [];
  for await (const chunk of req as AsyncIterable<Buffer>) chunks.push(chunk as Buffer);
  return parseText(Buffer.concat(chunks).toString("utf8"));
}
