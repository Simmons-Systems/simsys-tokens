import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  handleOf,
  mintToken,
  tokenHash,
  validateHandle,
  validateRole,
  validateService,
} from "../src/hashing.js";

// The SAME fixture the Python suite reads. A change here must keep both green.
const VECTORS = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../tests/vectors.json"), "utf8"),
) as {
  hash_vectors: Array<{ raw: string; sha256: string }>;
  valid_slugs: string[];
  invalid_slugs: string[];
};

describe("tokenHash — shared cross-runtime vectors", () => {
  for (const v of VECTORS.hash_vectors) {
    it(`matches the fixture for ${v.raw.slice(0, 14)}…`, () => {
      expect(tokenHash(v.raw)).toBe(v.sha256);
    });
  }

  it("hashes the FULL token, not the hex tail", () => {
    const raw = `demo-read-${"a".repeat(64)}`;
    expect(tokenHash(raw)).toBe(createHash("sha256").update(raw, "utf8").digest("hex"));
    expect(tokenHash(raw)).not.toBe(createHash("sha256").update("a".repeat(64), "utf8").digest("hex"));
  });
});

describe("mintToken", () => {
  it("emits <service>-<role>-<64 hex> and is unique", () => {
    const tok = mintToken("demo", "agent");
    const [service, role, hex] = tok.split("-");
    expect([service, role, hex.length]).toEqual(["demo", "agent", 64]);
    expect(mintToken("demo", "agent")).not.toBe(mintToken("demo", "agent"));
  });
});

describe("slug validation", () => {
  for (const slug of VECTORS.valid_slugs) {
    it(`accepts ${JSON.stringify(slug)}`, () => {
      expect(() => validateService(slug)).not.toThrow();
      expect(() => validateRole(slug)).not.toThrow();
    });
  }
  for (const slug of VECTORS.invalid_slugs) {
    it(`rejects ${JSON.stringify(slug)}`, () => {
      expect(() => validateService(slug)).toThrow();
      expect(() => validateRole(slug)).toThrow();
    });
  }
  it("rejects a trailing newline (the Python $ quirk)", () => {
    expect(() => validateRole("agent\n")).toThrow();
    expect(() => validateService("demo\n")).toThrow();
  });
});

describe("handles", () => {
  it("is the first 16 hex of the digest", () => {
    expect(handleOf("a".repeat(64))).toBe("a".repeat(16));
  });
  for (const bad of ["a".repeat(15), "a".repeat(17), "A".repeat(16), "z".repeat(16), "", `${"a".repeat(16)}\n`]) {
    it(`rejects ${JSON.stringify(bad)}`, () => {
      expect(() => validateHandle(bad)).toThrow();
    });
  }
});
