import { describe, expect, it } from "vitest";

import { checkOrigin } from "../src/csrf.js";

const SITE = "https://tokens.example.com";

describe("checkOrigin", () => {
  it("passes an exact origin", () => {
    expect(checkOrigin(SITE, SITE, null)).toBe(true);
  });
  it("fails a foreign origin", () => {
    expect(checkOrigin(SITE, "https://evil.example", null)).toBe(false);
  });
  it("accepts a referer when Origin is absent", () => {
    expect(checkOrigin(SITE, null, `${SITE}/ui/`)).toBe(true);
  });
  it("fails a foreign referer", () => {
    expect(checkOrigin(SITE, null, "https://evil.example/x")).toBe(false);
  });
  it("fails closed when neither header is present", () => {
    expect(checkOrigin(SITE, null, null)).toBe(false);
  });
  for (const near of [
    "https://tokens.example.com.evil.example",
    "http://tokens.example.com",
    "https://tokens.example.com:8443",
  ]) {
    it(`fails the near miss ${near}`, () => {
      expect(checkOrigin(SITE, near, null)).toBe(false);
    });
  }
  it("throws when site_origin is not absolute", () => {
    expect(() => checkOrigin("not-an-origin", "not-an-origin", null)).toThrow();
  });
});
