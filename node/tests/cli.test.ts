import { execFileSync } from "node:child_process";
import { existsSync, symlinkSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { main } from "../src/cli.js";
import { tempDb } from "./helpers.js";

let out: string[];
let err: string[];
let origOut: typeof process.stdout.write;
let origErr: typeof process.stderr.write;

beforeEach(() => {
  out = [];
  err = [];
  origOut = process.stdout.write;
  origErr = process.stderr.write;
  (process.stdout.write as unknown as (s: string) => boolean) = (s: string) => {
    out.push(String(s));
    return true;
  };
  (process.stderr.write as unknown as (s: string) => boolean) = (s: string) => {
    err.push(String(s));
    return true;
  };
});

afterEach(() => {
  process.stdout.write = origOut;
  process.stderr.write = origErr;
});

const text = (xs: string[]) => xs.join("");

describe("CLI", () => {
  it("mint --init creates the store and prints the token once", () => {
    const db = tempDb();
    expect(main(["mint", "--init", "--service", "demo", "--role", "agent", "--label", "s", "--db", db])).toBe(0);
    expect(existsSync(db)).toBe(true);
    expect(text(out)).toContain("demo-agent-");
  });

  it("mint without --init refuses a missing store", () => {
    const db = tempDb();
    expect(main(["mint", "--service", "demo", "--role", "agent", "--label", "s", "--db", db])).not.toBe(0);
  });

  it("list, revoke and verify never create the store", () => {
    const db = tempDb();
    expect(main(["list", "--service", "demo", "--db", db])).not.toBe(0);
    expect(main(["revoke", "--service", "demo", "--handle", "0".repeat(16), "--db", db])).not.toBe(0);
    expect(main(["verify", "--service", "demo", "--db", db, "--token", "x"])).not.toBe(0);
    expect(existsSync(db)).toBe(false);
  });

  it("list --json never shows the secret", () => {
    const db = tempDb();
    main(["mint", "--init", "--service", "demo", "--role", "agent", "--label", "scout", "--db", db]);
    const raw = text(out).trim().split("\n").pop() as string;
    out.length = 0;
    main(["list", "--service", "demo", "--db", db, "--json"]);
    const listed = text(out);
    expect(listed).not.toContain(raw);
    expect(JSON.parse(listed)[0].label).toBe("scout");
  });

  it("verify: live (0), revoked (1), expired (1), unknown (1)", () => {
    const db = tempDb();
    main(["mint", "--init", "--service", "demo", "--role", "agent", "--label", "v", "--db", db]);
    const raw = text(out).trim().split("\n").pop() as string;
    out.length = 0;

    expect(main(["verify", "--service", "demo", "--db", db, "--token", raw])).toBe(0);
    expect(text(out)).toContain("live");

    // stdin path, via the seam.
    out.length = 0;
    expect(main(["verify", "--service", "demo", "--db", db], { readStdin: () => `${raw}\n` })).toBe(0);

    expect(main(["verify", "--service", "demo", "--db", db, "--token", `demo-agent-${"0".repeat(64)}`])).toBe(1);
    expect(text(err)).toContain("unknown");
  });

  it("revoke reports a no-op the second time", () => {
    const db = tempDb();
    main(["mint", "--init", "--service", "demo", "--role", "agent", "--label", "r", "--db", db]);
    const printed = text(out);
    const handle = printed.split("handle: ")[1].split("\n")[0];
    out.length = 0;
    main(["revoke", "--service", "demo", "--handle", handle, "--db", db]);
    out.length = 0;
    expect(main(["revoke", "--service", "demo", "--handle", handle, "--db", db])).toBe(0);
    expect(text(out)).toContain("already revoked");
  });

  it("prints usage for --help and no args, and exits 0", () => {
    expect(main(["--help"])).toBe(0);
    expect(text(out)).toContain("Usage: simsys-tokens");
    out.length = 0;
    expect(main([])).toBe(0);
    expect(text(out)).toContain("Usage: simsys-tokens");
  });

  it("records an attributable created_by", () => {
    const db = tempDb();
    main(["mint", "--init", "--service", "demo", "--role", "agent", "--label", "s", "--db", db]);
    out.length = 0;
    main(["list", "--service", "demo", "--db", db, "--json"]);
    expect(JSON.parse(text(out))[0].created_by).toMatch(/^cli:/);
  });
});

describe("the installed bin", () => {
  // Run the BUILT entry through a symlink, exactly as node_modules/.bin does.
  // The previous entry gated itself on `import.meta.url === file://argv[1]`, which
  // is never true through a symlink, so the CLI exited 0 having done nothing —
  // a wrapper that looked installed and did not work.
  function runBin(args: string[]): { code: number; stdout: string } {
    const db = tempDb();
    const link = resolve(dirname(db), "simsys-tokens");
    symlinkSync(resolve("dist/bin.js"), link);
    try {
      const stdout = execFileSync("node", [link, ...args, "--db", db], { encoding: "utf8" });
      return { code: 0, stdout };
    } catch (err) {
      const e = err as { status?: number; stdout?: string };
      return { code: e.status ?? -1, stdout: e.stdout ?? "" };
    }
  }

  it("fails loudly on a missing store rather than exiting 0", () => {
    expect(runBin(["list", "--service", "demo"]).code).not.toBe(0);
  });

  it("mints through the bin and prints the token once", () => {
    const { code, stdout } = runBin([
      "mint", "--init", "--service", "demo", "--role", "agent", "--label", "s",
    ]);
    expect(code).toBe(0);
    expect(stdout).toContain("demo-agent-");
  });
});
