import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach } from "vitest";

const dirs: string[] = [];

/** A throwaway store path. Cleaned up after each test. */
export function tempDb(name = "tokens.db"): string {
  const dir = mkdtempSync(join(tmpdir(), "simsys-tokens-"));
  dirs.push(dir);
  return join(dir, name);
}

afterEach(() => {
  while (dirs.length > 0) {
    rmSync(dirs.pop() as string, { recursive: true, force: true });
  }
});
