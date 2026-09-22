import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The default event sink writes JSON to stdout, which interleaves with the
    // CLI output tests parse; setup.ts silences it per test.
    setupFiles: ["tests/setup.ts"],
  },
});
