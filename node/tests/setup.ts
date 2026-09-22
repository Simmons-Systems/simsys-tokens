import { beforeEach } from "vitest";

import { setSink } from "../src/events.js";

// Silence the process default sink for every test. Tests that assert on events
// install their own Emitter, and the default sink has its own explicit test.
beforeEach(() => {
  setSink(() => {});
});
