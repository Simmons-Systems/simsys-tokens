#!/usr/bin/env node
/**
 * The CLI entry point.
 *
 * Deliberately a separate file rather than an `import.meta.url === argv[1]`
 * guard inside cli.ts: invoked through `node_modules/.bin/simsys-tokens`,
 * argv[1] is the SYMLINK path while import.meta.url is the real one, so that
 * guard is never true and the CLI exits 0 having done nothing. Keeping the
 * entry explicit also lets tests import cli.ts without running it.
 */
import { main } from "./cli.js";

process.exit(main(process.argv.slice(2)));
