# Changelog

All notable changes to **@simsys/tokens** (the Node package) are documented here.
The Python package has its own changelog at the repository root.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

### Added
- **Next.js App Router adapter** — `@simsys/tokens/next` exports `collection`,
  `item` and `asset` handler sets for the three route files.
- **SvelteKit adapter** — `@simsys/tokens/svelte` exports the same three handler
  sets over `RequestEvent`.
- Neither file-routed adapter depends on its framework: both take Web
  `Request`/`Response`, and SvelteKit's `RequestEvent` is typed structurally, so
  `next` and `@sveltejs/kit` are not peers.
- Shared adapter plumbing (`http.ts`, `options.ts`) so the JSON-body rules, the
  component asset and the Store/Endpoints wiring exist once rather than per
  adapter. Exported for anyone writing a fourth adapter.

### Changed
- **BREAKING: the root entry no longer re-exports `installTokens`.** It is now the
  framework-free core, so importing `@simsys/tokens` pulls in no framework. Use
  `import { installTokens } from "@simsys/tokens/express"` (0.1.x's
  `@simsys/tokens` import). This is what lets the Next.js and SvelteKit adapters
  exist without every adopter installing Express.
- `express` moved from a required to an **optional** peer dependency — only the
  `/express` subpath needs it.

### Fixed
- `simsys-tokens --help` (and no arguments) printed an error and exited 1; both now
  print usage and exit 0.


## [0.1.3]

### Fixed
- **`simsys-tokens` did nothing when installed.** cli.ts gated its own execution
  on `import.meta.url === \`file://${process.argv[1]}\``, which is never true
  through `node_modules/.bin/simsys-tokens` — argv[1] is the symlink, import.meta.url
  the real path — so the command exited 0 without running. Found by installing the
  published package and checking the exit code, not the link. The entry point is now
  a separate `src/bin.ts`, and a test spawns the built bin so the wrapper is covered.

## [0.1.2]

### Fixed
- `express` is now declared as a **peer dependency**. It was only a devDependency,
  so a consumer's `npm i @simsys/tokens` produced a package whose root entry
  (`@simsys/tokens`) and `@simsys/tokens/express` both failed at import with
  `ERR_MODULE_NOT_FOUND: express` — the root re-exports the Express adapter, which
  imports express at module scope. Declaring the peer also makes npm 7+ install it
  for an app that does not already have it.

## [0.1.1]

### Fixed
- The `bin` entry pointed at `./dist/cli.js`; npm normalises the value, treats a
  leading `./` as invalid, and silently drops the entry at publish time — so the
  installed package had no `simsys-tokens` command. It is now `dist/cli.js`.

## [0.1.0]

### Added
- `installTokens(app, opts)` mounts the management surface on an Express app;
  `installTokens.express(opts)` returns the router instead.
- `GET/POST /api/tokens` and `GET/PATCH/DELETE /api/tokens/:handle`, plus
  `GET /simsys-tokens.js`.
- `authenticate(store, authorizationHeader)` → `TokenInfo | null`, with a shape
  check before hashing and a throttled `last_used_at` write.
- Token store at `dbPath` on `node:sqlite`, holding `sha256(<full token>)` only.
  Same schema and migration path as the Python package, so one store file works
  for both runtimes.
- Operator-gated management (listing included) and a fail-closed exact-origin
  CSRF check on every mutating method.
- Optional expiry (`expires_at`), surfaced in the listing and distinguishable
  from revoked/unknown via `token.auth_failed`'s `reason`.
- Lifecycle events through an injectable sink, defaulting to one JSON line on
  stdout.
- `simsys-tokens` CLI: `mint` (with `--init`), `list`, `revoke`, `verify`.
- `<simsys-tokens>` custom element — light DOM, no colours of its own.
