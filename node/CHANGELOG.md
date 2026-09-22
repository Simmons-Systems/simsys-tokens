# Changelog

All notable changes to **@simsys/tokens** (the Node package) are documented here.
The Python package has its own changelog at the repository root.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
