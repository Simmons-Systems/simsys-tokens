# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added
- `install_tokens(app, *, service, db_path, site_origin, session_resolver,
  import_tokens=None, event_sink=None)` — mounts `GET/POST /api/tokens` and
  `PATCH/DELETE /api/tokens/{handle}` on FastAPI or Flask, plus
  `GET /simsys-tokens.js`. Dispatches on the app type, with a `framework=`
  override.
- `authenticate(store, authorization_header)` → `TokenInfo | None`, with a
  shape check before hashing and a throttled `last_used_at` write.
- Token store at `db_path`, holding `sha256(<full token>)` only. Service-scoped,
  soft-revoke, one shared idempotent `ensure_schema()` used by the app and the
  CLI.
- Operator-gated management: listing, minting, relabelling and revoking require
  an interactive session with `is_operator`; bearer tokens are refused at every
  role. Exact-origin CSRF check, fail-closed, on every mutating method.
- `simsys-tokens` CLI: `mint` (with `--init`), `list`, `revoke`. Only
  `mint --init` may create the store.
- `<simsys-tokens>` custom element — light DOM, no colours of its own; list,
  create, and revoke. The raw token is shown once and never persisted.
- Lifecycle events through an injectable sink (`event_sink=`), defaulting to
  one JSON line on stdout. `simsys_tokens.integrations` provides optional
  `simsys-logevent` and `simsys-metrics` adapters.
- `tests/vectors.json` — shared hash/format fixture, read by the Node package's
  suite too.
