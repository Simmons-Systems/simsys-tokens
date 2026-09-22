# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- The repository now also ships **`@simsys/tokens`** (Node >= 22.13) for Express,
  Next.js and SvelteKit — see [`node/CHANGELOG.md`](node/CHANGELOG.md). It shares
  the token format and the store schema with the Python package, so a single store
  file is readable by either runtime.

## [0.2.0]

### Added
- **Token expiry.** A token may carry an `expires_at` (ISO-8601). An expired
  token stops authenticating and reports `auth_failed` with `reason="expired"`.
  Settable at mint, via `PATCH`, and from the CLI (`mint --expires-at`).
- `GET /api/tokens/{handle}` for one row's public metadata.
- `?label=` filter on the listing.
- `simsys-tokens verify` — resolve a presented token to `live` / `expired` /
  `revoked` / `unknown`. Reads the token from stdin by default so it does not
  land in shell history; exits non-zero unless the token is live.
- `--json` on `mint` and `revoke`, matching `list`.
- **Mount options:** `api_prefix=`, `asset_path=`, `auth_header=`,
  `limits=Limits(...)`, and `emitter=` for a per-app event sink. The component
  reads the prefix from its `api` attribute.
- `Status` now surfaces `expires_at` and `revoked_by` (attribution for who
  revoked a token).
- CI: a `lint` job (ruff) and a `build` job that builds the wheel, asserts the
  component asset is packaged, and imports the installed wheel.

### Fixed
- A typo'd `site_origin` now fails at construction instead of raising a 500 on
  every mutating request.
- `token.first_use` could fire twice when two concurrent requests both read
  `last_used_at IS NULL`; the in-lock claim now admits only one.
- `token.auth_failed` was throttled away on a freshly booted host, where
  `time.monotonic()` is under the throttle window (caught by CI on a fresh
  runner; it passed on a long-up box).
- Throttle-map eviction now refreshes a re-emitted key instead of evicting it as
  if it were the oldest.
- The store file (and its WAL sidecars) are created mode `0600`.

### Changed
- **Schema v2** with an incremental migration path (`_migrate`). A v1 store is
  upgraded in place on the next `ensure_schema()`, and the version row is
  upserted rather than ignored.
- Labels are length-bounded (`Limits.max_label_len`, default 64).
- `license` metadata uses the PEP 639 form (`license = "MIT"` + `license-files`).
- `ruff` config added; the tree is ruff-check and ruff-format clean.

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
