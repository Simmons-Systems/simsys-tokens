# simsys-tokens

Drop-in API-token store, auth and management surface for in-house web apps. One
`install_tokens()` call gives you a token store, an auth function,
operator-gated management endpoints, and a drop-in web component.

This repository ships **two packages** that share one token format and one store
schema, so a single `tokens.db` is readable by either runtime:

| Package | Runtime | README |
|---|---|---|
| `simsys-tokens` (this README) | Python — FastAPI, Flask | below |
| [`@simsys/tokens`](node/README.md) | Node — Express, Next.js, SvelteKit | [`node/README.md`](node/README.md) |

- **sha256 at rest.** Only `sha256(<full token>)` is stored; the raw value is
  shown once at creation and is never persisted or logged.
- **Revoke is immediate.** One indexed lookup per authenticated request — no
  cache to invalidate, no restart.
- **Optional expiry.** Pass `expires_at` at creation (or set it later); an
  expired token stops authenticating and reports `reason="expired"`.
- **Operator-gated management.** Listing, minting, relabelling and revoking
  require an interactive session carrying `is_operator`. Bearer tokens are
  refused at every role, so a leaked token cannot mint more tokens.
- **Stdlib only by default.** No required dependencies. FastAPI, Flask, and the
  optional Simmons Systems telemetry stack are extras.

## Install

```bash
pip install simsys-tokens              # core, stdlib only
pip install 'simsys-tokens[fastapi]'   # + FastAPI adapter
pip install 'simsys-tokens[flask]'     # + Flask adapter
```

## Quickstart

```python
from fastapi import FastAPI
from simsys_tokens import SessionIdentity, install_tokens

app = FastAPI()


def session_identity(request):
    user = resolve_my_session(request)  # your own auth
    return SessionIdentity(user=user, is_operator=user.is_admin) if user else None


install_tokens(
    app,
    service="myapp",
    db_path="/var/lib/myapp/tokens.db",
    site_origin="https://myapp.example.com",  # exact origin, for CSRF
    session_resolver=session_identity,
)
```

Then drop the component on any page:

```html
<script type="module" src="/simsys-tokens.js"></script>
<simsys-tokens service="myapp"></simsys-tokens>
```

## Endpoints

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/tokens` | Live rows by default; `?include=revoked` adds the rest, `?label=` filters, `?limit=` bounds. Never returns a secret or the full digest. |
| `POST` | `/api/tokens` | `{label, role, priority?, rate_limit?, expires_at?}` → `{handle, token}`. `token` is shown **once**. `409` on a live label collision. |
| `GET` | `/api/tokens/{handle}` | One row's public metadata, or `404`. |
| `PATCH` | `/api/tokens/{handle}` | `{label?, priority?, rate_limit?, expires_at?}`. `role` is not mutable — a role change is a fresh mint. Allowed on a revoked row. |
| `DELETE` | `/api/tokens/{handle}` | Soft revoke. A second `DELETE` is a no-op and does not rewrite `revoked_by`. |
| `GET` | `/simsys-tokens.js` | The component asset. Deliberately outside the API prefix. |

Status codes are evaluated **credentials → CSRF → validation → existence**, so an
unauthenticated caller cannot probe which handles exist (`401`, never `404`).

## Component tiers

1. **Drop it in** — `<script type="module" src="/simsys-tokens.js"></script>` then
   `<simsys-tokens service="myapp"></simsys-tokens>`. Functional list/create/revoke,
   inheriting the page's cascade.
2. **Theme it** — set `--st-bg`, `--st-fg`, `--st-accent`, `--st-border`,
   `--st-radius`, `--st-font`.
3. **Ignore it** — build your own page against the endpoints.

## CLI

```bash
simsys-tokens mint   --init --service myapp --role admin --label bootstrap
simsys-tokens mint   --service myapp --role agent --label scout --expires-at 2027-01-01T00:00:00+00:00
simsys-tokens list   --service myapp [--json]
simsys-tokens revoke --service myapp --handle <16-hex> [--json]
echo '<token>' | simsys-tokens verify --service myapp     # live | expired | revoked | unknown
```

`--db` defaults to `/var/lib/<service>/tokens.db`. Only `mint --init` creates the
store; `list`, `revoke` and `verify` fail loudly rather than create an empty one.
`verify` accepts the token on stdin (so it does not land in shell history) and
exits 0 only for a live token, so it is usable in a script.

## Configuration

Every parameter is optional except the four required ones:

```python
install_tokens(
    app,
    service="myapp",  # also the token prefix; ^[a-z0-9_]{1,32}$
    db_path="/var/lib/myapp/tokens.db",
    site_origin="https://myapp.example.com",  # exact origin, for CSRF
    session_resolver=session_identity,
    import_tokens=None,  # existing config tokens to import
    event_sink=None,  # reconfigures the process default sink
    emitter=None,  # a per-app Emitter (see below)
    limits=Limits(
        last_used_throttle=60, auth_failed_throttle=60, max_raw_len=256, max_label_len=64
    ),
    api_prefix="/api/tokens",
    asset_path="/simsys-tokens.js",
    auth_header="Authorization",
)
```

- **`api_prefix` / `asset_path`** — mount somewhere else when `/api/tokens` is
  taken. Pass the same prefix to the component:
  `<simsys-tokens service="myapp" api="/internal/tokens">`.
- **`auth_header`** — read the bearer from a different header if a gateway
  normalises `Authorization`.
- **`limits`** — throttle windows, the maximum raw token length hashed on the
  auth path, and the label length cap.
- **`emitter`** — an `Emitter(sink=…)` of your own. Use it when one process hosts
  more than one service, so their events do not share the process default.

## Adopting an existing static credential

1. `pip install simsys-tokens` (plus your framework extra).
2. Call `install_tokens(...)` at startup.
3. Hand your existing config tokens to `import_tokens=` — one entry per value,
   with either `key` (raw) or `key_sha256` (precomputed digest). Import is
   idempotent and skip-and-report: a bad entry is rejected, never fatal.
4. Add the component's two lines to an existing page.
5. Watch `last_used_at`: a token with none after a week has no caller and can be
   revoked.
6. Mint the replacement, update known callers, revoke the old row.
7. Empty the config block. The store is now the only source.

> A token that has been readable anywhere other than a `0600` config file — a
> database, a log, a world-readable file, git history — is **re-minted, never
> imported**.

## Optional integrations

Events and metrics are both **injectable callables** — wire your own backend, or
take the extras:

```bash
pip install 'simsys-tokens[simsys]'   # simsys-logevent + simsys-metrics
```

```python
from simsys_tokens import install_tokens
from simsys_tokens.integrations import simsys_event_sink, simsys_metrics

install_tokens(app, ..., event_sink=simsys_event_sink, metrics=simsys_metrics)
```

`service` and `role` slugs must match `^[a-z0-9_]{1,32}$` — **hyphens are
reserved as the token's field separator**, so use `my_app`, not `my-app`.

## License

MIT
