# simsys-tokens

Drop-in API-token store, auth and management surface for FastAPI and Flask apps.
One `install_tokens()` call gives you a token store, an auth function,
operator-gated management endpoints, and a drop-in web component.

- **sha256 at rest.** Only `sha256(<full token>)` is stored; the raw value is
  shown once at creation and is never persisted or logged.
- **Revoke is immediate.** One indexed lookup per authenticated request — no
  cache to invalidate, no restart.
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
    user = resolve_my_session(request)          # your own auth
    return SessionIdentity(user=user, is_operator=user.is_admin) if user else None

install_tokens(
    app,
    service="myapp",
    db_path="/var/lib/myapp/tokens.db",
    site_origin="https://myapp.example.com",    # exact origin, for CSRF
    session_resolver=session_identity,
)
```

Then drop the component on any page:

```html
<script type="module" src="/simsys-tokens.js"></script>
<simsys-tokens service="myapp"></simsys-tokens>
```

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
