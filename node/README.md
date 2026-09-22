# @simsys/tokens

Drop-in API-token store, auth and management surface for **Express, Next.js and
SvelteKit**. One mount call gives you a token store, an auth function,
operator-gated management endpoints, and a drop-in web component.

- **sha256 at rest.** Only `sha256(<full token>)` is stored; the raw value is
  shown once at creation and never persisted or logged.
- **Revoke is immediate.** One indexed lookup per authenticated request — no
  cache to invalidate, no restart.
- **Optional expiry.** Pass `expires_at` at creation (or set it later); an
  expired token stops authenticating and reports `reason: "expired"`.
- **Operator-gated management.** Listing, minting, relabelling and revoking
  require an interactive session carrying `isOperator`. Bearer tokens are
  refused at every role, so a leaked token cannot mint more tokens.
- **No dependencies.** The store is `node:sqlite`, which ships with Node.

## Install

```bash
npm install @simsys/tokens
```

Requires **Node >= 22.13** — the first release where `node:sqlite` works without
a flag. (Node 20 is end-of-life.)

`express` is an **optional peer dependency** (>= 5), needed only by
`@simsys/tokens/express`: the adapter mounts on your app's Express and must share
its Router class rather than bundle a second copy. The root entry and the
Next.js/SvelteKit adapters import no framework at all, so none of them require a
peer.

## Mount forms

The root entry (`@simsys/tokens`) is the **framework-free core** — `authenticate`,
`Endpoints`, `Store`, `Emitter` and the hashing helpers. Every adapter is its own
subpath, so installing this package never pulls in a framework you do not use:

```js
import { installTokens } from "@simsys/tokens/express";
import { collection, item, asset } from "@simsys/tokens/next";    // or /svelte
```

### Express

```js
import express from "express";
import { installTokens } from "@simsys/tokens/express";

const app = express();

installTokens(app, {
  service: "myapp",                              // also the token prefix; ^[a-z0-9_]{1,32}$
  dbPath: "/var/lib/myapp/tokens.db",
  siteOrigin: "https://myapp.example.com",       // exact origin, for CSRF
  sessionResolver: (req) => {
    const user = resolveMySession(req);          // your own auth
    return user ? { user: user.id, isOperator: user.isAdmin } : null;
  },
});
```

Or mount a router yourself: `app.use(installTokens.express({ ...same options }))`.

### Next.js (App Router)

```js
// app/api/tokens/route.ts
import { collection } from "@simsys/tokens/next";
export const { GET, POST } = collection(opts);

// app/api/tokens/[handle]/route.ts
import { item } from "@simsys/tokens/next";
export const { GET, PATCH, DELETE } = item(opts);

// app/simsys-tokens.js/route.ts
import { asset } from "@simsys/tokens/next";
export const { GET } = asset();
```

### SvelteKit

```js
// src/routes/api/tokens/+server.ts
import { collection } from "@simsys/tokens/svelte";
export const { GET, POST } = collection(opts);

// src/routes/api/tokens/[handle]/+server.ts
import { item } from "@simsys/tokens/svelte";
export const { GET, PATCH, DELETE } = item(opts);

// src/routes/simsys-tokens.js/+server.ts
import { asset } from "@simsys/tokens/svelte";
export const { GET } = asset();
```

> **The asset must live outside the API prefix.** Under file-based routing a path
> under `/api/tokens/*` resolves to the `[handle]` route, which answers a `GET`
> with a 405 — so the component never loads. That is why it is its own route file.

Both file-routed adapters take Web `Request`/`Response` (SvelteKit additionally
receives a structurally-typed `RequestEvent`), so neither requires `next` or
`@sveltejs/kit` as a dependency. The routes' own paths are chosen by your file
layout, so `apiPrefix`/`assetPath` apply to Express only.

Then drop the component on any page:

```html
<script type="module" src="/simsys-tokens.js"></script>
<simsys-tokens service="myapp"></simsys-tokens>
```

## Endpoints

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/tokens` | Live rows by default; `?include=revoked`, `?label=`, `?limit=`. Never returns a secret or the full digest. |
| `POST` | `/api/tokens` | `{label, role, priority?, rate_limit?, expires_at?}` → `{handle, token}`. `token` is shown **once**. `409` on a live label collision. |
| `GET` | `/api/tokens/:handle` | One row's public metadata, or `404`. |
| `PATCH` | `/api/tokens/:handle` | `{label?, priority?, rate_limit?, expires_at?}`. `role` is not mutable. Allowed on a revoked row. |
| `DELETE` | `/api/tokens/:handle` | Soft revoke. A second `DELETE` is a no-op. |
| `GET` | `/simsys-tokens.js` | The component asset. Deliberately outside the API prefix. |

Status codes are evaluated **credentials → CSRF → validation → existence**, so an
unauthenticated caller cannot probe which handles exist (`401`, never `404`).
The body is parsed *after* the credential check, so an unauthenticated caller
with malformed JSON gets `401`, not `400` — unless your own JSON parser runs
first, in which case its error handling applies.

## Configuration

```js
installTokens(app, {
  service, dbPath, siteOrigin, sessionResolver,   // required
  limits: { lastUsedThrottle: 60, authFailedThrottle: 60, maxRawLen: 256, maxLabelLen: 64 },
  emitter,            // an Emitter of your own (one per service in a process)
  eventSink,          // reconfigures the process default sink
  importTokens,       // existing config tokens to import at mount
  apiPrefix: "/api/tokens",
  assetPath: "/simsys-tokens.js",
  authHeader: "Authorization",
});
```

- **`apiPrefix` / `assetPath`** — mount somewhere else when `/api/tokens` is
  taken. Pass the same prefix to the component:
  `<simsys-tokens service="myapp" api="/internal/tokens">`.
- **`authHeader`** — read the bearer from a different header if a gateway
  normalises `Authorization`.
- **`limits`** — throttle windows, the maximum raw token length hashed on the
  auth path, and the label length cap.
- **`emitter`** — an `Emitter` of your own, for a process hosting more than one
  service.

## CLI

```bash
npx simsys-tokens mint   --init --service myapp --role admin --label bootstrap
npx simsys-tokens mint   --service myapp --role agent --label scout --expires-at 2027-01-01T00:00:00Z
npx simsys-tokens list   --service myapp [--json]
npx simsys-tokens revoke --service myapp --handle <16-hex> [--json]
echo '<token>' | npx simsys-tokens verify --service myapp   # live | expired | revoked | unknown
```

`--db` defaults to `/var/lib/<service>/tokens.db`. Only `mint --init` creates the
store; `list`, `revoke` and `verify` fail loudly rather than create an empty one.
`verify` exits 0 only for a live token.

## Cross-runtime

The store schema and the token format are identical to the Python
`simsys-tokens` package, and both suites read the same
[`tests/vectors.json`](../tests/vectors.json) — a preimage change reddens both.
Timestamps are normalised to `…+00:00`, so a store written by either runtime
reads consistently in the other.

## License

MIT
