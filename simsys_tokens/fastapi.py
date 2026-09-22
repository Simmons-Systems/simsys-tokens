"""FastAPI adapter. Translates requests; never decides policy."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from . import events
from .core import Endpoints
from .importer import import_entries
from .store import Store, ensure_schema

_ASSET = Path(__file__).parent / "static" / "simsys-tokens.js"


def install_tokens(
    app,
    *,
    service,
    db_path,
    site_origin,
    session_resolver,
    import_tokens=None,
    event_sink=None,
    emitter=None,
    limits=None,
    api_prefix="/api/tokens",
    asset_path="/simsys-tokens.js",
    auth_header="Authorization",
) -> Store:
    ensure_schema(db_path, create=True)
    if event_sink is not None:
        # Configures the process default, so a direct authenticate() call sees
        # the same sink. Pass emitter= for a per-app emitter that does NOT touch
        # the process-wide one.
        events.set_sink(event_sink)
    api = "/" + api_prefix.strip("/")
    asset = "/" + asset_path.strip("/")
    store = Store(db_path, service)
    endpoints = Endpoints(store, site_origin, emitter=emitter, limits=limits)
    if import_tokens:
        import_entries(store, import_tokens)

    def _ctx(request: Request):
        try:
            identity = session_resolver(request)
        except Exception:
            # Adopter code must not turn a management endpoint into a 500 with
            # a traceback. A raising resolver is treated as anonymous -> 401.
            identity = None
        return (
            identity,
            request.headers.get(auth_header),
            request.headers.get("Origin"),
            request.headers.get("Referer"),
        )

    @app.get(api)
    async def _list(request: Request):
        identity, bearer, _, _ = _ctx(request)
        status, body = endpoints.handle_list(identity, bearer, dict(request.query_params))
        return JSONResponse(body, status_code=status)

    async def _body(request: Request):
        """Mirror Flask's get_json(silent=True) or {}.

        Returns (body, error). A literal JSON `null` decodes to None, and
        malformed JSON raises — either becomes a 500 via body.get() unless
        handled here, and the two adapters must not disagree on this input.
        """
        raw = await request.body()
        if not raw:
            return {}, None
        try:
            parsed = json.loads(raw)
        except ValueError:
            return None, "request body is not valid JSON"
        if not isinstance(parsed, dict):
            return None, "request body must be a JSON object"
        return parsed, None

    @app.post(api)
    async def _create(request: Request):
        identity, bearer, origin, referer = _ctx(request)
        refusal = endpoints.authz(identity, bearer)  # BEFORE decoding the body
        if refusal:
            return JSONResponse(refusal[1], status_code=refusal[0])
        body, err = await _body(request)
        if err:
            return JSONResponse({"error": err}, status_code=400)
        status, out = endpoints.handle_create(identity, bearer, body, origin, referer)
        return JSONResponse(out, status_code=status)

    @app.get(f"{api}/{{handle}}")
    async def _get(handle: str, request: Request):
        identity, bearer, _, _ = _ctx(request)
        status, out = endpoints.handle_get(identity, bearer, handle)
        return JSONResponse(out, status_code=status)

    @app.patch(f"{api}/{{handle}}")
    async def _patch(handle: str, request: Request):
        identity, bearer, origin, referer = _ctx(request)
        refusal = endpoints.authz(identity, bearer)
        if refusal:
            return JSONResponse(refusal[1], status_code=refusal[0])
        body, err = await _body(request)
        if err:
            return JSONResponse({"error": err}, status_code=400)
        status, out = endpoints.handle_patch(identity, bearer, handle, body, origin, referer)
        return JSONResponse(out, status_code=status)

    @app.delete(f"{api}/{{handle}}")
    async def _delete(handle: str, request: Request):
        identity, bearer, origin, referer = _ctx(request)
        status, out = endpoints.handle_delete(identity, bearer, handle, origin, referer)
        return JSONResponse(out, status_code=status)

    # Deliberately OUTSIDE the api prefix: under file-based routing on other
    # frameworks a path under it collides with the {handle} route.
    @app.get(asset, include_in_schema=False)
    async def _asset_route():
        return Response(_ASSET.read_text(), media_type="application/javascript")

    return store
