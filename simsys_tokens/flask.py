"""Flask adapter. Translates requests; never decides policy."""
from __future__ import annotations

import json
from pathlib import Path

from flask import Response, jsonify, request

from . import events
from .core import Endpoints
from .importer import import_entries
from .store import Store, ensure_schema

_ASSET = Path(__file__).parent / "static" / "simsys-tokens.js"


def install_tokens(app, *, service, db_path, site_origin, session_resolver,
                   import_tokens=None, event_sink=None) -> Store:
    ensure_schema(db_path, create=True)
    if event_sink is not None:
        events.set_sink(event_sink)
    store = Store(db_path, service)
    endpoints = Endpoints(store, site_origin)
    if import_tokens:
        import_entries(store, import_tokens)

    def _ctx():
        try:
            identity = session_resolver(request)
        except Exception:
            # Same contract as the FastAPI adapter: a raising resolver is
            # anonymous (401), never a 500. Tested by mirror tests on both.
            identity = None
        return (
            identity,
            request.headers.get("Authorization"),
            request.headers.get("Origin"),
            request.headers.get("Referer"),
        )

    def _body():
        """Byte-for-byte the same logic as the FastAPI adapter's _body().

        Deliberately json.loads on the raw bytes rather than get_json(): Werkzeug
        returns None from get_json(silent=True) when Content-Type is not
        application/json, so identical JSON would 400 here and succeed on
        FastAPI. Parity is the whole point of this helper — a curl without an
        explicit -H Content-Type must behave the same on both adapters.
        """
        raw = request.get_data()
        if not raw:
            return {}, None
        try:
            parsed = json.loads(raw)
        except ValueError:
            return None, "request body is not valid JSON"
        if not isinstance(parsed, dict):
            return None, "request body must be a JSON object"
        return parsed, None

    # Explicit `endpoint=` names on every route: Flask derives the endpoint from
    # the view function's __name__, so registering `_list`/`_create` on the
    # ADOPTER's app collides with any view of the same name and raises
    # "View function mapping is overwriting an existing endpoint function".
    @app.get("/api/tokens", endpoint="simsys_tokens_list")
    def _list():
        identity, bearer, _, _ = _ctx()
        status, body = endpoints.handle_list(identity, bearer, request.args.to_dict())
        return jsonify(body), status

    @app.post("/api/tokens", endpoint="simsys_tokens_create")
    def _create():
        identity, bearer, origin, referer = _ctx()
        refusal = endpoints.authz(identity, bearer)   # BEFORE decoding the body
        if refusal:
            return jsonify(refusal[1]), refusal[0]
        body, err = _body()
        if err:
            return jsonify({"error": err}), 400
        status, out = endpoints.handle_create(identity, bearer, body, origin, referer)
        return jsonify(out), status

    @app.patch("/api/tokens/<handle>", endpoint="simsys_tokens_patch")
    def _patch(handle):
        identity, bearer, origin, referer = _ctx()
        refusal = endpoints.authz(identity, bearer)
        if refusal:
            return jsonify(refusal[1]), refusal[0]
        body, err = _body()
        if err:
            return jsonify({"error": err}), 400
        status, out = endpoints.handle_patch(identity, bearer, handle, body, origin, referer)
        return jsonify(out), status

    @app.delete("/api/tokens/<handle>", endpoint="simsys_tokens_delete")
    def _delete(handle):
        identity, bearer, origin, referer = _ctx()
        status, body = endpoints.handle_delete(identity, bearer, handle, origin, referer)
        return jsonify(body), status

    @app.get("/simsys-tokens.js", endpoint="simsys_tokens_asset")
    def _asset():
        return Response(_ASSET.read_text(), mimetype="application/javascript")

    return store
