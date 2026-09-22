import pytest
from flask import Flask

from simsys_tokens import SessionIdentity, install_tokens

SITE = "https://tokens.example.com"


@pytest.fixture()
def client(tmp_path):
    app = Flask(__name__)
    # Mutable identity, mirroring the FastAPI fixture's `state` dict, so the
    # anonymous cases below can be exercised on this adapter too.
    state = {"identity": SessionIdentity("leon", True)}
    install_tokens(
        app, service="demo", db_path=tmp_path / "t.db", site_origin=SITE,
        session_resolver=lambda request: state["identity"],
    )
    c = app.test_client()
    c.state = state
    return c


def test_create_and_list(client):
    r = client.post("/api/tokens", json={"label": "scout", "role": "agent"},
                    headers={"Origin": SITE})
    assert r.status_code == 201
    assert len(client.get("/api/tokens").get_json()["tokens"]) == 1


def test_csrf_rejects_a_foreign_origin(client):
    r = client.post("/api/tokens", json={"label": "x", "role": "agent"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_asset_served(client):
    assert client.get("/simsys-tokens.js").status_code == 200


def test_json_without_a_content_type_header_is_accepted(client):
    # The FastAPI adapter has the identically-named test. get_json() would
    # return None here and 400; parsing the raw bytes must not.
    r = client.post("/api/tokens", data=b'{"label":"noct","role":"agent"}',
                    headers={"Origin": SITE})
    assert r.status_code == 201


def test_anonymous_with_malformed_json_is_401_not_400(client):
    # The FastAPI adapter has the identically-named test. Without this mirror,
    # moving _body() above authz() in THIS adapter alone turns nothing red.
    client.state["identity"] = None
    r = client.post("/api/tokens", data=b"{not json",
                    headers={"Origin": SITE, "Content-Type": "application/json"})
    assert r.status_code == 401


def test_routes_do_not_collide_with_the_adopter_s_own_views(tmp_path):
    # Flask derives the endpoint name from the view function's __name__, so
    # unnamed routes would clash with any app that has its own _list/_create.
    app = Flask(__name__)

    @app.get("/things")
    def _list():
        return "ours"

    install_tokens(
        app, service="demo", db_path=tmp_path / "t.db", site_origin=SITE,
        session_resolver=lambda request: SessionIdentity("leon", True),
    )
    assert app.test_client().get("/api/tokens").status_code == 200


def test_raising_resolver_is_401_not_500(tmp_path):
    # Mirror of the FastAPI identically-named test. Without this mirror, removing
    # the try/except in THIS adapter alone turns nothing red.
    app = Flask(__name__)

    def _boom(request):
        raise RuntimeError("adopter bug")

    install_tokens(
        app, service="demo", db_path=tmp_path / "t.db", site_origin=SITE,
        session_resolver=_boom,
    )
    assert app.test_client().get("/api/tokens").status_code == 401
