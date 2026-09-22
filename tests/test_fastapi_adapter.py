import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from simsys_tokens import SessionIdentity, install_tokens

SITE = "https://tokens.example.com"


@pytest.fixture()
def client(tmp_path):
    app = FastAPI()
    state = {"identity": SessionIdentity(user="leon", is_operator=True)}
    install_tokens(
        app,
        service="demo",
        db_path=tmp_path / "tokens.db",
        site_origin=SITE,
        session_resolver=lambda request: state["identity"],
    )
    c = TestClient(app)
    c.state = state
    return c


def test_create_then_list_round_trip(client):
    r = client.post("/api/tokens", json={"label": "scout", "role": "agent"},
                    headers={"Origin": SITE})
    assert r.status_code == 201
    raw = r.json()["token"]
    rows = client.get("/api/tokens").json()["tokens"]
    # The secret must appear in the CREATE response and nowhere else.
    assert len(rows) == 1
    assert raw not in str(rows)


def test_component_asset_is_served_outside_the_api_namespace(client):
    r = client.get("/simsys-tokens.js")
    assert r.status_code == 200
    assert "customElements.define" in r.text
    assert "javascript" in r.headers["content-type"]


def test_non_operator_gets_403(client):
    client.state["identity"] = SessionIdentity(user="member", is_operator=False)
    assert client.get("/api/tokens").status_code == 403


def test_anonymous_gets_401(client):
    client.state["identity"] = None
    assert client.get("/api/tokens").status_code == 401


def test_anonymous_with_malformed_json_is_401_not_400(client):
    # Authorization must be decided BEFORE the body is decoded. A 400 here would
    # mean the server parsed an unauthenticated caller's payload, and would leak
    # that the endpoint exists and is parsing.
    client.state["identity"] = None
    r = client.post("/api/tokens", content=b"{not json",
                    headers={"Origin": SITE, "Content-Type": "application/json"})
    assert r.status_code == 401


def test_json_without_a_content_type_header_is_accepted(client):
    # Parity anchor: Flask's get_json() would refuse this. Both adapters parse
    # the raw bytes, so both must accept it.
    r = client.post("/api/tokens", content=b'{"label":"noct","role":"agent"}',
                    headers={"Origin": SITE})
    assert r.status_code == 201


def test_import_tokens_runs_at_mount(tmp_path):
    app = FastAPI()
    store = install_tokens(
        app, service="demo", db_path=tmp_path / "t.db", site_origin=SITE,
        session_resolver=lambda r: SessionIdentity("leon", True),
        import_tokens=[{"role": "agent", "key": "demo-agent-" + "d" * 64}],
    )
    rows, _ = store.list_rows()
    assert [r["label"] for r in rows] == ["imported:agent"]


def test_event_sink_is_installed(tmp_path):
    from simsys_tokens import events

    seen = []
    app = FastAPI()
    install_tokens(
        app, service="demo", db_path=tmp_path / "t.db", site_origin=SITE,
        session_resolver=lambda r: SessionIdentity("leon", True),
        event_sink=lambda event, fields: seen.append(event),
    )
    try:
        TestClient(app).post("/api/tokens", json={"label": "s", "role": "agent"},
                             headers={"Origin": SITE})
        assert "token.created" in seen
    finally:
        events.set_sink(None)   # reset the process-wide sink


def test_raising_resolver_is_401_not_500(tmp_path):
    from fastapi.testclient import TestClient as _TC

    app = FastAPI()

    def _boom(request):
        raise RuntimeError("adopter bug")

    install_tokens(
        app, service="demo", db_path=tmp_path / "t.db", site_origin=SITE,
        session_resolver=_boom,
    )
    assert _TC(app).get("/api/tokens").status_code == 401
