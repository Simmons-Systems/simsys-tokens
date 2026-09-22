import json

import pytest

from simsys_tokens import events
from simsys_tokens.core import authenticate
from simsys_tokens.store import Store, ensure_schema


@pytest.fixture()
def captured(monkeypatch):
    """Replaces conftest's autouse silencer for this module.

    Signature mirrors the real sink — (event: str, fields: dict) — so a stub
    that would accept something else cannot hide a caller passing the wrong shape.
    """
    seen = []
    monkeypatch.setattr(
        events, "_sink", lambda event, fields: seen.append({"event": event, **fields})
    )
    return seen


@pytest.fixture()
def store(tmp_path):
    db = tmp_path / "tokens.db"
    ensure_schema(db, create=True)
    return Store(db, "demo")


def test_auth_failed_fires_on_a_presented_but_bad_bearer(captured, store):
    authenticate(store, "Bearer demo-agent-" + "0" * 64)
    assert [p["event"] for p in captured] == ["token.auth_failed"]


def test_auth_failed_does_not_fire_on_an_anonymous_request(captured, store):
    authenticate(store, None)
    authenticate(store, "")
    assert captured == [], "anonymous requests must not emit — this floods the sink"


def test_auth_failed_on_a_revoked_token_names_it(captured, store):
    raw, handle = store.mint("agent", "scout", "cli:leon@dev")
    store.revoke(handle, "session:leon")
    captured.clear()
    authenticate(store, f"Bearer {raw}")
    assert captured[0]["handle"] == handle and captured[0]["label"] == "scout"


def test_auth_failed_on_an_unknown_digest_carries_no_label(captured, store):
    authenticate(store, "Bearer demo-agent-" + "0" * 64)
    assert captured[0].get("label") is None
    assert "digest_prefix" in captured[0]


def test_auth_failed_on_malformed_shape_is_throttled_not_silent(captured, store):
    authenticate(store, "Bearer nope")
    assert captured[0]["reason"] == "malformed"
    captured.clear()
    # Second identical malformed presentation within the throttle window emits
    # nothing: without this a scanner floods the sink at one event per request.
    authenticate(store, "Bearer nope")
    assert captured == []


def test_auth_failed_on_unknown_digest_is_throttled(captured, store):
    bad = "Bearer demo-agent-" + "1" * 64
    authenticate(store, bad)
    assert len(captured) == 1
    authenticate(store, bad)
    assert len(captured) == 1, "repeat unknown digest must not re-emit within 60s"


def test_first_use_fires_once_and_only_once(captured, store):
    raw, handle = store.mint("agent", "scout", "cli:leon@dev")
    authenticate(store, f"Bearer {raw}")
    assert [p["event"] for p in captured] == ["token.first_use"]
    captured.clear()
    store.last_touch.clear()          # defeat the 60s throttle, not the flag
    authenticate(store, f"Bearer {raw}")
    assert captured == [], "first_use must not re-fire on later authentications"


def test_the_default_sink_writes_json_with_the_service(capsys, monkeypatch):
    """Pins the default sink's contract.

    Every other test replaces events._sink, so a default sink that wrote nothing
    — or dropped the service — would be invisible to the whole suite. This is
    the one test that exercises it.
    """
    monkeypatch.setattr(events, "_sink", events._stdout_sink)
    events.token_created("demo", "abc123", "scout", "agent", "cli:leon@dev")
    line = capsys.readouterr().out.strip()
    assert line, "nothing was written by the default sink"
    payload = json.loads(line)
    assert payload["event"] == "token.created"
    assert payload["service"] == "demo"
    assert payload["label"] == "scout"
