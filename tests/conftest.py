import pytest


@pytest.fixture(autouse=True)
def _silence_events(monkeypatch):
    """Stub the default emitter's sink for EVERY test.

    The default sink writes one JSON line to stdout, which would interleave with
    the CLI output that tests parse; and tests should not depend on the exact
    envelope shape. Modules that assert on events install their own sink.

    The import is guarded because simsys_tokens.events does not exist until
    Task 6, and an unguarded import here would break earlier tasks at collection.
    """
    try:
        from simsys_tokens import events
    except ImportError:
        return
    monkeypatch.setattr(events.DEFAULT, "sink", lambda event, fields: None)
