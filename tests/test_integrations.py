"""The optional telemetry integrations.

These require the ``logevent`` / ``metrics`` extras, which CI installs. They are
skipped if the extras are absent so the suite stays green for a core-only install.
"""
import io
import json

import pytest

from simsys_tokens import integrations

pytest.importorskip("simsys_logevent")
pytest.importorskip("simsys_metrics")


def test_simsys_event_sink_forwards_to_logevent():
    import simsys_logevent

    buf = io.StringIO()
    # out= is a CALLABLE, not a stream: log_event does out(json_line), so passing
    # a StringIO raises TypeError inside its never-throw guard and writes nothing.
    simsys_logevent.configure(service="demo", out=buf.write)
    integrations.simsys_event_sink(
        "token.created", {"service": "demo", "label": "scout", "role": "agent"}
    )
    payload = json.loads(buf.getvalue().strip())
    assert payload["event"] == "token.created"
    assert payload["service"] == "demo"
    assert payload["label"] == "scout"


def test_simsys_metrics_sink_increments_from_events():
    import simsys_metrics

    simsys_metrics.set_service("demo")
    integrations.simsys_metrics_sink("token.created", {"service": "demo"})
    counter = integrations._counters["simsys_tokens_created_total"]
    assert counter.labels(service="demo")._value.get() == 1


def test_simsys_metrics_sink_counts_auth_failures_by_reason():
    import simsys_metrics

    simsys_metrics.set_service("demo")
    integrations.simsys_metrics_sink("token.auth_failed", {"service": "demo", "reason": "revoked"})
    counter = integrations._counters["simsys_tokens_auth_failed_total"]
    assert counter.labels(service="demo", reason="revoked")._value.get() == 1


def test_simsys_sink_runs_both_halves(monkeypatch):
    calls = []
    monkeypatch.setattr(integrations, "simsys_event_sink", lambda e, f: calls.append(("log", e)))
    monkeypatch.setattr(integrations, "simsys_metrics_sink", lambda e, f: calls.append(("metric", e)))
    integrations.simsys_sink("token.revoked", {"service": "demo"})
    assert calls == [("log", "token.revoked"), ("metric", "token.revoked")]
