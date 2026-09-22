"""Optional integrations for the Simmons Systems telemetry stack.

Nothing here is imported unless an adopter wires it, and each adapter imports
its dependency at call time — so this module is safe to import without the
``logevent`` or ``metrics`` extras installed.

```python
from simsys_tokens import install_tokens
from simsys_tokens.integrations import simsys_sink   # logevent + metrics

install_tokens(app, ..., event_sink=simsys_sink)
```
"""

from __future__ import annotations

# Counters are created once and cached: prometheus_client raises on duplicate
# registration, and a sink is called on every event.
_counters: dict[str, object] = {}


def simsys_event_sink(event: str, fields: dict) -> None:
    """Forward an event to ``simsys-logevent``.

    Requires the ``logevent`` extra. The caller is responsible for
    ``simsys_logevent.configure(service=...)`` (usually already done for the
    host app), since the package does not own that global.
    """
    from simsys_logevent import log_event  # noqa: PLC0415 (optional dep)

    log_event(event, **fields)


def _inc(name: str, documentation: str, labels: dict) -> None:
    from simsys_metrics import make_counter  # noqa: PLC0415 (optional dep)

    counter = _counters.get(name)
    if counter is None:
        counter = make_counter(name, documentation, labelnames=tuple(sorted(labels)))
        _counters[name] = counter
    counter.labels(**labels).inc()


def simsys_metrics_sink(event: str, fields: dict) -> None:
    """Derive ``simsys_tokens_*`` counters from lifecycle events.

    Requires the ``metrics`` extra. The host app still mounts ``/metrics``
    itself via ``simsys_metrics.install(...)``; this only feeds the counters.
    """
    service = fields.get("service", "unknown")
    if event == "token.created":
        _inc("simsys_tokens_created_total", "Tokens created", {"service": service})
    elif event == "token.revoked":
        _inc("simsys_tokens_revoked_total", "Tokens revoked", {"service": service})
    elif event == "token.auth_failed":
        _inc(
            "simsys_tokens_auth_failed_total",
            "Failed token authentications",
            {"service": service, "reason": fields.get("reason", "unknown")},
        )


def simsys_sink(event: str, fields: dict) -> None:
    """Both integrations. A logevent failure must not swallow the metric."""
    try:
        simsys_event_sink(event, fields)
    finally:
        simsys_metrics_sink(event, fields)
