"""Lifecycle events, emitted through an injectable sink.

The sink is a callable ``(event: str, fields: dict) -> None``. The default writes
one JSON line to stdout, using the standard library only — so the package has no
required dependencies. An adopter who wants structured logging or metrics wires
their own sink, or uses one of the adapters in
:mod:`simsys_tokens.integrations`.

An :class:`Emitter` owns a sink, so a process hosting more than one service can
give each its own emitter instead of sharing one global. ``events.DEFAULT`` is
the process-wide default used when no emitter is passed.

``token.auth_failed`` fires ONLY when a bearer credential was presented and
failed to resolve. Never on the no-credential path: ``authenticate()`` runs on
effectively every request, so emitting on every ``None`` return would fire on
every anonymous hit to a health check or a scrape.
"""

from __future__ import annotations

import json
import sys

DEFAULT_SERVICE = "unknown"


def stdout_sink(event: str, fields: dict) -> None:
    """One JSON line per event. The dependency-free default."""
    sys.stdout.write(json.dumps({"event": event, **fields}, default=str) + "\n")


class Emitter:
    """Owns an event sink and the convenience methods over it.

    ``service`` is optional here and usually passed per call, because the
    store already knows it; it exists so a caller that emits without a service
    in hand can pin one.
    """

    def __init__(self, sink=None, service: str | None = None):
        self.sink = sink or stdout_sink
        self.service = service

    def emit(self, event: str, *, service: str | None = None, **fields) -> None:
        # A sink that raises must never break the request path: events are
        # observability, not control flow.
        svc = service or self.service or DEFAULT_SERVICE
        try:
            self.sink(event, {"service": svc, **fields})
        except Exception:
            pass

    def token_created(self, service, handle, label, role, actor):
        self.emit(
            "token.created", service=service, handle=handle, label=label, role=role, actor=actor
        )

    def token_revoked(self, service, handle, label, actor):
        self.emit("token.revoked", service=service, handle=handle, label=label, actor=actor)

    def token_relabelled(self, service, handle, old, new, actor):
        self.emit("token.relabelled", service=service, handle=handle, old=old, new=new, actor=actor)

    def token_policy_changed(self, service, handle, field, old, new, actor):
        self.emit(
            "token.policy_changed",
            service=service,
            handle=handle,
            field=field,
            old=old,
            new=new,
            actor=actor,
        )

    def token_imported(self, service, handle, label, role):
        self.emit("token.imported", service=service, handle=handle, label=label, role=role)

    def token_import_rejected(self, service, role, reason):
        self.emit("token.import_rejected", service=service, role=role, reason=reason)

    def token_auth_failed(self, service, *, handle=None, label=None, digest_prefix=None, reason):
        self.emit(
            "token.auth_failed",
            service=service,
            handle=handle,
            label=label,
            digest_prefix=digest_prefix,
            reason=reason,
        )

    def token_first_use(self, service, handle, label):
        self.emit("token.first_use", service=service, handle=handle, label=label)


# Process-wide default. ``set_sink`` reconfigures it; a second emitter is how an
# app with two services keeps their events separate.
DEFAULT = Emitter()


def set_sink(sink=None) -> None:
    """Install a sink on the default emitter, or reset to the stdout default."""
    DEFAULT.sink = sink or stdout_sink
