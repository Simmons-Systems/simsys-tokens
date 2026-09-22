"""Lifecycle events, emitted through an injectable sink.

The sink is a callable ``(event: str, fields: dict) -> None``. The default writes
one JSON line to stdout, using the standard library only — so the package has no
required dependencies. An adopter who wants structured logging or metrics wires
their own sink, or uses one of the adapters in
:mod:`simsys_tokens.integrations`.

``token.auth_failed`` fires ONLY when a bearer credential was presented and
failed to resolve. Never on the no-credential path: ``authenticate()`` runs on
effectively every request, so emitting on every ``None`` return would fire on
every anonymous hit to a health check or a scrape.
"""
from __future__ import annotations

import json
import sys

DEFAULT_SERVICE = "unknown"


def _stdout_sink(event: str, fields: dict) -> None:
    sys.stdout.write(json.dumps({"event": event, **fields}, default=str) + "\n")


# Process-wide sink. One install per process is the norm; if an app mounts the
# surface twice, the last sink wins. Tests replace this to capture events.
_sink = _stdout_sink


def set_sink(sink=None) -> None:
    """Install a sink callable, or reset to the stdout default when None."""
    global _sink
    _sink = sink or _stdout_sink


def emit(event: str, **fields) -> None:
    # A sink that raises must never break the request path: events are
    # observability, not control flow.
    try:
        _sink(event, fields)
    except Exception:
        pass


def token_created(service, handle, label, role, actor):
    emit("token.created", service=service, handle=handle, label=label, role=role, actor=actor)


def token_revoked(service, handle, label, actor):
    emit("token.revoked", service=service, handle=handle, label=label, actor=actor)


def token_relabelled(service, handle, old, new, actor):
    emit("token.relabelled", service=service, handle=handle, old=old, new=new, actor=actor)


def token_policy_changed(service, handle, field, old, new, actor):
    emit("token.policy_changed", service=service, handle=handle, field=field,
         old=old, new=new, actor=actor)


def token_imported(service, handle, label, role):
    emit("token.imported", service=service, handle=handle, label=label, role=role)


def token_import_rejected(service, role, reason):
    emit("token.import_rejected", service=service, role=role, reason=reason)


def token_auth_failed(service, *, handle=None, label=None, digest_prefix=None, reason):
    emit("token.auth_failed", service=service, handle=handle, label=label,
         digest_prefix=digest_prefix, reason=reason)


def token_first_use(service, handle, label):
    emit("token.first_use", service=service, handle=handle, label=label)
