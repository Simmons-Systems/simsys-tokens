"""Framework-agnostic policy. Adapters translate; they never decide."""

from __future__ import annotations

import json as _json
import re
import sqlite3
import time
from dataclasses import dataclass

from . import events
from .csrf import check_origin
from .hashing import token_hash, validate_handle, validate_role
from .models import SessionIdentity, TokenInfo  # noqa: F401  (re-exported)
from .store import (
    AmbiguousHandle,
    NoSuchHandle,
    Store,
    normalize_expires_at,
)

LAST_USED_THROTTLE_SECONDS = 60
AUTH_FAILED_THROTTLE_SECONDS = 60
# Longest well-formed token: 32 + 1 + 32 + 1 + 64 = 130. Cap at 256 to leave
# headroom without letting a 10 MB Authorization header reach sha256 (CPU DoS).
MAX_RAW_LEN = 256
MAX_LABEL_LEN = 64
TOKEN_RE = re.compile(r"[a-z0-9_]{1,32}-[a-z0-9_]{1,32}-[0-9a-f]{64}")

_PATCHABLE = {"label", "priority", "rate_limit", "expires_at"}


@dataclass(frozen=True)
class Limits:
    """Tunables a high- or low-traffic adopter may need to change."""

    last_used_throttle: int = LAST_USED_THROTTLE_SECONDS
    auth_failed_throttle: int = AUTH_FAILED_THROTTLE_SECONDS
    max_raw_len: int = MAX_RAW_LEN
    max_label_len: int = MAX_LABEL_LEN


DEFAULT_LIMITS = Limits()


def _extract_bearer(header: str | None) -> str | None:
    if not header or not header.startswith("Bearer "):
        return None
    return header[len("Bearer ") :] or None


def _well_formed(raw: str, max_raw_len: int) -> bool:
    """Shape check BEFORE hashing. Hashing arbitrary-length attacker input on
    the hot auth path is a CPU-DoS vector; a malformed token can never resolve,
    so reject it without touching sha256 or SQLite."""
    return len(raw) <= max_raw_len and TOKEN_RE.fullmatch(raw) is not None


def _emit_auth_failed_once(
    store: Store, emitter: events.Emitter, limits: Limits, *, key: str, event_kwargs: dict
) -> None:
    """Emit token.auth_failed at most once per throttle window per key.

    Without this a scanner presenting random bearers fires one event per request
    and destroys the signal the rollout depends on.

    ``key in store.last_auth_failed`` rather than ``.get(key, 0.0)``: monotonic
    counts from an arbitrary epoch, so on a freshly booted host now < 60 and a
    ``now - 0.0 < 60`` guard would throttle the FIRST failure away entirely.
    """
    now = time.monotonic()
    with store._touch_lock:
        last = store.last_auth_failed.get(key)
        if last is not None and now - last < limits.auth_failed_throttle:
            return
        store._touch_note(store.last_auth_failed, key, now)
    emitter.token_auth_failed(store.service, **event_kwargs)


def authenticate(
    store: Store,
    authorization_header: str | None,
    *,
    emitter: events.Emitter | None = None,
    limits: Limits | None = None,
) -> TokenInfo | None:
    emitter = emitter or events.DEFAULT
    limits = limits or DEFAULT_LIMITS
    raw = _extract_bearer(authorization_header)
    if raw is None:
        return None
    if not _well_formed(raw, limits.max_raw_len):
        # Malformed shapes can never resolve. Emit throttled so a scanner
        # hammering garbage cannot flood the sink: at most one event per window
        # per distinct prefix. No digest exists (nothing was hashed), so carry a
        # raw prefix only, never a label.
        _emit_auth_failed_once(
            store,
            emitter,
            limits,
            key=f"malformed:{raw[:16]}",
            event_kwargs={"digest_prefix": None, "reason": "malformed"},
        )
        return None
    digest = token_hash(raw)
    row = store.lookup_live(digest)
    if row is None:
        revoked = store.find_any(digest)
        if revoked is None:
            _emit_auth_failed_once(
                store,
                emitter,
                limits,
                key=f"unknown:{digest[:16]}",
                event_kwargs={"digest_prefix": digest[:16], "reason": "unknown"},
            )
        elif revoked["revoked_at"] is not None:
            _emit_auth_failed_once(
                store,
                emitter,
                limits,
                key=f"revoked:{digest[:16]}",
                event_kwargs={
                    "handle": digest[:16],
                    "label": revoked["label"],
                    "reason": "revoked",
                },
            )
        else:
            # Present, not revoked, and lookup_live filtered it — so it expired.
            _emit_auth_failed_once(
                store,
                emitter,
                limits,
                key=f"expired:{digest[:16]}",
                event_kwargs={
                    "handle": digest[:16],
                    "label": revoked["label"],
                    "reason": "expired",
                },
            )
        return None
    # Capture first-use BEFORE the throttled touch, since touch is what stops
    # last_used_at being None.
    first_use = row["last_used_at"] is None
    now = time.monotonic()
    # The throttle map lives on the STORE, not module-global: a global keyed
    # only on digest is shared across every service in the process and grows
    # without bound for the life of the app.
    #
    # `or first_use` is NOT redundant. time.monotonic() counts from an arbitrary
    # epoch — on a freshly booted host it is < 60, so `now - 0.0 >= 60` is False
    # and the very first touch would be throttled away.
    #
    # Lock + bounded map: Flask runs threaded and async workers share the Store,
    # so an unlocked dict check-then-set races; and an unbounded dict grows for
    # the life of the app under scanner traffic. See Store._touch_note().
    with store._touch_lock:
        # Only the thread that flips the flag from "unset" to a stamp may emit
        # first_use: two concurrent requests both read last_used_at IS NULL, and
        # without the in-lock claim both would emit a duplicate event.
        claim_first_use = first_use and store.last_touch.get(digest) is None
        last = store.last_touch.get(digest, 0.0)
        should_touch = now - last >= limits.last_used_throttle or claim_first_use
        if should_touch:
            store._touch_note(store.last_touch, digest, now)
    if should_touch:
        store.touch_last_used(digest)
    if claim_first_use:
        emitter.token_first_use(store.service, digest[:16], row["label"])
    return TokenInfo(
        handle=digest[:16],
        label=row["label"],
        role=row["role"],
        priority=row["priority"],
        rate_limit=row["rate_limit"],
        token_sha256=digest,
        expires_at=row["expires_at"],
    )


def validate_policy(body) -> str | None:
    """Return an error string, or None. Validates at the boundary so a
    downstream consumer parsing rate_limit as JSON cannot fail at runtime on a
    value this layer happily stored.

    Public because the importer applies the identical rule — the import path
    writes rows without going through an endpoint, so a private copy here would
    leave the one caller that bypasses HTTP also bypassing validation."""
    priority = body.get("priority")
    # `isinstance(True, int)` is True in Python, so a bare int check accepts
    # `"priority": true` from a JSON body and stores 1.
    if priority is not None and (isinstance(priority, bool) or not isinstance(priority, int)):
        return "priority must be an integer or null"
    rate_limit = body.get("rate_limit")
    if rate_limit is not None:
        if not isinstance(rate_limit, str):
            return "rate_limit must be a JSON string or null"
        try:
            parsed = _json.loads(rate_limit)
        except ValueError:
            return "rate_limit must parse as JSON"
        # The app parses this as a policy object. Storing a valid-JSON
        # non-object ('"x"', '[1]', '10') would fail at the consumer, not here.
        if not isinstance(parsed, dict):
            return "rate_limit must be a JSON object"
    if "expires_at" in body:
        try:
            normalize_expires_at(body["expires_at"])
        except ValueError as exc:
            return str(exc)
    return None


def _row_to_public(row) -> dict:
    return {
        "handle": row["token_sha256"][:16],
        "label": row["label"],
        "role": row["role"],
        "priority": row["priority"],
        "rate_limit": row["rate_limit"],
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "created_by": row["created_by"],
        "last_used_at": row["last_used_at"],
        "revoked_at": row["revoked_at"],
        "revoked_by": row["revoked_by"],
    }


class Endpoints:
    def __init__(
        self,
        store: Store,
        site_origin: str,
        *,
        emitter: events.Emitter | None = None,
        limits: Limits | None = None,
    ):
        # Validate at construction: a typo'd site_origin must fail at startup,
        # not raise a 500 on every mutating request. check_origin raises
        # ValueError when site_origin is not an absolute origin.
        check_origin(site_origin, site_origin, None)
        self.store = store
        self.site_origin = site_origin
        self.emitter = emitter or events.DEFAULT
        self.limits = limits or DEFAULT_LIMITS

    # -- guards ------------------------------------------------------------
    def authz(self, identity, bearer):
        """Public so an adapter can refuse BEFORE decoding a request body.

        Parsing attacker-controlled JSON for a caller who has not authenticated
        is work done on their behalf, and it also reorders the response: a
        malformed body from an anonymous caller would answer 400 (leaking that
        the endpoint exists and is parsing) instead of 401.
        """
        return self._authz(identity, bearer)

    def _authz(self, identity, bearer):
        """Credentials first, always. Returns (status, body) on refusal, else None."""
        if bearer:
            return (403, {"error": "bearer tokens may not reach management endpoints"})
        if identity is None:
            return (401, {"error": "authentication required"})
        if not identity.is_operator:
            return (403, {"error": "operator privilege required"})
        return None

    def _csrf(self, origin, referer):
        if not check_origin(self.site_origin, origin, referer):
            return (403, {"error": "origin check failed"})
        return None

    # -- handlers ----------------------------------------------------------
    def handle_list(self, identity, bearer, params):
        refusal = self._authz(identity, bearer)
        if refusal:
            return refusal
        include = str(params.get("include", "")) == "revoked"
        try:
            limit = int(params.get("limit", self.store.max_limit))
        except (TypeError, ValueError):
            # ?limit=abc is a trivially reachable input on a public query
            # endpoint; an uncaught ValueError here is a 500, not a 400.
            return (400, {"error": "limit must be an integer"})
        label = params.get("label")
        if label is not None and not isinstance(label, str):
            return (400, {"error": "label must be a string"})
        rows, has_more = self.store.list_rows(include_revoked=include, limit=limit, label=label)
        return (200, {"tokens": [_row_to_public(r) for r in rows], "has_more": has_more})

    def handle_get(self, identity, bearer, handle):
        refusal = self._authz(identity, bearer)
        if refusal:
            return refusal
        try:
            row = self.store.resolve_handle(handle)
        except ValueError as exc:
            return (400, {"error": str(exc)})
        except NoSuchHandle:
            return (404, {"error": "no such token"})
        except AmbiguousHandle:
            return (409, {"error": "handle is ambiguous"})
        return (200, _row_to_public(row))

    def handle_create(self, identity, bearer, body, origin, referer):
        refusal = self._authz(identity, bearer) or self._csrf(origin, referer)
        if refusal:
            return refusal
        label, role = body.get("label"), body.get("role")
        if not label or not isinstance(label, str) or not role:
            return (400, {"error": "label and role are required"})
        if len(label) > self.limits.max_label_len:
            return (400, {"error": f"label must be <= {self.limits.max_label_len} characters"})
        try:
            validate_role(role)
        except ValueError as exc:
            return (400, {"error": str(exc)})
        bad = validate_policy(body)
        if bad:
            return (400, {"error": bad})
        try:
            raw, handle = self.store.mint(
                role,
                label,
                f"session:{identity.user}",
                body.get("priority"),
                body.get("rate_limit"),
                body.get("expires_at"),
            )
        except sqlite3.IntegrityError:
            # The partial unique index is the authority, not a prior lookup —
            # a check-then-insert loses the race between two concurrent creates.
            return (409, {"error": f"label {label!r} is already in use by a live token"})
        self.emitter.token_created(
            self.store.service, handle, label, role, f"session:{identity.user}"
        )
        return (201, {"handle": handle, "token": raw})

    def handle_patch(self, identity, bearer, handle, body, origin, referer):
        refusal = self._authz(identity, bearer) or self._csrf(origin, referer)
        if refusal:
            return refusal
        unknown = set(body) - _PATCHABLE
        if unknown:
            return (400, {"error": f"not mutable: {sorted(unknown)}"})
        # handle_create validates label; handle_patch must too, or an empty
        # string or an int reaches the row through the one write path that
        # skipped the check.
        if "label" in body:
            if not isinstance(body["label"], str) or not body["label"]:
                return (400, {"error": "label must be a non-empty string"})
            if len(body["label"]) > self.limits.max_label_len:
                return (400, {"error": f"label must be <= {self.limits.max_label_len} characters"})
        bad = validate_policy(body)
        if bad:
            return (400, {"error": bad})
        try:
            validate_handle(handle)
            row = self.store.resolve_handle(handle)
        except ValueError as exc:
            return (400, {"error": str(exc)})
        except NoSuchHandle:
            return (404, {"error": "no such token"})
        except AmbiguousHandle:
            return (409, {"error": "handle is ambiguous"})
        new_label = body.get("label")
        actor = f"session:{identity.user}"
        try:
            updated = self.store.update_row(
                handle,
                label=new_label,
                priority=body.get("priority", ...),
                rate_limit=body.get("rate_limit", ...),
                expires_at=body.get("expires_at", ...),
            )
        except sqlite3.IntegrityError:
            # Same authority as handle_create: the partial unique index, not a
            # prior lookup. Keeping a check-then-insert here would make the two
            # write paths disagree under concurrency.
            return (409, {"error": f"label {new_label!r} is already in use by a live token"})
        if new_label and new_label != row["label"]:
            self.emitter.token_relabelled(
                self.store.service, handle, row["label"], new_label, actor
            )
        for field in ("priority", "rate_limit", "expires_at"):
            if field in body and body[field] != row[field]:
                self.emitter.token_policy_changed(
                    self.store.service, handle, field, row[field], body[field], actor
                )
        return (200, _row_to_public(updated))

    def handle_delete(self, identity, bearer, handle, origin, referer):
        refusal = self._authz(identity, bearer) or self._csrf(origin, referer)
        if refusal:
            return refusal
        try:
            validate_handle(handle)
            row = self.store.resolve_handle(handle)
        except ValueError as exc:
            return (400, {"error": str(exc)})
        except NoSuchHandle:
            return (404, {"error": "no such token"})
        except AmbiguousHandle:
            return (409, {"error": "handle is ambiguous"})
        updated, changed = self.store.revoke(handle, f"session:{identity.user}")
        if changed:
            # Only a real live->revoked transition emits. A repeat DELETE is a
            # no-op and must not put a second revoke event in the sink.
            self.emitter.token_revoked(
                self.store.service, handle, row["label"], f"session:{identity.user}"
            )
        return (200, _row_to_public(updated))
