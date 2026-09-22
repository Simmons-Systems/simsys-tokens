"""Framework-agnostic policy. Adapters translate; they never decide."""
from __future__ import annotations

import re
import time

from . import events
from .hashing import token_hash
from .models import SessionIdentity, TokenInfo  # noqa: F401  (re-exported)
from .store import Store

LAST_USED_THROTTLE_SECONDS = 60
AUTH_FAILED_THROTTLE_SECONDS = 60
# Longest well-formed token: 32 + 1 + 32 + 1 + 64 = 130. Cap at 256 to leave
# headroom without letting a 10 MB Authorization header reach sha256 (CPU DoS).
MAX_RAW_LEN = 256
TOKEN_RE = re.compile(r"[a-z0-9_]{1,32}-[a-z0-9_]{1,32}-[0-9a-f]{64}")


def _extract_bearer(header: str | None) -> str | None:
    if not header or not header.startswith("Bearer "):
        return None
    return header[len("Bearer "):] or None


def _well_formed(raw: str) -> bool:
    """Shape check BEFORE hashing. Hashing arbitrary-length attacker input on
    the hot auth path is a CPU-DoS vector; a malformed token can never resolve,
    so reject it without touching sha256 or SQLite."""
    return len(raw) <= MAX_RAW_LEN and TOKEN_RE.fullmatch(raw) is not None


def _emit_auth_failed_once(store: Store, *, key: str, event_kwargs: dict) -> None:
    """Emit token.auth_failed at most once per AUTH_FAILED_THROTTLE_SECONDS per
    key per process. Without this a scanner presenting random bearers fires one
    event per request and destroys the signal the rollout depends on."""
    now = time.monotonic()
    with store._touch_lock:
        last = store.last_auth_failed.get(key, 0.0)
        if now - last < AUTH_FAILED_THROTTLE_SECONDS:
            return
        store._touch_note(store.last_auth_failed, key, now)
    events.token_auth_failed(store.service, **event_kwargs)


def authenticate(store: Store, authorization_header: str | None) -> TokenInfo | None:
    raw = _extract_bearer(authorization_header)
    if raw is None:
        return None
    if not _well_formed(raw):
        # Malformed shapes can never resolve. Emit throttled so a scanner
        # hammering garbage cannot flood the sink: at most one event per 60 s
        # per distinct prefix per process. No digest exists (nothing was hashed),
        # so carry a raw prefix only, never a label.
        _emit_auth_failed_once(
            store, key=f"malformed:{raw[:16]}",
            event_kwargs={"digest_prefix": None, "reason": "malformed"},
        )
        return None
    digest = token_hash(raw)
    row = store.lookup_live(digest)
    if row is None:
        revoked = store.find_any(digest)
        if revoked is not None:
            _emit_auth_failed_once(
                store, key=f"revoked:{digest[:16]}",
                event_kwargs={
                    "handle": digest[:16], "label": revoked["label"],
                    "reason": "revoked",
                },
            )
        else:
            _emit_auth_failed_once(
                store, key=f"unknown:{digest[:16]}",
                event_kwargs={"digest_prefix": digest[:16], "reason": "unknown"},
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
    # and the very first touch would be throttled away. last_used_at would stay
    # NULL and token.first_use would re-fire until the box had been up a minute.
    #
    # Lock + bounded map: Flask runs threaded and async workers share the Store,
    # so an unlocked dict check-then-set races; and an unbounded dict grows for
    # the life of the app under scanner traffic. See Store._touch_note().
    with store._touch_lock:
        last = store.last_touch.get(digest, 0.0)
        should_touch = now - last >= LAST_USED_THROTTLE_SECONDS or first_use
        if should_touch:
            store._touch_note(store.last_touch, digest, now)
    if should_touch:
        store.touch_last_used(digest)
    if first_use:
        events.token_first_use(store.service, digest[:16], row["label"])
    return TokenInfo(
        handle=digest[:16],
        label=row["label"],
        role=row["role"],
        priority=row["priority"],
        rate_limit=row["rate_limit"],
        token_sha256=digest,
    )
