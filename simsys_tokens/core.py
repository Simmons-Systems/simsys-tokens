"""Framework-agnostic policy. Adapters translate; they never decide."""
from __future__ import annotations

import re
import time

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


def authenticate(store: Store, authorization_header: str | None) -> TokenInfo | None:
    raw = _extract_bearer(authorization_header)
    if raw is None:
        return None
    if not _well_formed(raw):
        # Task 6 upgrades this branch to emit token.auth_failed reason="malformed"
        # (throttled). For now: fail closed without hashing or DB lookup.
        return None
    digest = token_hash(raw)
    row = store.lookup_live(digest)
    if row is None:
        return None
    now = time.monotonic()
    # The throttle map lives on the STORE, not module-global: a global keyed
    # only on digest is shared across every service in the process and grows
    # without bound for the life of the app.
    #
    # `or row["last_used_at"] is None` is NOT redundant. time.monotonic() counts
    # from an arbitrary epoch — on a freshly booted host it is < 60, so
    # `now - 0.0 >= 60` is False and the very first touch would be throttled
    # away. last_used_at would stay NULL and token.first_use would re-fire on
    # every request until the box had been up a minute.
    #
    # Lock + bounded map: Flask runs threaded and async workers share the Store,
    # so an unlocked dict check-then-set races; and an unbounded dict grows for
    # the life of the app under scanner traffic. See Store._touch_note().
    with store._touch_lock:
        last = store.last_touch.get(digest, 0.0)
        should_touch = (
            now - last >= LAST_USED_THROTTLE_SECONDS or row["last_used_at"] is None
        )
        if should_touch:
            store._touch_note(store.last_touch, digest, now)
    if should_touch:
        store.touch_last_used(digest)
    return TokenInfo(
        handle=digest[:16],
        label=row["label"],
        role=row["role"],
        priority=row["priority"],
        rate_limit=row["rate_limit"],
        token_sha256=digest,
    )
