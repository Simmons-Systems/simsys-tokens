from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TokenInfo:
    """What a bearer caller resolved to.

    Carries token_sha256 (a hash is not a secret, and the app needs it for its
    ownership column) and NEVER the raw token at any key.
    """

    handle: str
    label: str
    role: str
    priority: int | None
    rate_limit: str | None
    token_sha256: str
    expires_at: str | None = None


@dataclass(frozen=True)
class SessionIdentity:
    """An interactive identity. `is_operator` has no default, deliberately —
    an authenticated member of a member-facing portal is not an operator."""

    user: str
    is_operator: bool
