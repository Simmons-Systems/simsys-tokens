"""Token minting, hashing and slug validation.

The preimage is the FULL token string, not its hex tail. Getting this wrong is
silent: a mismatched preimage yields a well-formed digest that simply never
matches, so every token fails auth and every ownership check says "not yours".
"""
from __future__ import annotations

import hashlib
import re
import secrets

# fullmatch, NOT re.match with `$`: in Python `$` also matches immediately
# before a trailing newline, so `^[a-z0-9_]{1,32}$` accepts "agent\n" — which
# would then be embedded in a token string and break every downstream parse.
SLUG_RE = re.compile(r"[a-z0-9_]{1,32}")
HANDLE_RE = re.compile(r"[0-9a-f]{16}")
HANDLE_LEN = 16


def token_hash(raw: str) -> str:
    """sha256 of the full token string, lowercase hex."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def mint_token(service: str, role: str) -> str:
    validate_service(service)
    validate_role(role)
    return f"{service}-{role}-{secrets.token_hex(32)}"


def _validate_slug(value: str, what: str) -> None:
    # Hyphen is the token's field separator, so it cannot appear in either field.
    if not isinstance(value, str) or not SLUG_RE.fullmatch(value):
        raise ValueError(f"{what} must match ^[a-z0-9_]{{1,32}}$ (no hyphens); got {value!r}")


def validate_service(service: str) -> None:
    _validate_slug(service, "service")


def validate_role(role: str) -> None:
    _validate_slug(role, "role")


def validate_handle(handle: str) -> None:
    if not isinstance(handle, str) or not HANDLE_RE.fullmatch(handle):
        raise ValueError(f"handle must be exactly 16 lowercase hex chars; got {handle!r}")


def handle_of(digest: str) -> str:
    return digest[:HANDLE_LEN]
