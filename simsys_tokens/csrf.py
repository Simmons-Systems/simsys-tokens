"""Exact-origin CSRF check for mutating management endpoints.

Fail closed. A request carrying NEITHER Origin nor Referer is rejected: a
default-allow there is a complete bypass, and it is the branch a test must cover
explicitly because the foreign-Origin case passes either way.
"""

from __future__ import annotations

from urllib.parse import urlsplit


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def check_origin(site_origin: str, origin: str | None, referer: str | None) -> bool:
    expected = _origin_of(site_origin)
    if not expected:
        raise ValueError(f"site_origin is not a valid absolute origin: {site_origin!r}")
    if origin:
        return _origin_of(origin) == expected
    if referer:
        return _origin_of(referer) == expected
    return False
